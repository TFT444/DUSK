"""OIDC authentication, claim-derived tenancy, and capability authorization."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Protocol, cast

import httpx2
import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dusk_control_plane.config import Settings

logger = logging.getLogger(__name__)
_bearer = HTTPBearer(auto_error=False)


class IdentityKind(StrEnum):
    WORKLOAD = "workload"
    HUMAN = "human"


class Role(StrEnum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    ADMINISTRATOR = "administrator"


class Capability(StrEnum):
    DASHBOARD_READ = "dashboard:read"
    DECISION_SUMMARY_READ = "decision-summary:read"
    DECISION_DETAIL_READ = "decision-detail:read"
    AGENT_INVESTIGATE = "agent:investigate"
    AUDIT_INVESTIGATE = "audit:investigate"
    POLICY_EVIDENCE_READ = "policy-evidence:read"
    OPERATIONS_READ = "operations:read"
    TENANT_ADMINISTER = "tenant:administer"


@dataclass(frozen=True)
class RoutePolicy:
    identity_kind: IdentityKind | None
    capability: Capability | None = None


ROUTE_POLICIES: Mapping[str, RoutePolicy] = MappingProxyType(
    {
        "GET /livez": RoutePolicy(None),
        "GET /readyz": RoutePolicy(None),
        "POST /v2/evaluations": RoutePolicy(IdentityKind.WORKLOAD),
        "GET /v2/dashboard/summary": RoutePolicy(IdentityKind.HUMAN, Capability.DASHBOARD_READ),
        "GET /v2/dashboard/decision-volume": RoutePolicy(
            IdentityKind.HUMAN, Capability.DASHBOARD_READ
        ),
        "GET /v2/dashboard/action-breakdown": RoutePolicy(
            IdentityKind.HUMAN, Capability.DASHBOARD_READ
        ),
        "GET /v2/decisions": RoutePolicy(IdentityKind.HUMAN, Capability.DECISION_SUMMARY_READ),
        "GET /v2/decisions/{trace_id}": RoutePolicy(
            IdentityKind.HUMAN, Capability.DECISION_DETAIL_READ
        ),
        "GET /v2/agents/risk": RoutePolicy(IdentityKind.HUMAN, Capability.AGENT_INVESTIGATE),
        "GET /v2/agents/{agent_id}": RoutePolicy(IdentityKind.HUMAN, Capability.AGENT_INVESTIGATE),
        "GET /v2/policies": RoutePolicy(IdentityKind.HUMAN, Capability.POLICY_EVIDENCE_READ),
        "GET /v2/policies/summary": RoutePolicy(
            IdentityKind.HUMAN, Capability.POLICY_EVIDENCE_READ
        ),
        "GET /v2/integrations/health": RoutePolicy(IdentityKind.HUMAN, Capability.OPERATIONS_READ),
        "GET /v2/audit-events": RoutePolicy(IdentityKind.HUMAN, Capability.AUDIT_INVESTIGATE),
        "GET /v2/service/status": RoutePolicy(IdentityKind.HUMAN, Capability.OPERATIONS_READ),
    }
)


ROLE_CAPABILITIES: Mapping[Role, frozenset[Capability]] = MappingProxyType(
    {
        Role.VIEWER: frozenset({Capability.DASHBOARD_READ, Capability.DECISION_SUMMARY_READ}),
        Role.ANALYST: frozenset(
            {
                Capability.DASHBOARD_READ,
                Capability.DECISION_SUMMARY_READ,
                Capability.DECISION_DETAIL_READ,
                Capability.AGENT_INVESTIGATE,
                Capability.AUDIT_INVESTIGATE,
            }
        ),
        Role.OPERATOR: frozenset(
            {
                Capability.DASHBOARD_READ,
                Capability.DECISION_SUMMARY_READ,
                Capability.DECISION_DETAIL_READ,
                Capability.AGENT_INVESTIGATE,
                Capability.AUDIT_INVESTIGATE,
                Capability.OPERATIONS_READ,
            }
        ),
        Role.AUDITOR: frozenset({Capability.AUDIT_INVESTIGATE, Capability.POLICY_EVIDENCE_READ}),
        Role.ADMINISTRATOR: frozenset({Capability.TENANT_ADMINISTER}),
    }
)


@dataclass(frozen=True)
class Principal:
    issuer: str
    subject: str
    tenant_id: str
    kind: IdentityKind
    roles: frozenset[Role] = frozenset()
    workload_id: str | None = None

    def has_capability(self, capability: Capability) -> bool:
        return any(capability in ROLE_CAPABILITIES[role] for role in self.roles)


class AuthenticationRejectedError(Exception):
    """The presented credential cannot establish a verified identity."""

    def __init__(self, reason_code: str = "invalid_credential") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class IdentityProviderUnavailableError(Exception):
    """The configured identity authority could not be verified safely."""


class AuthorizationDeniedError(Exception):
    """The verified principal lacks the route's declared authorization."""


class JwksFetcher(Protocol):
    async def fetch(self) -> Mapping[str, object]: ...


class Authenticator(Protocol):
    async def authenticate(self, token: str) -> Principal: ...


@dataclass(frozen=True)
class HttpxJwksFetcher:
    uri: str
    timeout_seconds: float
    max_bytes: int
    transport: httpx2.AsyncBaseTransport | None = None

    async def fetch(self) -> Mapping[str, object]:
        timeout = httpx2.Timeout(self.timeout_seconds)
        try:
            async with httpx2.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
                limits=httpx2.Limits(max_connections=4, max_keepalive_connections=2),
                transport=self.transport,
            ) as client:
                async with client.stream(
                    "GET", self.uri, headers={"Accept": "application/json"}
                ) as response:
                    if response.status_code != 200:
                        raise IdentityProviderUnavailableError
                    declared = response.headers.get("content-length")
                    if declared is not None and (
                        not declared.isdecimal() or int(declared) > self.max_bytes
                    ):
                        raise IdentityProviderUnavailableError
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > self.max_bytes:
                            raise IdentityProviderUnavailableError
        except IdentityProviderUnavailableError:
            raise
        except (httpx2.HTTPError, TimeoutError) as exc:
            raise IdentityProviderUnavailableError from exc
        try:
            document = json.loads(body, object_pairs_hook=_unique_json_object)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise IdentityProviderUnavailableError from exc
        if not isinstance(document, dict):
            raise IdentityProviderUnavailableError
        return cast(dict[str, object], document)


class JwksCache:
    """Bounded JWKS cache with single-flight refresh and no stale-key fallback."""

    def __init__(
        self,
        *,
        fetcher: JwksFetcher,
        algorithms: tuple[str, ...],
        ttl_seconds: int,
        min_refresh_seconds: int,
        max_keys: int,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetcher = fetcher
        self._algorithms = frozenset(algorithms)
        self._ttl_seconds = ttl_seconds
        self._min_refresh_seconds = min_refresh_seconds
        self._max_keys = max_keys
        self._monotonic = monotonic
        self._keys: dict[str, jwt.PyJWK] = {}
        self._expires_at = 0.0
        self._last_miss_refresh_at = float("-inf")
        self._lock = asyncio.Lock()

    async def get(self, kid: str) -> jwt.PyJWK:
        now = self._monotonic()
        key = self._keys.get(kid)
        if now < self._expires_at and key is not None:
            return key
        async with self._lock:
            now = self._monotonic()
            key = self._keys.get(kid)
            if now < self._expires_at and key is not None:
                return key
            expired = now >= self._expires_at
            if not expired and now - self._last_miss_refresh_at < self._min_refresh_seconds:
                raise AuthenticationRejectedError("unknown_key")
            await self._refresh(now, missing_key_refresh=not expired)
            try:
                return self._keys[kid]
            except KeyError as exc:
                raise AuthenticationRejectedError("unknown_key") from exc

    async def _refresh(self, now: float, *, missing_key_refresh: bool) -> None:
        try:
            document = await self._fetcher.fetch()
            parsed = self._parse_document(document)
        except AuthenticationRejectedError:
            raise
        except IdentityProviderUnavailableError:
            raise
        except (jwt.PyJWKError, ValueError, TypeError) as exc:
            raise IdentityProviderUnavailableError from exc
        self._keys = parsed
        if missing_key_refresh:
            self._last_miss_refresh_at = now
        self._expires_at = now + self._ttl_seconds

    def _parse_document(self, document: Mapping[str, object]) -> dict[str, jwt.PyJWK]:
        raw_keys = document.get("keys")
        if not isinstance(raw_keys, list) or not 1 <= len(raw_keys) <= self._max_keys:
            raise IdentityProviderUnavailableError
        parsed: dict[str, jwt.PyJWK] = {}
        for raw_key in raw_keys:
            if not isinstance(raw_key, dict):
                raise IdentityProviderUnavailableError
            kid = raw_key.get("kid")
            use = raw_key.get("use")
            key_type = raw_key.get("kty")
            if (
                not isinstance(kid, str)
                or not 1 <= len(kid) <= 128
                or any(not character.isprintable() or character.isspace() for character in kid)
                or kid in parsed
                or use not in (None, "sig")
                or key_type not in ("RSA", "EC")
            ):
                raise IdentityProviderUnavailableError
            algorithm = self._resolve_algorithm(raw_key.get("alg"), cast(str, key_type))
            parsed[kid] = jwt.PyJWK(raw_key, algorithm=algorithm)
        return parsed

    def _resolve_algorithm(self, algorithm: object, key_type: str) -> str:
        if algorithm is None:
            prefix = "RS" if key_type == "RSA" else "ES"
            candidates = [item for item in self._algorithms if item.startswith(prefix)]
            if len(candidates) != 1:
                raise IdentityProviderUnavailableError
            return candidates[0]
        if not isinstance(algorithm, str) or algorithm not in self._algorithms:
            raise IdentityProviderUnavailableError
        return algorithm


class OidcAuthenticator:
    def __init__(
        self,
        *,
        settings: Settings,
        jwks: JwksCache,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if settings.oidc_issuer is None or settings.oidc_audience is None:
            raise ValueError("OIDC issuer and audience are required")
        self._settings = settings
        self._jwks = jwks
        self._wall_clock = wall_clock

    @classmethod
    def from_settings(cls, settings: Settings) -> OidcAuthenticator:
        if settings.oidc_jwks_uri is None:
            raise ValueError("OIDC JWKS URI is required")
        fetcher = HttpxJwksFetcher(
            uri=settings.oidc_jwks_uri,
            timeout_seconds=settings.oidc_http_timeout_seconds,
            max_bytes=settings.oidc_max_jwks_bytes,
        )
        return cls(
            settings=settings,
            jwks=JwksCache(
                fetcher=fetcher,
                algorithms=tuple(settings.oidc_algorithms),
                ttl_seconds=settings.oidc_jwks_ttl_seconds,
                min_refresh_seconds=settings.oidc_jwks_min_refresh_seconds,
                max_keys=settings.oidc_max_jwks_keys,
            ),
        )

    async def authenticate(self, token: str) -> Principal:
        if not token or len(token.encode("utf-8")) > self._settings.oidc_max_token_bytes:
            raise AuthenticationRejectedError("malformed_token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise AuthenticationRejectedError("malformed_token") from exc
        algorithm = header.get("alg")
        kid = header.get("kid")
        if "crit" in header:
            raise AuthenticationRejectedError("unsupported_critical_header")
        if algorithm not in self._settings.oidc_algorithms or not isinstance(kid, str):
            raise AuthenticationRejectedError("invalid_header")
        if not 1 <= len(kid) <= 128:
            raise AuthenticationRejectedError("invalid_header")
        key = await self._jwks.get(kid)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self._settings.oidc_algorithms),
                audience=self._settings.oidc_audience,
                issuer=self._settings.oidc_issuer,
                options={
                    "require": ["iss", "aud", "sub", "iat", "nbf", "exp"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.InvalidTokenError as exc:
            raise AuthenticationRejectedError("invalid_token") from exc
        return self._principal_from_claims(claims)

    def _principal_from_claims(self, claims: Mapping[str, Any]) -> Principal:
        subject = _bounded_identifier(claims.get("sub"), "subject")
        tenant_id = _bounded_identifier(claims.get(self._settings.oidc_tenant_claim), "tenant")
        raw_kind = claims.get(self._settings.oidc_identity_kind_claim)
        if not isinstance(raw_kind, str):
            raise AuthenticationRejectedError("invalid_identity_kind")
        try:
            kind = IdentityKind(raw_kind)
        except (TypeError, ValueError) as exc:
            raise AuthenticationRejectedError("invalid_identity_kind") from exc
        issued_at = _numeric_date(claims.get("iat"))
        not_before = _numeric_date(claims.get("nbf"))
        expires_at = _numeric_date(claims.get("exp"))
        now = self._wall_clock()
        skew = self._settings.oidc_clock_skew_seconds
        if (
            issued_at > now + skew
            or not_before > now + skew
            or expires_at <= now - skew
            or expires_at <= issued_at
            or expires_at <= not_before
        ):
            raise AuthenticationRejectedError("invalid_time_claim")
        age = now - issued_at
        if age > self._settings.oidc_max_token_age_seconds:
            raise AuthenticationRejectedError("token_too_old")
        raw_roles = claims.get(self._settings.oidc_roles_claim, [])
        raw_workload = claims.get(self._settings.oidc_workload_claim)
        if kind is IdentityKind.WORKLOAD:
            if raw_roles not in (None, []):
                raise AuthenticationRejectedError("mixed_identity_claims")
            workload_id = _bounded_identifier(raw_workload, "workload")
            roles: frozenset[Role] = frozenset()
        else:
            if raw_workload is not None:
                raise AuthenticationRejectedError("mixed_identity_claims")
            roles = _roles(raw_roles)
            workload_id = None
        return Principal(
            issuer=cast(str, claims["iss"]),
            subject=subject,
            tenant_id=tenant_id,
            kind=kind,
            roles=roles,
            workload_id=workload_id,
        )


def _bounded_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise AuthenticationRejectedError(f"invalid_{field}")
    if any(
        character.isspace() or ord(character) < 33 or ord(character) > 126 for character in value
    ):
        raise AuthenticationRejectedError(f"invalid_{field}")
    return value


def _numeric_date(value: object) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise AuthenticationRejectedError("invalid_time_claim")
    numeric = float(value)
    if not math.isfinite(numeric):
        raise AuthenticationRejectedError("invalid_time_claim")
    return numeric


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _roles(value: object) -> frozenset[Role]:
    if not isinstance(value, list) or not 1 <= len(value) <= len(Role):
        raise AuthenticationRejectedError("invalid_roles")
    if not all(isinstance(role, str) for role in value) or len(set(value)) != len(value):
        raise AuthenticationRejectedError("invalid_roles")
    try:
        return frozenset(Role(role) for role in value)
    except ValueError as exc:
        raise AuthenticationRejectedError("invalid_roles") from exc


async def authenticated_principal(
    request: Request,
    credential: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    authenticator: Authenticator | None = request.app.state.container.authenticator
    if credential is None or credential.scheme.lower() != "bearer":
        raise AuthenticationRejectedError("missing_credential")
    if authenticator is None:
        raise IdentityProviderUnavailableError
    try:
        return await authenticator.authenticate(credential.credentials)
    except IdentityProviderUnavailableError:
        logger.warning(
            "identity provider unavailable",
            extra={"event_code": "identity.provider_unavailable"},
        )
        raise
    except AuthenticationRejectedError:
        logger.info(
            "authentication rejected",
            extra={"event_code": "identity.authentication_rejected"},
        )
        raise


def require_identity(
    kind: IdentityKind, capability: Capability | None = None
) -> Callable[..., Awaitable[Principal]]:
    async def authorize(
        principal: Annotated[Principal, Depends(authenticated_principal)],
    ) -> Principal:
        if principal.kind is not kind:
            raise AuthorizationDeniedError
        if capability is not None and not principal.has_capability(capability):
            raise AuthorizationDeniedError
        return principal

    return authorize


def require_route_policy(method: str, path: str) -> Callable[..., Awaitable[Principal]]:
    """Build a dependency only for a declared protected route policy."""
    route_key = f"{method.upper()} {path}"
    try:
        policy = ROUTE_POLICIES[route_key]
    except KeyError as exc:
        raise ValueError(f"route policy is not declared: {route_key}") from exc
    if policy.identity_kind is None:
        raise ValueError(f"public route does not require authorization: {route_key}")
    return require_identity(policy.identity_kind, policy.capability)
