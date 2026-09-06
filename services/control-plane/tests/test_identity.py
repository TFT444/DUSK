"""OIDC signature, claims, tenant derivation, and role tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import jwt
import pytest
from identity_helpers import SequenceFetcher, SigningKey, signing_key, token

from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.identity import (
    AuthenticationRejectedError,
    Capability,
    IdentityKind,
    JwksCache,
    OidcAuthenticator,
    Role,
)

NOW = 1_800_000_000


def identity_settings(**overrides: object) -> Settings:
    return Settings(
        environment=Environment.TEST,
        v2_enabled=True,
        oidc_issuer="https://identity.example.test/",
        oidc_audience="dusk-control-plane",
        oidc_jwks_uri="https://identity.example.test/.well-known/jwks.json",
        oidc_clock_skew_seconds=0,
        oidc_max_token_age_seconds=3600,
        oidc_jwks_min_refresh_seconds=1,
        **overrides,
    )


def base_claims(**overrides: Any) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "iss": "https://identity.example.test/",
        "aud": "dusk-control-plane",
        "sub": "principal-123",
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 300,
        "dusk_tenant_id": "tenant-a",
        "dusk_identity_kind": "workload",
        "dusk_workload_id": "agent-a",
    }
    claims.update(overrides)
    return claims


def authenticator(
    key: SigningKey,
    *,
    settings: Settings | None = None,
    claims_documents: list[Mapping[str, object] | Exception] | None = None,
) -> OidcAuthenticator:
    resolved = settings or identity_settings()
    fetcher = SequenceFetcher(claims_documents or [{"keys": [key.jwk]}])
    cache = JwksCache(
        fetcher=fetcher,
        algorithms=tuple(resolved.oidc_algorithms),
        ttl_seconds=resolved.oidc_jwks_ttl_seconds,
        min_refresh_seconds=resolved.oidc_jwks_min_refresh_seconds,
        max_keys=resolved.oidc_max_jwks_keys,
    )
    return OidcAuthenticator(settings=resolved, jwks=cache, wall_clock=lambda: NOW)


@pytest.mark.anyio
async def test_workload_identity_is_derived_only_from_verified_claims() -> None:
    key = signing_key("current")
    principal = await authenticator(key).authenticate(token(key, base_claims()))

    assert principal.issuer == "https://identity.example.test/"
    assert principal.subject == "principal-123"
    assert principal.tenant_id == "tenant-a"
    assert principal.kind is IdentityKind.WORKLOAD
    assert principal.workload_id == "agent-a"
    assert principal.roles == frozenset()


@pytest.mark.anyio
async def test_human_roles_map_to_explicit_capabilities() -> None:
    key = signing_key("current")
    claims = base_claims(
        dusk_identity_kind="human",
        dusk_roles=["analyst"],
        dusk_workload_id=None,
    )
    principal = await authenticator(key).authenticate(token(key, claims))

    assert principal.roles == frozenset({Role.ANALYST})
    assert principal.has_capability(Capability.DECISION_DETAIL_READ)
    assert not principal.has_capability(Capability.OPERATIONS_READ)
    assert not principal.has_capability(Capability.TENANT_ADMINISTER)


@pytest.mark.parametrize(
    "claims",
    [
        base_claims(iss="https://attacker.example/"),
        base_claims(aud="different-service"),
        base_claims(exp=NOW - 1),
        base_claims(nbf=NOW + 1),
        base_claims(iat=NOW - 4000),
        base_claims(iat=float("nan")),
        base_claims(exp=float("inf")),
        base_claims(iat=NOW + 10, nbf=NOW - 10, exp=NOW + 5),
        base_claims(iat=NOW - 10, nbf=NOW + 10, exp=NOW + 5),
        {key: value for key, value in base_claims().items() if key != "sub"},
        {key: value for key, value in base_claims().items() if key != "dusk_tenant_id"},
    ],
)
@pytest.mark.anyio
async def test_invalid_or_missing_required_claims_are_rejected(claims: dict[str, Any]) -> None:
    key = signing_key("current")
    with pytest.raises(AuthenticationRejectedError):
        await authenticator(key).authenticate(token(key, claims))


@pytest.mark.anyio
async def test_algorithm_is_pinned_before_key_lookup() -> None:
    key = signing_key("current")
    forged = jwt.encode(
        base_claims(),
        "attacker-secret-that-is-long-enough",
        algorithm="HS256",
        headers={"kid": key.kid},
    )
    with pytest.raises(AuthenticationRejectedError, match="invalid_header"):
        await authenticator(key).authenticate(forged)


@pytest.mark.anyio
async def test_wrong_signature_is_rejected_even_when_kid_matches() -> None:
    trusted = signing_key("current")
    attacker = signing_key("current")
    with pytest.raises(AuthenticationRejectedError, match="invalid_token"):
        await authenticator(trusted).authenticate(token(attacker, base_claims()))


@pytest.mark.anyio
async def test_missing_kid_and_oversized_tokens_are_rejected_before_jwks_use() -> None:
    key = signing_key("current")
    without_kid = jwt.encode(base_claims(), key.private_key, algorithm="RS256")
    constrained = identity_settings(oidc_max_token_bytes=1024)
    with pytest.raises(AuthenticationRejectedError, match="invalid_header"):
        await authenticator(key).authenticate(without_kid)
    with pytest.raises(AuthenticationRejectedError, match="malformed_token"):
        await authenticator(key, settings=constrained).authenticate("x" * 1025)


@pytest.mark.anyio
async def test_unsupported_critical_header_is_rejected() -> None:
    key = signing_key("current")
    encoded = jwt.encode(
        base_claims(),
        key.private_key,
        algorithm="RS256",
        headers={"kid": key.kid, "crit": ["custom"], "custom": "value"},
    )
    with pytest.raises(AuthenticationRejectedError):
        await authenticator(key).authenticate(encoded)


@pytest.mark.parametrize(
    "claims",
    [
        base_claims(dusk_roles=["viewer"]),
        base_claims(
            dusk_identity_kind="human",
            dusk_roles=["viewer", "viewer"],
            dusk_workload_id=None,
        ),
        base_claims(dusk_identity_kind="human", dusk_roles=["owner"], dusk_workload_id=None),
        base_claims(dusk_identity_kind="human", dusk_roles=["viewer"], dusk_workload_id="agent-a"),
    ],
)
@pytest.mark.anyio
async def test_mixed_or_escalated_identity_claims_are_rejected(claims: dict[str, Any]) -> None:
    key = signing_key("current")
    with pytest.raises(AuthenticationRejectedError):
        await authenticator(key).authenticate(token(key, claims))


def test_roles_are_not_an_implicit_privilege_hierarchy() -> None:
    expected = {
        Role.VIEWER: {Capability.DASHBOARD_READ, Capability.DECISION_SUMMARY_READ},
        Role.ANALYST: {
            Capability.DASHBOARD_READ,
            Capability.DECISION_SUMMARY_READ,
            Capability.DECISION_DETAIL_READ,
            Capability.AGENT_INVESTIGATE,
            Capability.AUDIT_INVESTIGATE,
        },
        Role.OPERATOR: {
            Capability.DASHBOARD_READ,
            Capability.DECISION_SUMMARY_READ,
            Capability.DECISION_DETAIL_READ,
            Capability.AGENT_INVESTIGATE,
            Capability.AUDIT_INVESTIGATE,
            Capability.OPERATIONS_READ,
        },
        Role.AUDITOR: {Capability.AUDIT_INVESTIGATE, Capability.POLICY_EVIDENCE_READ},
        Role.ADMINISTRATOR: {Capability.TENANT_ADMINISTER},
    }
    from dusk_control_plane.identity import ROLE_CAPABILITIES

    assert {role: set(capabilities) for role, capabilities in ROLE_CAPABILITIES.items()} == expected
