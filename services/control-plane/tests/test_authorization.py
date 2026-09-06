"""Route-level identity-kind, capability, isolation, and safe-error tests."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Annotated

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from dusk_control_plane.app import create_app
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dependencies import AppContainer
from dusk_control_plane.identity import (
    ROLE_CAPABILITIES,
    ROUTE_POLICIES,
    AuthenticationRejectedError,
    Authenticator,
    AuthorizationDeniedError,
    Capability,
    IdentityKind,
    IdentityProviderUnavailableError,
    Principal,
    Role,
    require_identity,
)

WORKLOAD_DEPENDENCY = require_identity(IdentityKind.WORKLOAD)
OPERATIONS_DEPENDENCY = require_identity(IdentityKind.HUMAN, Capability.OPERATIONS_READ)


@dataclass(frozen=True)
class TokenAuthenticator(Authenticator):
    principals: dict[str, Principal]

    async def authenticate(self, token: str) -> Principal:
        return self.principals[token]


@dataclass(frozen=True)
class RejectingAuthenticator(Authenticator):
    error: Exception

    async def authenticate(self, _token: str) -> Principal:
        raise self.error


def principal(
    *, kind: IdentityKind, tenant: str = "tenant-from-token", roles: frozenset[Role] = frozenset()
) -> Principal:
    return Principal(
        issuer="https://identity.example.test/",
        subject="subject",
        tenant_id=tenant,
        kind=kind,
        roles=roles,
        workload_id="agent-a" if kind is IdentityKind.WORKLOAD else None,
    )


def client() -> TestClient:
    authenticator = TokenAuthenticator(
        {
            "workload": principal(kind=IdentityKind.WORKLOAD),
            "viewer": principal(kind=IdentityKind.HUMAN, roles=frozenset({Role.VIEWER})),
            "operator": principal(kind=IdentityKind.HUMAN, roles=frozenset({Role.OPERATOR})),
        }
    )
    settings = Settings(environment=Environment.TEST)
    app = create_app(container=AppContainer.build(settings=settings, authenticator=authenticator))
    router = APIRouter()

    @router.post("/__test/evaluate")
    async def evaluate(
        identity: Annotated[Principal, Depends(WORKLOAD_DEPENDENCY)],
    ) -> dict[str, str]:
        return {"tenant_id": identity.tenant_id}

    @router.get("/__test/operations")
    async def operations(
        identity: Annotated[Principal, Depends(OPERATIONS_DEPENDENCY)],
    ) -> dict[str, str]:
        return {"tenant_id": identity.tenant_id}

    app.include_router(router, include_in_schema=False)
    return TestClient(app, raise_server_exceptions=False)


def test_workload_route_uses_claim_tenant_and_ignores_request_tenant() -> None:
    with client() as test_client:
        response = test_client.post(
            "/__test/evaluate?tenant_id=attacker-tenant",
            headers={"Authorization": "Bearer workload", "X-Tenant-ID": "attacker-tenant"},
            json={"tenant_id": "attacker-tenant"},
        )
    assert response.status_code == 200
    assert response.json() == {"tenant_id": "tenant-from-token"}


def test_identity_classes_cannot_cross_route_boundaries() -> None:
    with client() as test_client:
        workload_on_human = test_client.get(
            "/__test/operations", headers={"Authorization": "Bearer workload"}
        )
        human_on_workload = test_client.post(
            "/__test/evaluate", headers={"Authorization": "Bearer operator"}
        )
    assert workload_on_human.status_code == 403
    assert human_on_workload.status_code == 403


def test_capability_denial_and_missing_authentication_are_standardized() -> None:
    with client() as test_client:
        viewer = test_client.get("/__test/operations", headers={"Authorization": "Bearer viewer"})
        missing = test_client.get("/__test/operations")
        allowed = test_client.get(
            "/__test/operations", headers={"Authorization": "Bearer operator"}
        )
    assert viewer.status_code == 403
    assert viewer.json()["error"]["code"] == "FORBIDDEN"
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert missing.headers["WWW-Authenticate"] == "Bearer"
    assert allowed.status_code == 200


def test_every_planned_and_operational_route_has_an_explicit_policy() -> None:
    assert set(ROUTE_POLICIES) == {
        "GET /livez",
        "GET /readyz",
        "POST /v2/evaluations",
        "GET /v2/dashboard/summary",
        "GET /v2/dashboard/decision-volume",
        "GET /v2/dashboard/action-breakdown",
        "GET /v2/decisions",
        "GET /v2/decisions/{trace_id}",
        "GET /v2/agents/risk",
        "GET /v2/agents/{agent_id}",
        "GET /v2/policies",
        "GET /v2/policies/summary",
        "GET /v2/integrations/health",
        "GET /v2/audit-events",
        "GET /v2/service/status",
    }
    assert ROUTE_POLICIES["GET /livez"].identity_kind is None
    assert ROUTE_POLICIES["GET /readyz"].identity_kind is None
    assert all(
        policy.identity_kind is not None
        for route, policy in ROUTE_POLICIES.items()
        if route not in {"GET /livez", "GET /readyz"}
    )


def test_rejected_token_and_sensitive_claims_never_enter_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_token = "secret-token-tenant-a-subject-a"
    settings = Settings(environment=Environment.TEST)
    authenticator = RejectingAuthenticator(AuthenticationRejectedError("invalid_token"))
    app = create_app(container=AppContainer.build(settings=settings, authenticator=authenticator))
    router = APIRouter()

    @router.get("/__test/protected")
    async def protected(
        _identity: Annotated[Principal, Depends(OPERATIONS_DEPENDENCY)],
    ) -> dict[str, bool]:
        return {"allowed": True}

    app.include_router(router, include_in_schema=False)
    configured_client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.INFO), configured_client as test_client:
        response = test_client.get(
            "/__test/protected", headers={"Authorization": f"Bearer {sensitive_token}"}
        )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert sensitive_token not in caplog.text
    assert "tenant-a" not in caplog.text
    assert "subject-a" not in caplog.text


def test_identity_provider_outage_fails_closed_with_safe_retryable_error() -> None:
    settings = Settings(environment=Environment.TEST)
    authenticator = RejectingAuthenticator(IdentityProviderUnavailableError())
    app = create_app(container=AppContainer.build(settings=settings, authenticator=authenticator))
    router = APIRouter()

    @router.post("/__test/consequential")
    async def consequential(
        _identity: Annotated[Principal, Depends(WORKLOAD_DEPENDENCY)],
    ) -> dict[str, bool]:
        return {"allowed": True}

    app.include_router(router, include_in_schema=False)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        response = test_client.post(
            "/__test/consequential", headers={"Authorization": "Bearer opaque-token"}
        )

    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "code": "IDENTITY_PROVIDER_UNAVAILABLE",
            "message": "Identity verification is temporarily unavailable",
            "request_id": response.headers["X-Request-ID"],
            "retryable": True,
        }
    }


@pytest.mark.parametrize("role", list(Role))
@pytest.mark.parametrize("capability", list(Capability))
@pytest.mark.anyio
async def test_authorization_matrix_has_zero_unauthorized_successes(
    role: Role, capability: Capability
) -> None:
    identity = principal(kind=IdentityKind.HUMAN, roles=frozenset({role}))
    dependency = require_identity(IdentityKind.HUMAN, capability)

    if capability in ROLE_CAPABILITIES[role]:
        assert await dependency(identity) is identity
    else:
        with pytest.raises(AuthorizationDeniedError):
            await dependency(identity)
