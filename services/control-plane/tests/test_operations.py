"""Policy catalogue and measured operational API boundary tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import uuid4

from dusk.policies import load_enterprise_pack
from fastapi.testclient import TestClient

from dusk_control_plane.app import create_app
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dependencies import AppContainer
from dusk_control_plane.identity import IdentityKind, Principal, Role
from dusk_control_plane.operations import (
    IntegrationHealthPage,
    IntegrationHealthQuery,
    InvalidOperationsCursorError,
    OperationsCursorCodec,
    OperationsQueryUnavailableError,
    PolicyListQuery,
    PolicyPage,
    PolicySummary,
    PostgresOperationsReader,
    ServiceComponent,
    ServiceStatus,
)
from dusk_control_plane.storage.models import IntegrationHealth

TENANT = uuid4()
NOW = datetime(2026, 9, 3, 12, tzinfo=UTC)


class _Authenticator:
    async def authenticate(self, token: str) -> Principal:
        return Principal(
            issuer="https://identity.example.test/",
            subject=token,
            tenant_id=str(TENANT),
            kind=IdentityKind.HUMAN,
            roles=frozenset({Role(token)}),
        )


class _Reader:
    error: Exception | None = None
    principal: Principal | None = None

    async def policies(self, query: PolicyListQuery, principal: Principal) -> PolicyPage:
        self.principal = principal
        if self.error:
            raise self.error
        return PolicyPage(
            pack_name="control-baseline", pack_version="2.4.1", items=(), next_cursor=None
        )

    async def policy_summary(self, principal: Principal) -> PolicySummary:
        self.principal = principal
        if self.error:
            raise self.error
        return PolicySummary(
            pack_name="control-baseline",
            pack_version="2.4.1",
            default_decision="ALLOW",
            total_rules=2,
            enforced_rules=1,
            planned_rules=1,
            counts_by_status={"enforced": 1, "planned": 1},
        )

    async def integration_health(
        self, query: IntegrationHealthQuery, principal: Principal
    ) -> IntegrationHealthPage:
        self.principal = principal
        if self.error:
            raise self.error
        return IntegrationHealthPage(state="empty", snapshot_at=NOW, items=(), next_cursor=None)

    async def service_status(self, principal: Principal) -> ServiceStatus:
        self.principal = principal
        if self.error:
            raise self.error
        return ServiceStatus(
            status="degraded",
            measured_at=NOW,
            components=(ServiceComponent(name="gate", status="unmeasured"),),
            instrumented_pipeline_stages=(),
        )


def _settings() -> Settings:
    return Settings(
        environment=Environment.TEST,
        v2_enabled=True,
        oidc_issuer="https://identity.example.test/",
        oidc_audience="dusk-control-plane",
        oidc_jwks_uri="https://identity.example.test/jwks.json",
        storage_enabled=True,
        database_url="postgresql+asyncpg://user:secret@database/control_plane",
        operations_read_api_enabled=True,
        decision_cursor_signing_key="x" * 32,
    )


def _client(reader: _Reader) -> TestClient:
    return TestClient(
        create_app(
            container=AppContainer(
                settings=_settings(), authenticator=_Authenticator(), operations_reader=reader
            )
        ),
        raise_server_exceptions=False,
    )


def test_policy_routes_require_auditor_and_use_claim_derived_tenant() -> None:
    reader = _Reader()
    with _client(reader) as client:
        forbidden = client.get("/v2/policies", headers={"Authorization": "Bearer operator"})
        injected = client.get(
            "/v2/policies?tenant_id=attacker", headers={"Authorization": "Bearer auditor"}
        )
        allowed = client.get("/v2/policies/summary", headers={"Authorization": "Bearer auditor"})
    assert forbidden.status_code == 403
    assert injected.status_code == 422
    assert allowed.status_code == 200
    assert reader.principal is not None
    assert reader.principal.tenant_id == str(TENANT)


def test_operational_routes_require_operator_and_report_empty_or_unmeasured() -> None:
    reader = _Reader()
    with _client(reader) as client:
        forbidden = client.get("/v2/service/status", headers={"Authorization": "Bearer analyst"})
        health = client.get("/v2/integrations/health", headers={"Authorization": "Bearer operator"})
        status = client.get("/v2/service/status", headers={"Authorization": "Bearer operator"})
    assert forbidden.status_code == 403
    assert health.json()["state"] == "empty"
    assert status.json()["components"][0]["status"] == "unmeasured"
    assert status.json()["instrumented_pipeline_stages"] == []


def test_operational_failure_is_standardized_and_sanitized() -> None:
    reader = _Reader()
    reader.error = OperationsQueryUnavailableError("postgresql://user:secret@internal")
    with _client(reader) as client:
        response = client.get("/v2/service/status", headers={"Authorization": "Bearer operator"})
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "OPERATIONAL_DATA_UNAVAILABLE"
    assert "secret" not in response.text
    assert response.json()["error"]["retryable"] is True


def test_stale_health_and_unapproved_diagnostics_are_not_presented_as_healthy() -> None:
    reader = PostgresOperationsReader(
        None,
        load_enterprise_pack(),
        OperationsCursorCodec(b"x" * 32),  # type: ignore[arg-type]
    )
    row = IntegrationHealth(
        tenant_id=TENANT,
        integration_key="cloud-adapter",
        integration_kind="adapter",
        status="HEALTHY",
        checked_at=NOW,
        latency_ms=10,
        safe_diagnostic_code="SECRET_INTERNAL_HOST",
    )
    stale = reader._health_view(row, NOW.replace(hour=13))
    assert stale.status == "STALE"
    assert stale.diagnostic_code == "STALE_MEASUREMENT"
    row.checked_at = NOW.replace(minute=59)
    fresh = reader._health_view(row, NOW.replace(hour=13))
    assert fresh.status == "HEALTHY"
    assert fresh.diagnostic_code is None


def test_policy_catalogue_uses_active_pack_and_tenant_bound_cursor() -> None:
    asyncio.run(_assert_policy_catalogue())


async def _assert_policy_catalogue() -> None:
    pack = load_enterprise_pack()
    codec = OperationsCursorCodec(b"x" * 32)
    reader = PostgresOperationsReader(None, pack, codec)  # type: ignore[arg-type]
    auditor = Principal(
        issuer="issuer",
        subject="auditor",
        tenant_id=str(TENANT),
        kind=IdentityKind.HUMAN,
        roles=frozenset({Role.AUDITOR}),
    )
    first = await reader.policies(PolicyListQuery(limit=1), auditor)
    summary = await reader.policy_summary(auditor)
    assert first.pack_version == pack.version
    assert first.items[0].id == sorted(rule.id for rule in pack.rules)[0]
    assert first.next_cursor is not None
    assert summary.total_rules == len(pack.rules)
    assert summary.enforced_rules == sum(rule.status == "enforced" for rule in pack.rules)
    assert summary.planned_rules == sum(rule.status == "planned" for rule in pack.rules)

    other_tenant = Principal(
        issuer="issuer",
        subject="auditor",
        tenant_id=str(uuid4()),
        kind=IdentityKind.HUMAN,
        roles=frozenset({Role.AUDITOR}),
    )
    try:
        await reader.policies(PolicyListQuery(limit=1, cursor=first.next_cursor), other_tenant)
    except InvalidOperationsCursorError:
        pass
    else:
        raise AssertionError("cross-tenant cursor was accepted")
