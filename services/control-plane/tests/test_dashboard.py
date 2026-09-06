"""Dashboard and agent investigation API boundary tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from dusk_control_plane.app import create_app
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dashboard import (
    ActionBreakdown,
    AgentDetail,
    AgentNotFoundError,
    AgentRiskCursorCodec,
    AgentRiskItem,
    AgentRiskPage,
    AgentRiskQuery,
    DashboardQueryUnavailableError,
    DashboardSummary,
    DashboardWindowQuery,
    DecisionVolume,
    InvalidAgentRiskCursorError,
    LatencyMetric,
    MetricFreshness,
    MetricValue,
    _RiskCursor,
)
from dusk_control_plane.dependencies import AppContainer
from dusk_control_plane.identity import IdentityKind, Principal, Role

TENANT = uuid4()
NOW = datetime(2026, 9, 2, 16, 0, tzinfo=UTC)


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
    def __init__(self) -> None:
        self.principal: Principal | None = None
        self.error: Exception | None = None

    async def summary(self, query: DashboardWindowQuery, principal: Principal) -> DashboardSummary:
        self.principal = principal
        if self.error:
            raise self.error
        metric = MetricValue(value=4, previous_value=2, change_percent=100)
        return DashboardSummary(
            window=query.window,
            window_start=NOW - query.window.duration,
            window_end=NOW,
            comparison_start=NOW - 2 * query.window.duration,
            comparison_end=NOW - query.window.duration,
            decisions=metric,
            blocked=metric,
            would_block=metric,
            allowed=metric,
            active_agents=metric,
            high_risk_decisions=metric,
            evaluation_latency=LatencyMetric(p95_ms=12, sample_count=4),
            freshness=_freshness(),
        )

    async def decision_volume(
        self, query: DashboardWindowQuery, principal: Principal
    ) -> DecisionVolume:
        raise NotImplementedError

    async def action_breakdown(
        self, query: DashboardWindowQuery, principal: Principal
    ) -> ActionBreakdown:
        raise NotImplementedError

    async def agent_risk(self, query: AgentRiskQuery, principal: Principal) -> AgentRiskPage:
        self.principal = principal
        if self.error:
            raise self.error
        item = AgentRiskItem(
            agent_id="agent-a",
            risk_score=Decimal("0.9"),
            decision_count=4,
            high_risk_count=2,
            block_count=1,
            would_block_count=1,
            last_seen_at=NOW,
        )
        return AgentRiskPage(
            window=query.window,
            window_start=NOW - query.window.duration,
            window_end=NOW,
            items=(item,),
            next_cursor=None,
            freshness=_freshness(),
        )

    async def agent_detail(
        self, agent_id: str, query: DashboardWindowQuery, principal: Principal
    ) -> AgentDetail:
        if self.error:
            raise self.error
        assert agent_id == "agent-a"
        return AgentDetail(
            agent_id=agent_id,
            risk_score=Decimal("0.9"),
            decision_count=4,
            high_risk_count=2,
            block_count=1,
            would_block_count=1,
            last_seen_at=NOW,
            window=query.window,
            window_start=NOW - query.window.duration,
            window_end=NOW,
            first_seen_at=NOW - timedelta(hours=1),
            allow_count=2,
            evaluation_latency=LatencyMetric(p95_ms=12, sample_count=4),
            recent_decisions=(),
            freshness=_freshness(),
        )


def _freshness() -> MetricFreshness:
    return MetricFreshness(state="available", snapshot_at=NOW, source_last_updated_at=NOW)


def _settings() -> Settings:
    return Settings(
        environment=Environment.TEST,
        v2_enabled=True,
        oidc_issuer="https://identity.example.test/",
        oidc_audience="dusk-control-plane",
        oidc_jwks_uri="https://identity.example.test/jwks.json",
        storage_enabled=True,
        database_url="postgresql+asyncpg://user:secret@database/control_plane",
        dashboard_read_api_enabled=True,
        decision_cursor_signing_key="x" * 32,
    )


def _client(reader: _Reader) -> TestClient:
    return TestClient(
        create_app(
            container=AppContainer(
                settings=_settings(), authenticator=_Authenticator(), dashboard_reader=reader
            )
        ),
        raise_server_exceptions=False,
    )


def test_dashboard_is_viewer_accessible_and_tenant_is_claim_derived() -> None:
    reader = _Reader()
    with _client(reader) as client:
        rejected = client.get(
            "/v2/dashboard/summary?tenant_id=attacker",
            headers={"Authorization": "Bearer viewer"},
        )
        response = client.get(
            "/v2/dashboard/summary?window=7d",
            headers={"Authorization": "Bearer viewer"},
        )
    assert rejected.status_code == 422
    assert response.status_code == 200
    assert response.json()["freshness"]["poll_after_seconds"] == 30
    assert response.json()["timezone"] == "UTC"
    assert reader.principal is not None
    assert reader.principal.tenant_id == str(TENANT)


def test_agent_views_require_investigation_capability_and_map_safe_errors() -> None:
    reader = _Reader()
    with _client(reader) as client:
        viewer = client.get("/v2/agents/risk", headers={"Authorization": "Bearer viewer"})
        analyst = client.get("/v2/agents/risk", headers={"Authorization": "Bearer analyst"})
    assert viewer.status_code == 403
    assert analyst.status_code == 200
    assert analyst.json()["items"][0]["agent_id"] == "agent-a"

    reader.error = AgentNotFoundError()
    with _client(reader) as client:
        missing = client.get("/v2/agents/agent-a", headers={"Authorization": "Bearer analyst"})
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "AGENT_NOT_FOUND"

    reader.error = DashboardQueryUnavailableError()
    with _client(reader) as client:
        unavailable = client.get(
            "/v2/dashboard/summary", headers={"Authorization": "Bearer viewer"}
        )
    assert unavailable.status_code == 503
    assert unavailable.json()["error"]["retryable"] is True


def test_agent_cursor_is_versioned_tenant_and_filter_bound() -> None:
    codec = AgentRiskCursorCodec(b"k" * 32)
    query = AgentRiskQuery(window="7d", minimum_risk_score=0.5)
    cursor = codec.encode(
        tenant_id=TENANT,
        query=query,
        value=_RiskCursor(
            snapshot_at=NOW,
            risk_score=Decimal("0.9"),
            high_risk_count=2,
            last_seen_at=NOW,
            agent_id="agent-a",
        ),
    )
    decoded = codec.decode(cursor, tenant_id=TENANT, query=query)
    assert decoded.agent_id == "agent-a"
    assert decoded.snapshot_at == NOW
    with pytest.raises(InvalidAgentRiskCursorError):
        codec.decode(cursor, tenant_id=uuid4(), query=query)
    with pytest.raises(InvalidAgentRiskCursorError):
        codec.decode(cursor, tenant_id=TENANT, query=AgentRiskQuery(window="30d"))
    with pytest.raises(InvalidAgentRiskCursorError):
        replacement = "A" if cursor[-1] != "A" else "B"
        codec.decode(cursor[:-1] + replacement, tenant_id=TENANT, query=query)


def test_dashboard_feature_flag_is_default_off_and_validated() -> None:
    assert Settings().dashboard_read_api_enabled is False
    with pytest.raises(ValueError, match="dashboard_read_api_enabled requires"):
        Settings(dashboard_read_api_enabled=True, decision_cursor_signing_key="x" * 32)
