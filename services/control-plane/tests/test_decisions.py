"""Decision read API, cursor integrity, RBAC, and safe-error tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from dusk_control_plane.app import create_app
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.decisions import (
    AuditContinuity,
    DecisionCursorCodec,
    DecisionDetail,
    DecisionListQuery,
    DecisionNotFoundError,
    DecisionPage,
    DecisionQueryUnavailableError,
    DecisionSummary,
    InvalidDecisionCursorError,
)
from dusk_control_plane.dependencies import AppContainer
from dusk_control_plane.identity import IdentityKind, Principal, Role

TENANT_A = uuid4()
TENANT_B = uuid4()
TRACE_ID = uuid4()
NOW = datetime(2026, 9, 2, 15, 0, tzinfo=UTC)


class _Authenticator:
    async def authenticate(self, token: str) -> Principal:
        role = Role(token)
        return Principal(
            issuer="https://identity.example.test/",
            subject=f"subject-{token}",
            tenant_id=str(TENANT_A),
            kind=IdentityKind.HUMAN,
            roles=frozenset({role}),
        )


class _Reader:
    def __init__(self) -> None:
        self.list_principal: Principal | None = None
        self.list_error: Exception | None = None
        self.detail_error: Exception | None = None

    async def list_decisions(self, query: DecisionListQuery, principal: Principal) -> DecisionPage:
        self.list_principal = principal
        if self.list_error is not None:
            raise self.list_error
        return DecisionPage(
            items=(
                DecisionSummary(
                    trace_id=TRACE_ID,
                    created_at=NOW,
                    agent_id="agent-a",
                    action_type="network.firewall.update",
                    verdict="BLOCK",
                    behavioral_score=0.91,
                    blast_radius="HIGH",
                    policy_decision="DENY",
                    evidence_degraded=False,
                    response_status="DELIVERED",
                    detail_available=True,
                ),
            ),
            next_cursor=None,
            snapshot_at=NOW,
        )

    async def get_decision(self, trace_id: UUID, principal: Principal) -> DecisionDetail:
        if self.detail_error is not None:
            raise self.detail_error
        assert trace_id == TRACE_ID
        summary = (await self.list_decisions(DecisionListQuery(), principal)).items[0]
        return DecisionDetail(
            **summary.model_dump(),
            input_digest="sha256:" + "a" * 64,
            action=None,
            reasons=(),
            mitre_mappings=(),
            predicted_next=None,
            policy_pack_version="2026.09",
            policy_matches=(),
            evidence_state={"degraded": False},
            pipeline_timings={"total_ms": 2.0},
            audit=AuditContinuity(
                sequence=1,
                event_type="evaluation.decided",
                occurred_at=NOW,
                digest="b" * 64,
                previous_digest=None,
            ),
            similar_decisions=(),
            detail_deleted_at=None,
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
        decision_read_api_enabled=True,
        decision_cursor_signing_key="x" * 32,
    )


def _client(reader: _Reader) -> TestClient:
    return TestClient(
        create_app(
            container=AppContainer(
                settings=_settings(),
                authenticator=_Authenticator(),
                decision_reader=reader,
            )
        ),
        raise_server_exceptions=False,
    )


def test_signed_cursor_is_tenant_and_filter_bound_and_rejects_tampering() -> None:
    codec = DecisionCursorCodec(b"k" * 32)
    cursor = codec.encode(
        tenant_id=TENANT_A,
        filter_fingerprint="f" * 64,
        snapshot_at=NOW,
        after_created_at=NOW,
        after_id=TRACE_ID,
    )
    decoded = codec.decode(cursor, tenant_id=TENANT_A, filter_fingerprint="f" * 64)
    assert decoded.snapshot_at == NOW
    assert decoded.after_created_at == NOW
    assert decoded.after_id == TRACE_ID
    for invalid, tenant, fingerprint in (
        (cursor[:-1] + ("A" if cursor[-1] != "A" else "B"), TENANT_A, "f" * 64),
        (cursor, TENANT_B, "f" * 64),
        (cursor, TENANT_A, "0" * 64),
        ("not+base64", TENANT_A, "f" * 64),
    ):
        with pytest.raises(InvalidDecisionCursorError):
            codec.decode(invalid, tenant_id=tenant, filter_fingerprint=fingerprint)


def test_query_requires_utc_range_and_stable_filter_fingerprint() -> None:
    with pytest.raises(ValidationError):
        DecisionListQuery(created_from=datetime(2026, 9, 2, 15, 0))
    with pytest.raises(ValidationError):
        DecisionListQuery(
            created_from=datetime(2026, 9, 2, 16, 0, tzinfo=UTC),
            created_to=datetime(2026, 9, 2, 15, 0, tzinfo=UTC),
        )
    first = DecisionListQuery(limit=10, verdict="BLOCK")
    second = DecisionListQuery(limit=100, verdict="BLOCK", cursor="opaque")
    assert first.fingerprint() == second.fingerprint()


def test_viewer_receives_only_summary_and_claim_derived_tenant() -> None:
    reader = _Reader()
    with _client(reader) as client:
        response = client.get(
            "/v2/decisions?verdict=BLOCK&tenant_id=attacker",
            headers={"Authorization": "Bearer viewer", "X-Tenant-ID": str(TENANT_B)},
        )
    assert response.status_code == 422  # undeclared query fields are rejected
    with _client(reader) as client:
        response = client.get(
            "/v2/decisions?verdict=BLOCK", headers={"Authorization": "Bearer viewer"}
        )
    assert response.status_code == 200
    assert response.json()["items"][0]["trace_id"] == str(TRACE_ID)
    assert "action" not in response.json()["items"][0]
    assert reader.list_principal is not None
    assert reader.list_principal.tenant_id == str(TENANT_A)


def test_detail_requires_analyst_capability_and_uses_standard_not_found_error() -> None:
    reader = _Reader()
    with _client(reader) as client:
        viewer = client.get(f"/v2/decisions/{TRACE_ID}", headers={"Authorization": "Bearer viewer"})
        analyst = client.get(
            f"/v2/decisions/{TRACE_ID}", headers={"Authorization": "Bearer analyst"}
        )
    assert viewer.status_code == 403
    assert viewer.json()["error"]["code"] == "FORBIDDEN"
    assert analyst.status_code == 200
    assert analyst.json()["audit"]["digest"] == "b" * 64

    reader.detail_error = DecisionNotFoundError()
    with _client(reader) as client:
        missing = client.get(
            f"/v2/decisions/{uuid4()}", headers={"Authorization": "Bearer analyst"}
        )
    assert missing.status_code == 404
    assert missing.json()["error"] == {
        "code": "DECISION_NOT_FOUND",
        "message": "Decision was not found",
        "request_id": missing.headers["X-Request-ID"],
        "retryable": False,
    }


@pytest.mark.parametrize(
    ("error", "status", "code", "retryable"),
    (
        (InvalidDecisionCursorError(), 422, "INVALID_CURSOR", False),
        (DecisionQueryUnavailableError(), 503, "DECISION_QUERY_UNAVAILABLE", True),
    ),
)
def test_list_failures_use_safe_standard_errors(
    error: Exception, status: int, code: str, retryable: bool
) -> None:
    reader = _Reader()
    reader.list_error = error
    with _client(reader) as client:
        response = client.get("/v2/decisions", headers={"Authorization": "Bearer analyst"})
    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert response.json()["error"]["retryable"] is retryable
    assert response.json()["error"]["request_id"] == response.headers["X-Request-ID"]


def test_read_routes_are_absent_when_default_disabled() -> None:
    settings = Settings(environment=Environment.TEST)
    app = create_app(container=AppContainer.build(settings=settings))
    paths = {route.path for route in app.routes}
    assert "/v2/decisions" not in paths
    assert "/v2/decisions/{trace_id}" not in paths
