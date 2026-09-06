"""Atomic evidence boundary, redaction, and audit-chain unit tests."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from dusk_control_plane.app import create_app
from dusk_control_plane.audit import (
    AuditCheckpoint,
    AuditIntegrityError,
    DurableCommitUnavailableError,
    DurableDecision,
    DurableEvaluationService,
    audit_digest,
    redact_for_storage,
    verify_audit_chain,
    verify_signed_audit_chain,
)
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dependencies import AppContainer
from dusk_control_plane.evaluations import (
    CanonicalAction,
    EvaluationRequest,
    EvaluationResponse,
    EvidenceEnvelope,
    PipelineTimings,
)
from dusk_control_plane.identity import IdentityKind, Principal
from dusk_control_plane.storage.models import AuditEvent

NOW = datetime(2026, 9, 1, tzinfo=UTC)


class _Signer:
    key_id = "test-key-1"

    async def sign(self, digest: bytes) -> bytes:
        return hmac.new(b"test-only-key", digest, hashlib.sha256).digest()

    async def verify(self, digest: bytes, signature: bytes, key_id: str) -> bool:
        expected = await self.sign(digest)
        return key_id == self.key_id and hmac.compare_digest(expected, signature)


def _event(tenant_id: UUID, sequence: int, previous: bytes | None) -> AuditEvent:
    event = AuditEvent(
        id=uuid4(),
        tenant_id=tenant_id,
        sequence=sequence,
        event_type="evaluation.decided",
        decision_id=uuid4(),
        principal_id=uuid4(),
        occurred_at=NOW,
        previous_digest=previous,
        digest=b"x" * 32,
        integrity_metadata={"format": "dusk.audit.v1", "verdict": "BLOCK"},
        sensitive_detail=None,
    )
    event.digest = audit_digest(
        tenant_id=tenant_id,
        sequence=sequence,
        event_type=event.event_type,
        decision_id=event.decision_id,
        principal_id=event.principal_id,
        occurred_at=event.occurred_at,
        previous_digest=previous,
        integrity_metadata=event.integrity_metadata,
    )
    return event


def _chain() -> tuple[UUID, list[AuditEvent], AuditCheckpoint]:
    tenant_id = uuid4()
    first = _event(tenant_id, 1, None)
    second = _event(tenant_id, 2, first.digest)
    return tenant_id, [first, second], AuditCheckpoint(tenant_id, 2, second.digest)


def test_chain_verifier_accepts_canonical_chain() -> None:
    tenant_id, events, checkpoint = _chain()
    verify_audit_chain(tenant_id, events, checkpoint)


@pytest.mark.anyio
async def test_signed_verifier_detects_signature_mismatch() -> None:
    tenant_id, events, checkpoint = _chain()
    signer = _Signer()
    for event in events:
        event.signing_key_id = signer.key_id
        event.signature = await signer.sign(event.digest)
    await verify_signed_audit_chain(tenant_id, events, checkpoint, signer)
    events[-1].signature = b"invalid"
    with pytest.raises(AuditIntegrityError, match="signature mismatch"):
        await verify_signed_audit_chain(tenant_id, events, checkpoint, signer)


@pytest.mark.parametrize("mutation", ["content", "delete", "reorder", "splice"])
def test_chain_verifier_detects_mutation_deletion_reordering_and_tenant_splice(mutation) -> None:
    tenant_id, events, checkpoint = _chain()
    if mutation == "content":
        events[0].integrity_metadata = {"format": "dusk.audit.v1", "verdict": "ALLOW"}
    elif mutation == "delete":
        events.pop()
    elif mutation == "reorder":
        events.reverse()
    else:
        events[1].tenant_id = uuid4()
    with pytest.raises(AuditIntegrityError):
        verify_audit_chain(tenant_id, events, checkpoint)


def test_redaction_is_recursive_bounded_and_does_not_mutate_input() -> None:
    source = {
        "target": "cluster-a",
        "credentials": {"token": "raw-token", "nested": [{"password": "raw-password"}]},
        "prompt": "unrestricted prompt",
    }
    original = deepcopy(source)
    stored = redact_for_storage(source)
    assert stored == {
        "target": "cluster-a",
        "credentials": "[REDACTED]",
        "prompt": "[REDACTED]",
    }
    assert source == original
    assert "raw-token" not in repr(stored)
    assert "raw-password" not in repr(stored)
    too_deep: object = "too deep"
    for _ in range(18):
        too_deep = {"next": too_deep}
    with pytest.raises(ValueError, match="nesting"):
        redact_for_storage(too_deep)


def _request() -> EvaluationRequest:
    return EvaluationRequest(
        action=CanonicalAction(
            agent_id="agent-a",
            action_type="storage.delete",
            target="bucket-a",
            consequential=True,
        ),
        evidence=(
            EvidenceEnvelope(
                domain="action",
                source_identity="cloud-audit",
                provenance="signed-event",
                observed_at=NOW,
                digest="sha256:" + "0" * 64,
                payload={"type": "storage.delete"},
                tenant_id="tenant-a",
                key_id="test-key",
                nonce="test-nonce-00000001",
                signature="a" * 86,
            ),
        ),
        idempotency_key="request-1",
    )


def _response() -> EvaluationResponse:
    return EvaluationResponse(
        trace_id=str(uuid4()),
        verdict="BLOCK",
        behavioral_score=0.9,
        blast_radius="HIGH",
        reasons=("destructive action",),
        reason_codes=("POLICY_DENY",),
        mitre_attack=(),
        mitre_atlas=(),
        predicted_next="none",
        policy_decision="DENY",
        policy_pack_version="1.0.0",
        matched_rules=(),
        evidence_degraded=False,
        response_status="DECIDED",
        pipeline_timings=PipelineTimings(behavioral_ms=1, policy_ms=1, total_ms=2),
        similar_decision_ids=(),
    )


class _Evaluator:
    async def evaluate(self, request, principal):
        return _response()


class _StalledEvaluator:
    async def evaluate(self, request, principal):
        await asyncio.sleep(60)
        return _response()


class _Store:
    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.calls = 0

    async def persist(self, **kwargs):
        self.calls += 1
        if self.failure:
            raise self.failure
        response = kwargs["response"]
        trace_id = UUID(response.trace_id)
        return DurableDecision(
            uuid4(),
            trace_id,
            uuid4(),
            uuid4(),
            AuditCheckpoint(uuid4(), 1, b"x" * 32),
            True,
            response.model_copy(update={"response_status": "DELIVERY_PENDING"}),
        )


@pytest.mark.anyio
async def test_durable_wrapper_returns_only_after_commit_and_exposes_lifecycle() -> None:
    store = _Store()
    principal = Principal("issuer", "subject", str(uuid4()), IdentityKind.WORKLOAD)
    result = await DurableEvaluationService(_Evaluator(), store).evaluate(_request(), principal)
    assert store.calls == 1
    assert result.response_status == "DELIVERY_PENDING"


@pytest.mark.anyio
async def test_consequential_evaluation_fails_closed_on_storage_outage() -> None:
    store = _Store(failure=TimeoutError("postgresql unavailable"))
    principal = Principal("issuer", "subject", str(uuid4()), IdentityKind.WORKLOAD)
    with pytest.raises(DurableCommitUnavailableError):
        await DurableEvaluationService(_Evaluator(), store).evaluate(_request(), principal)


class _Authenticator:
    async def authenticate(self, token: str) -> Principal:
        return Principal("issuer", "subject", str(uuid4()), IdentityKind.WORKLOAD)


def test_durable_commit_outage_returns_sanitized_retryable_503() -> None:
    settings = Settings(
        environment=Environment.TEST,
        v2_enabled=True,
        oidc_issuer="https://identity.example.test/",
        oidc_audience="dusk-control-plane",
        oidc_jwks_uri="https://identity.example.test/jwks.json",
    )
    service = DurableEvaluationService(
        _Evaluator(),
        _Store(failure=TimeoutError("postgresql://user:secret@private-host/database")),
    )
    app = create_app(
        container=AppContainer(
            settings=settings,
            authenticator=_Authenticator(),
            evaluation_service=service,
        )
    )
    with TestClient(app) as client:
        response = client.post(
            "/v2/evaluations",
            headers={"Authorization": "Bearer test-token"},
            json=_request().model_dump(mode="json"),
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "EVALUATION_UNAVAILABLE"
    assert response.json()["error"]["retryable"] is True
    assert "secret" not in response.text
    assert "private-host" not in response.text


def test_stalled_evaluation_is_cancelled_by_fail_closed_request_deadline() -> None:
    settings = Settings(
        environment=Environment.TEST,
        v2_enabled=True,
        oidc_issuer="https://identity.example.test/",
        oidc_audience="dusk-control-plane",
        oidc_jwks_uri="https://identity.example.test/jwks.json",
        evaluation_timeout_seconds=0.1,
    )
    store = _Store()
    service = DurableEvaluationService(_StalledEvaluator(), store)
    app = create_app(
        container=AppContainer(
            settings=settings,
            authenticator=_Authenticator(),
            evaluation_service=service,
        )
    )
    with TestClient(app) as client:
        response = client.post(
            "/v2/evaluations",
            headers={"Authorization": "Bearer test-token"},
            json=_request().model_dump(mode="json"),
        )
    assert response.status_code == 503
    assert response.json()["error"] == {
        "code": "EVALUATION_UNAVAILABLE",
        "message": "Evaluation is temporarily unavailable",
        "request_id": response.headers["X-Request-ID"],
        "retryable": True,
    }
    assert store.calls == 0
