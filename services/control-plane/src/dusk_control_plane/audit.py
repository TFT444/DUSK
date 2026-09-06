"""Atomic decision evidence persistence and tenant-scoped audit verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Literal, Protocol, cast
from uuid import UUID, uuid4

from pydantic import BaseModel
from sqlalchemy import select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from dusk_control_plane.evaluations import (
    EvaluationRequest,
    EvaluationResponse,
    EvaluationService,
    EvaluationUnavailableError,
    PipelineTimings,
    PolicyMatchResponse,
)
from dusk_control_plane.identity import Principal
from dusk_control_plane.observability import Telemetry
from dusk_control_plane.storage.database import Database
from dusk_control_plane.storage.models import (
    AuditEvent,
    Decision,
    OutboxDelivery,
    PolicyMatch,
    PrincipalRecord,
    Tenant,
)
from dusk_control_plane.storage.models import (
    CanonicalAction as StoredCanonicalAction,
)

AUDIT_FORMAT = "dusk.audit.v1"
AUDIT_EVENT_TYPE = "evaluation.decided"
_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|credential|password|prompt|provider.?payload|raw.?request|"
    r"response.?body|secret|session|token)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?:"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"
    r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
    r"|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"
    r"|[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@"
    r")",
    re.IGNORECASE,
)
_MAX_CONTAINER_ITEMS = 256
_MAX_STRING_LENGTH = 4096
_MAX_REDACTED_BYTES = 64 * 1024
JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]
AnyVerdict = Literal["ALLOW", "WOULD-BLOCK", "BLOCK"]
AnyPolicyDecision = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]


class DurableCommitUnavailableError(EvaluationUnavailableError):
    """The authorization evidence transaction could not be committed."""


class AuditIntegrityError(RuntimeError):
    """Stored evidence does not match the canonical tenant audit chain."""


@dataclass(frozen=True)
class AuditCheckpoint:
    tenant_id: UUID
    sequence: int
    digest: bytes


@dataclass(frozen=True)
class DurableDecision:
    decision_id: UUID
    trace_id: UUID
    audit_event_id: UUID
    delivery_id: UUID
    checkpoint: AuditCheckpoint
    inserted: bool
    response: EvaluationResponse
    audit_ms: float = 0


@dataclass(frozen=True)
class OutboxIntent:
    destination_key: str = "decision-events"
    delivery_kind: str = "DECISION_RECORDED"
    destination_kind: Literal["WEBHOOK", "ENFORCEMENT_BROKER"] = "WEBHOOK"
    max_attempts: int = 10


DEFAULT_OUTBOX_INTENT = OutboxIntent()


class OutboxIntentResolver(Protocol):
    """Select a trusted destination from the durable decision result."""

    def resolve(self, request: EvaluationRequest, response: EvaluationResponse) -> OutboxIntent: ...


@dataclass(frozen=True)
class ProviderBrokerIntentResolver:
    """Route only allowed actions to a credential-holding enforcement broker."""

    broker_destination_key: str
    event_destination_key: str = "decision-events"
    max_attempts: int = 10

    def __post_init__(self) -> None:
        keys = (self.broker_destination_key, self.event_destination_key)
        if any(not key or len(key) > 128 for key in keys):
            raise ValueError("broker destination keys are invalid")
        if not 1 <= self.max_attempts <= 100:
            raise ValueError("broker maximum attempts is invalid")

    def resolve(self, request: EvaluationRequest, response: EvaluationResponse) -> OutboxIntent:
        del request
        if response.verdict == "ALLOW":
            return OutboxIntent(
                destination_key=self.broker_destination_key,
                destination_kind="ENFORCEMENT_BROKER",
                delivery_kind="ACTION_EXECUTION",
                max_attempts=self.max_attempts,
            )
        return OutboxIntent(
            destination_key=self.event_destination_key,
            destination_kind="WEBHOOK",
            delivery_kind="DECISION_RECORDED",
            max_attempts=self.max_attempts,
        )


class DecisionEvidenceStore(Protocol):
    async def persist(
        self,
        *,
        request: EvaluationRequest,
        response: EvaluationResponse,
        principal: Principal,
        intent: OutboxIntent = DEFAULT_OUTBOX_INTENT,
    ) -> DurableDecision: ...


class AuditSigner(Protocol):
    """External signing boundary, normally backed by a managed KMS/HSM key."""

    @property
    def key_id(self) -> str: ...

    async def sign(self, digest: bytes) -> bytes: ...

    async def verify(self, digest: bytes, signature: bytes, key_id: str) -> bool: ...


class DurableEvaluationService:
    """Require durable decision evidence before returning a consequential verdict."""

    def __init__(
        self,
        evaluator: EvaluationService,
        evidence_store: DecisionEvidenceStore,
        telemetry: Telemetry | None = None,
        intent_resolver: OutboxIntentResolver | None = None,
    ) -> None:
        self._evaluator = evaluator
        self._evidence_store = evidence_store
        self._telemetry = telemetry
        self._intent_resolver = intent_resolver

    async def evaluate(
        self, request: EvaluationRequest, principal: Principal
    ) -> EvaluationResponse:
        started = time.perf_counter()
        response = await self._evaluator.evaluate(request, principal)
        intent = (
            self._intent_resolver.resolve(request, response)
            if self._intent_resolver is not None
            else DEFAULT_OUTBOX_INTENT
        )
        persistence_started = time.perf_counter()
        try:
            if self._telemetry is None:
                durable = await self._evidence_store.persist(
                    request=request, response=response, principal=principal, intent=intent
                )
            else:
                with self._telemetry.stage("persistence", decision_trace_id=response.trace_id):
                    durable = await self._evidence_store.persist(
                        request=request, response=response, principal=principal, intent=intent
                    )
        except DurableCommitUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed at the durability boundary
            raise DurableCommitUnavailableError from exc
        persistence_ms = (time.perf_counter() - persistence_started) * 1000
        timings = durable.response.pipeline_timings.model_copy(
            update={
                "persistence_ms": persistence_ms,
                "audit_ms": durable.audit_ms,
                "total_ms": (time.perf_counter() - started) * 1000,
            }
        )
        return durable.response.model_copy(update={"pipeline_timings": timings})


class PostgresDecisionEvidenceStore:
    """Commit the decision, audit link, and delivery intent as one transaction."""

    def __init__(
        self,
        database: Database,
        signer: AuditSigner,
        *,
        telemetry: Telemetry | None = None,
    ) -> None:
        self._database = database
        self._signer = signer
        self._telemetry = telemetry

    async def persist(
        self,
        *,
        request: EvaluationRequest,
        response: EvaluationResponse,
        principal: Principal,
        intent: OutboxIntent = DEFAULT_OUTBOX_INTENT,
    ) -> DurableDecision:
        started = time.perf_counter()
        try:
            tenant_id = UUID(principal.tenant_id)
        except ValueError as exc:
            raise DurableCommitUnavailableError("identity tenant is not a storage UUID") from exc
        try:
            async with self._database.transaction() as session:
                durable = await self._persist_transaction(
                    session=session,
                    tenant_id=tenant_id,
                    request=request,
                    response=response,
                    principal=principal,
                    intent=intent,
                )
                if durable.inserted:
                    persistence_ms = (time.perf_counter() - started) * 1000
                    timings = durable.response.pipeline_timings.model_copy(
                        update={
                            "persistence_ms": persistence_ms,
                            "audit_ms": durable.audit_ms,
                            "total_ms": durable.response.pipeline_timings.total_ms + persistence_ms,
                        }
                    )
                    await session.execute(
                        update(Decision)
                        .where(Decision.id == durable.decision_id, Decision.tenant_id == tenant_id)
                        .values(pipeline_timings=timings.model_dump(mode="json"))
                    )
                    durable = DurableDecision(
                        decision_id=durable.decision_id,
                        trace_id=durable.trace_id,
                        audit_event_id=durable.audit_event_id,
                        delivery_id=durable.delivery_id,
                        checkpoint=durable.checkpoint,
                        inserted=True,
                        response=durable.response.model_copy(update={"pipeline_timings": timings}),
                        audit_ms=durable.audit_ms,
                    )
                return durable
        except DurableCommitUnavailableError:
            raise
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise DurableCommitUnavailableError("durable evidence commit unavailable") from exc

    async def _persist_transaction(
        self,
        *,
        session: AsyncSession,
        tenant_id: UUID,
        request: EvaluationRequest,
        response: EvaluationResponse,
        principal: Principal,
        intent: OutboxIntent,
    ) -> DurableDecision:
        tenant = await session.scalar(select(Tenant.id).where(Tenant.id == tenant_id))
        if tenant is None:
            raise DurableCommitUnavailableError("identity tenant is not provisioned")

        redacted_action = redact_for_storage(request.action.model_dump(mode="json"))
        input_digest = hashlib.sha256(_canonical_bytes(request)).digest()
        # Serialize only retries for this tenant/key.  The database lock closes the
        # lookup/insert race across processes while preserving cross-tenant progress.
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 211))"),
            {"lock_key": f"{tenant_id}:{request.idempotency_key}"},
        )
        existing = await session.execute(
            select(Decision, StoredCanonicalAction.input_digest)
            .join(
                StoredCanonicalAction,
                (StoredCanonicalAction.tenant_id == Decision.tenant_id)
                & (StoredCanonicalAction.id == Decision.action_id),
            )
            .where(
                Decision.tenant_id == tenant_id,
                Decision.idempotency_key == request.idempotency_key,
            )
        )
        row = existing.one_or_none()
        if row is not None:
            decision, stored_digest = row
            if not hmac.compare_digest(stored_digest, input_digest):
                raise DurableCommitUnavailableError("idempotency key conflicts with input digest")
            audit = await session.scalar(
                select(AuditEvent).where(
                    AuditEvent.tenant_id == tenant_id,
                    AuditEvent.decision_id == decision.id,
                )
            )
            delivery = await session.scalar(
                select(OutboxDelivery).where(
                    OutboxDelivery.tenant_id == tenant_id,
                    OutboxDelivery.decision_id == decision.id,
                )
            )
            if audit is None or delivery is None:
                raise DurableCommitUnavailableError("idempotent evidence bundle is incomplete")
            stored_response = await _restore_response(session, tenant_id, decision)
            return DurableDecision(
                decision.id,
                decision.trace_id,
                audit.id,
                delivery.delivery_id,
                AuditCheckpoint(tenant_id, audit.sequence, audit.digest),
                False,
                stored_response,
                float((decision.pipeline_timings or {}).get("audit_ms", 0)),
            )

        observed_at = await _database_now(session)
        principal_id = await _upsert_principal(session, tenant_id, principal, observed_at)
        action = StoredCanonicalAction(
            tenant_id=tenant_id,
            input_digest=input_digest,
            redacted_action=redacted_action,
        )
        session.add(action)
        await session.flush()

        decision = Decision(
            tenant_id=tenant_id,
            action_id=action.id,
            trace_id=_trace_uuid(response.trace_id),
            idempotency_key=request.idempotency_key,
            agent_id=request.action.agent_id,
            verdict=response.verdict,
            behavioral_score=Decimal(str(response.behavioral_score)),
            blast_radius=response.blast_radius,
            reasons=[{"message": value} for value in response.reasons]
            + [{"code": value} for value in response.reason_codes],
            mitre_mappings=[
                *({"framework": "MITRE ATT&CK", "id": value} for value in response.mitre_attack),
                *({"framework": "MITRE ATLAS", "id": value} for value in response.mitre_atlas),
            ],
            predicted_next={"action": response.predicted_next},
            policy_decision=response.policy_decision,
            policy_pack_version=response.policy_pack_version,
            evidence_state={"degraded": response.evidence_degraded},
            pipeline_timings=response.pipeline_timings.model_dump(mode="json"),
            response_status="DELIVERY_PENDING",
        )
        session.add(decision)
        await session.flush()
        for match in response.matched_rules:
            session.add(
                PolicyMatch(
                    tenant_id=tenant_id,
                    decision_id=decision.id,
                    rule_id=match.id,
                    rule_version=match.version,
                    effect=response.policy_decision,
                    safe_metadata=redact_for_storage(match.model_dump(mode="json")),
                )
            )

        # Serialize all writers for this tenant, including the first event in a chain.
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:tenant_id, 197))"),
            {"tenant_id": str(tenant_id)},
        )
        previous = await session.scalar(
            select(AuditEvent)
            .where(AuditEvent.tenant_id == tenant_id)
            .order_by(AuditEvent.sequence.desc())
            .limit(1)
        )
        sequence = 1 if previous is None else previous.sequence + 1
        occurred_at = await _database_now(session)
        metadata = _integrity_metadata(
            decision,
            input_digest,
            response,
            principal_id=principal_id,
        )
        digest = audit_digest(
            tenant_id=tenant_id,
            sequence=sequence,
            event_type=AUDIT_EVENT_TYPE,
            decision_id=decision.id,
            principal_id=principal_id,
            occurred_at=occurred_at,
            previous_digest=None if previous is None else previous.digest,
            integrity_metadata=metadata,
        )
        audit_event_id = uuid4()
        delivery_id = uuid4()
        audit_started = time.perf_counter()
        try:
            if self._telemetry is None:
                signature = await self._signer.sign(digest)
            else:
                with self._telemetry.stage(
                    "audit",
                    decision_trace_id=response.trace_id,
                    decision_id=str(decision.id),
                    audit_event_id=str(audit_event_id),
                    delivery_id=str(delivery_id),
                ):
                    signature = await self._signer.sign(digest)
        except Exception as exc:  # noqa: BLE001 - signer detail cannot cross the boundary
            raise DurableCommitUnavailableError("audit signing unavailable") from exc
        if not signature or len(signature) > 8192 or not self._signer.key_id:
            raise DurableCommitUnavailableError("audit signer returned invalid evidence")
        audit = AuditEvent(
            id=audit_event_id,
            tenant_id=tenant_id,
            sequence=sequence,
            event_type=AUDIT_EVENT_TYPE,
            decision_id=decision.id,
            principal_id=principal_id,
            occurred_at=occurred_at,
            previous_digest=None if previous is None else previous.digest,
            digest=digest,
            signing_key_id=self._signer.key_id,
            signature=signature,
            integrity_metadata=metadata,
            sensitive_detail=None,
        )
        delivery = OutboxDelivery(
            tenant_id=tenant_id,
            decision_id=decision.id,
            delivery_id=delivery_id,
            deduplication_key=f"decision:{decision.id}",
            destination_key=intent.destination_key,
            destination_kind=intent.destination_kind,
            delivery_kind=intent.delivery_kind,
            redacted_payload={
                "audit_digest": digest.hex(),
                "audit_sequence": sequence,
                "decision_id": str(decision.id),
                "trace_id": str(decision.trace_id),
                "verdict": decision.verdict,
                "action_digest": input_digest.hex(),
            },
            max_attempts=intent.max_attempts,
            next_attempt_at=occurred_at,
        )
        session.add_all((audit, delivery))
        await session.flush()
        audit_ms = (time.perf_counter() - audit_started) * 1000
        return DurableDecision(
            decision.id,
            decision.trace_id,
            audit.id,
            delivery_id,
            AuditCheckpoint(tenant_id, sequence, digest),
            True,
            response.model_copy(
                update={
                    "trace_id": str(decision.trace_id),
                    "response_status": "DELIVERY_PENDING",
                }
            ),
            audit_ms,
        )


def redact_for_storage(value: object, *, _depth: int = 0) -> JsonValue:
    """Return bounded JSON data with credential-bearing fields irreversibly masked."""
    if _depth > 16:
        raise ValueError("stored content exceeds maximum nesting depth")
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _redact_string(value)
    if isinstance(value, Mapping):
        if len(value) > _MAX_CONTAINER_ITEMS:
            raise ValueError("stored object exceeds maximum field count")
        redacted = {
            str(key)[:128]: "[REDACTED]"
            if _SENSITIVE_KEY.search(str(key))
            else redact_for_storage(cast(object, item), _depth=_depth + 1)
            for key, item in value.items()
        }
        if len(_canonical_bytes(redacted)) > _MAX_REDACTED_BYTES:
            raise ValueError("redacted content exceeds storage limit")
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        if len(value) > _MAX_CONTAINER_ITEMS:
            raise ValueError("stored array exceeds maximum item count")
        return [redact_for_storage(item, _depth=_depth + 1) for item in value]
    raise ValueError("stored content must be JSON compatible")


def _redact_string(value: str) -> str:
    return "[REDACTED]" if _SENSITIVE_VALUE.search(value) else value[:_MAX_STRING_LENGTH]


def audit_digest(
    *,
    tenant_id: UUID,
    sequence: int,
    event_type: str,
    decision_id: UUID | None,
    principal_id: UUID | None,
    occurred_at: datetime,
    previous_digest: bytes | None,
    integrity_metadata: Mapping[str, object],
) -> bytes:
    document = {
        "format": AUDIT_FORMAT,
        "tenant_id": str(tenant_id),
        "sequence": sequence,
        "event_type": event_type,
        "decision_id": None if decision_id is None else str(decision_id),
        "principal_id": None if principal_id is None else str(principal_id),
        "occurred_at": occurred_at.astimezone(UTC).isoformat(timespec="microseconds"),
        "previous_digest": None if previous_digest is None else previous_digest.hex(),
        "integrity_metadata": integrity_metadata,
    }
    return hashlib.sha256(_canonical_bytes(document)).digest()


def verify_audit_chain(
    tenant_id: UUID,
    events: Sequence[AuditEvent],
    checkpoint: AuditCheckpoint,
) -> None:
    """Verify a complete ordered chain against an independently retained checkpoint."""
    if checkpoint.tenant_id != tenant_id:
        raise AuditIntegrityError("checkpoint tenant mismatch")
    previous: bytes | None = None
    previous_time: datetime | None = None
    for expected_sequence, event in enumerate(events, start=1):
        if event.tenant_id != tenant_id:
            raise AuditIntegrityError("cross-tenant audit splice detected")
        if event.sequence != expected_sequence:
            raise AuditIntegrityError("audit deletion or reordering detected")
        if event.previous_digest != previous:
            raise AuditIntegrityError("audit predecessor mismatch")
        if previous_time is not None and event.occurred_at < previous_time:
            raise AuditIntegrityError("audit timestamp anomaly detected")
        expected = audit_digest(
            tenant_id=tenant_id,
            sequence=event.sequence,
            event_type=event.event_type,
            decision_id=event.decision_id,
            principal_id=event.principal_id,
            occurred_at=event.occurred_at,
            previous_digest=event.previous_digest,
            integrity_metadata=event.integrity_metadata,
        )
        if not hmac.compare_digest(event.digest, expected):
            raise AuditIntegrityError("audit digest mismatch")
        previous = event.digest
        previous_time = event.occurred_at
    if len(events) != checkpoint.sequence or previous is None:
        raise AuditIntegrityError("audit tail deletion detected")
    if not hmac.compare_digest(previous, checkpoint.digest):
        raise AuditIntegrityError("audit checkpoint mismatch")


async def verify_signed_audit_chain(
    tenant_id: UUID,
    events: Sequence[AuditEvent],
    checkpoint: AuditCheckpoint,
    signer: AuditSigner,
) -> None:
    """Verify canonical digests and every external signature in the chain."""
    verify_audit_chain(tenant_id, events, checkpoint)
    for event in events:
        if event.signing_key_id is None or event.signature is None:
            raise AuditIntegrityError("audit signature missing")
        try:
            valid = await signer.verify(event.digest, event.signature, event.signing_key_id)
        except Exception as exc:  # noqa: BLE001 - verifier failures are safe integrity failures
            raise AuditIntegrityError("audit signature verification unavailable") from exc
        if not valid:
            raise AuditIntegrityError("audit signature mismatch")


async def _upsert_principal(
    session: AsyncSession, tenant_id: UUID, principal: Principal, observed_at: datetime
) -> UUID:
    principal_id = uuid4()
    statement = (
        insert(PrincipalRecord)
        .values(
            id=principal_id,
            tenant_id=tenant_id,
            issuer=principal.issuer,
            subject=principal.subject,
            identity_kind=principal.kind.value,
            workload_id=principal.workload_id,
            last_seen_at=observed_at,
        )
        .on_conflict_do_update(
            constraint="uq_principals_tenant_subject",
            set_={"last_seen_at": observed_at, "workload_id": principal.workload_id},
        )
        .returning(PrincipalRecord.id)
    )
    value = await session.scalar(statement)
    if value is None:
        raise DurableCommitUnavailableError("principal persistence failed")
    return value


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(text("SELECT clock_timestamp()"))
    if not isinstance(value, datetime):
        raise DurableCommitUnavailableError("trusted database time unavailable")
    return value


async def _restore_response(
    session: AsyncSession, tenant_id: UUID, decision: Decision
) -> EvaluationResponse:
    matches = list(
        (
            await session.scalars(
                select(PolicyMatch)
                .where(
                    PolicyMatch.tenant_id == tenant_id,
                    PolicyMatch.decision_id == decision.id,
                )
                .order_by(PolicyMatch.rule_id)
            )
        ).all()
    )
    reasons = tuple(
        str(value["message"])
        for value in decision.reasons or ()
        if isinstance(value, dict) and "message" in value
    )
    reason_codes = tuple(
        str(value["code"])
        for value in decision.reasons or ()
        if isinstance(value, dict) and "code" in value
    )
    mappings = decision.mitre_mappings or ()
    timings = decision.pipeline_timings or {}
    evidence = decision.evidence_state or {}
    return EvaluationResponse(
        trace_id=str(decision.trace_id),
        verdict=cast(AnyVerdict, decision.verdict),
        behavioral_score=float(decision.behavioral_score),
        blast_radius=decision.blast_radius,
        reasons=reasons,
        reason_codes=reason_codes,
        mitre_attack=tuple(
            str(value["id"])
            for value in mappings
            if value.get("framework") == "MITRE ATT&CK" and "id" in value
        ),
        mitre_atlas=tuple(
            str(value["id"])
            for value in mappings
            if value.get("framework") == "MITRE ATLAS" and "id" in value
        ),
        predicted_next=str((decision.predicted_next or {}).get("action", "")),
        policy_decision=cast(AnyPolicyDecision, decision.policy_decision),
        policy_pack_version=decision.policy_pack_version,
        matched_rules=tuple(
            PolicyMatchResponse.model_validate(match.safe_metadata) for match in matches
        ),
        evidence_degraded=bool(evidence.get("degraded", False)),
        response_status="DELIVERY_PENDING",
        pipeline_timings=PipelineTimings.model_validate(timings),
        similar_decision_ids=(),
    )


def _trace_uuid(value: str) -> UUID:
    try:
        return UUID(value)
    except ValueError:
        return UUID(bytes=hashlib.sha256(value.encode()).digest()[:16])


def _integrity_metadata(
    decision: Decision,
    input_digest: bytes,
    response: EvaluationResponse,
    *,
    principal_id: UUID,
) -> dict[str, JsonValue]:
    return {
        "format": AUDIT_FORMAT,
        "input_digest": input_digest.hex(),
        "trace_id": str(decision.trace_id),
        "verdict": decision.verdict,
        "behavioral_score": str(decision.behavioral_score),
        "policy_decision": decision.policy_decision,
        "policy_pack_version": decision.policy_pack_version,
        "matched_rules": [
            {"id": match.id, "version": match.version} for match in response.matched_rules
        ],
        "evidence_degraded": response.evidence_degraded,
        "evidence_owner": str(principal_id),
        "retention_state": "ACTIVE",
        "delivery_state": "PENDING",
        "redaction": {"status": "APPLIED", "schema_version": 1},
        "trusted_time_source": "postgresql.clock_timestamp",
    }


def _canonical_bytes(value: object) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
