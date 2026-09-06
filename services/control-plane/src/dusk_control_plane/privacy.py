"""Tenant-safe retention cleanup and bounded compliance export services."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Literal, cast
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import and_, exists, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from dusk_control_plane.audit import AUDIT_FORMAT, AuditSigner, audit_digest, redact_for_storage
from dusk_control_plane.identity import (
    AuthorizationDeniedError,
    Capability,
    IdentityKind,
    Principal,
)
from dusk_control_plane.storage.database import Database
from dusk_control_plane.storage.models import (
    AuditEvent,
    CanonicalAction,
    Decision,
    PrincipalRecord,
    Tenant,
)

RETENTION_EVENT_TYPE = "privacy.retention_applied"
POLICY_EVENT_TYPE = "privacy.retention_policy_updated"
DEFAULT_DECISION_RETENTION_DAYS = 90
DEFAULT_AUDIT_RETENTION_DAYS = 365
MAX_RETENTION_BATCH_SIZE = 500
MAX_EXPORT_PAGE_SIZE = 100
MAX_EXPORT_BYTES = 8 * 1024 * 1024


class PrivacyUnavailableError(RuntimeError):
    """The privacy operation could not complete safely."""


class PrivacyModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RetentionRunResult(PrivacyModel):
    tenant_id: UUID
    mode: Literal["DRY_RUN", "APPLY"]
    status: Literal["LEGAL_HOLD", "COMPLETE", "MORE_AVAILABLE"]
    as_of: datetime
    decision_cutoff: datetime
    audit_cutoff: datetime
    decision_details: int = Field(ge=0)
    canonical_actions: int = Field(ge=0)
    audit_sensitive_details: int = Field(ge=0)
    evidence_event_id: UUID | None = None
    evidence_sequence: int | None = Field(default=None, gt=0)


class RetentionPolicy(PrivacyModel):
    decision_retention_days: int = Field(ge=1, le=3650)
    audit_retention_days: int = Field(ge=1, le=3650)
    legal_hold: bool


class RetentionPolicyResult(RetentionPolicy):
    tenant_id: UUID
    updated_at: datetime
    evidence_event_id: UUID | None = None
    evidence_sequence: int | None = Field(default=None, gt=0)


class ExportPosition(PrivacyModel):
    created_at: datetime
    decision_id: UUID

    @model_validator(mode="after")
    def require_utc(self) -> ExportPosition:
        offset = self.created_at.utcoffset()
        if self.created_at.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("export position must use UTC")
        return self


class ExportDecision(PrivacyModel):
    trace_id: UUID
    created_at: datetime
    agent_id: str
    verdict: str
    behavioral_score: float
    blast_radius: str
    policy_decision: str
    policy_pack_version: str
    response_status: str
    input_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    action: dict[str, object] | None
    reasons: tuple[dict[str, object], ...] | None
    mitre_mappings: tuple[dict[str, object], ...] | None
    predicted_next: dict[str, object] | None
    evidence_state: dict[str, object] | None
    pipeline_timings: dict[str, object] | None
    detail_deleted_at: datetime | None
    audit_sequence: int = Field(gt=0)
    audit_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ExportPage(PrivacyModel):
    generated_at: datetime
    items: tuple[ExportDecision, ...]
    next_position: ExportPosition | None
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class RetentionPolicyService:
    """Update the claim-derived tenant policy and append signed change evidence."""

    def __init__(self, database: Database, signer: AuditSigner) -> None:
        self._database = database
        self._signer = signer

    async def configure(
        self, principal: Principal, policy: RetentionPolicy
    ) -> RetentionPolicyResult:
        tenant_id = _administrator_tenant(principal)
        try:
            async with self._database.transaction() as session:
                tenant = await session.scalar(
                    select(Tenant).where(Tenant.id == tenant_id).with_for_update()
                )
                if tenant is None:
                    raise PrivacyUnavailableError("tenant is not provisioned")
                updated_at = await _database_now(session)
                before = {
                    "decision_retention_days": tenant.decision_retention_days,
                    "audit_retention_days": tenant.audit_retention_days,
                    "legal_hold": tenant.legal_hold,
                }
                after = policy.model_dump(mode="json")
                if before == after:
                    return RetentionPolicyResult(
                        tenant_id=tenant_id,
                        updated_at=updated_at,
                        **after,
                    )
                principal_id = await _upsert_human_principal(
                    session, tenant_id, principal, updated_at
                )
                tenant.decision_retention_days = policy.decision_retention_days
                tenant.audit_retention_days = policy.audit_retention_days
                tenant.legal_hold = policy.legal_hold
                tenant.updated_at = updated_at
                event_id, sequence = await _append_signed_event(
                    session,
                    tenant_id=tenant_id,
                    signer=self._signer,
                    event_type=POLICY_EVENT_TYPE,
                    principal_id=principal_id,
                    metadata={
                        "format": AUDIT_FORMAT,
                        "operation_id": str(uuid4()),
                        "before": before,
                        "after": after,
                        "trusted_time_source": "postgresql.clock_timestamp",
                    },
                )
                return RetentionPolicyResult(
                    tenant_id=tenant_id,
                    updated_at=updated_at,
                    evidence_event_id=event_id,
                    evidence_sequence=sequence,
                    **after,
                )
        except PrivacyUnavailableError:
            raise
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise PrivacyUnavailableError("retention policy transaction unavailable") from exc


class RetentionService:
    """Apply one transactionally bounded retention batch for a single tenant."""

    def __init__(
        self, database: Database, signer: AuditSigner, *, default_batch_size: int = 100
    ) -> None:
        if not 1 <= default_batch_size <= MAX_RETENTION_BATCH_SIZE:
            raise ValueError(f"default_batch_size must be between 1 and {MAX_RETENTION_BATCH_SIZE}")
        self._database = database
        self._signer = signer
        self._default_batch_size = default_batch_size

    async def run_once(  # noqa: C901
        self, principal: Principal, *, dry_run: bool = True, batch_size: int | None = None
    ) -> RetentionRunResult:
        tenant_id = _administrator_tenant(principal)
        batch_size = self._default_batch_size if batch_size is None else batch_size
        if not 1 <= batch_size <= MAX_RETENTION_BATCH_SIZE:
            raise ValueError(f"batch_size must be between 1 and {MAX_RETENTION_BATCH_SIZE}")
        try:
            async with self._database.transaction() as session:
                tenant = await session.scalar(
                    select(Tenant).where(Tenant.id == tenant_id).with_for_update()
                )
                if tenant is None:
                    raise PrivacyUnavailableError("tenant is not provisioned")
                as_of = await _database_now(session)
                decision_cutoff = as_of - timedelta(days=tenant.decision_retention_days)
                audit_cutoff = as_of - timedelta(days=tenant.audit_retention_days)
                if tenant.legal_hold:
                    return _retention_result(
                        tenant_id,
                        dry_run,
                        "LEGAL_HOLD",
                        as_of,
                        decision_cutoff,
                        audit_cutoff,
                    )

                decision_candidates = list(
                    (
                        await session.execute(
                            select(Decision.id, Decision.action_id)
                            .where(
                                Decision.tenant_id == tenant_id,
                                Decision.created_at < decision_cutoff,
                                Decision.detail_deleted_at.is_(None),
                            )
                            .order_by(Decision.created_at, Decision.id)
                            .limit(batch_size + 1)
                            .with_for_update()
                        )
                    ).all()
                )
                selected_decisions = decision_candidates[:batch_size]
                remaining = batch_size - len(selected_decisions)
                audit_candidates: list[UUID] = []
                if remaining:
                    audit_candidates = list(
                        (
                            await session.scalars(
                                select(AuditEvent.id)
                                .where(
                                    AuditEvent.tenant_id == tenant_id,
                                    AuditEvent.occurred_at < audit_cutoff,
                                    AuditEvent.sensitive_detail.is_not(None),
                                    AuditEvent.detail_deleted_at.is_(None),
                                )
                                .order_by(AuditEvent.occurred_at, AuditEvent.id)
                                .limit(remaining + 1)
                                .with_for_update()
                            )
                        ).all()
                    )
                selected_audits = audit_candidates[:remaining]
                more = len(decision_candidates) > batch_size or len(audit_candidates) > remaining
                if remaining == 0 and not more:
                    more = bool(
                        await session.scalar(
                            select(
                                exists().where(
                                    AuditEvent.tenant_id == tenant_id,
                                    AuditEvent.occurred_at < audit_cutoff,
                                    AuditEvent.sensitive_detail.is_not(None),
                                    AuditEvent.detail_deleted_at.is_(None),
                                )
                            )
                        )
                    )

                if dry_run:
                    return _retention_result(
                        tenant_id,
                        True,
                        "MORE_AVAILABLE" if more else "COMPLETE",
                        as_of,
                        decision_cutoff,
                        audit_cutoff,
                        decision_details=len(selected_decisions),
                        audit_sensitive_details=len(selected_audits),
                    )

                decision_ids = [row.id for row in selected_decisions]
                action_ids = [row.action_id for row in selected_decisions]
                if decision_ids:
                    await session.execute(
                        update(Decision)
                        .where(Decision.tenant_id == tenant_id, Decision.id.in_(decision_ids))
                        .values(
                            reasons=None,
                            mitre_mappings=None,
                            predicted_next=None,
                            evidence_state=None,
                            pipeline_timings=None,
                            detail_deleted_at=as_of,
                        )
                    )
                action_count = await _tombstone_unreferenced_actions(
                    session, tenant_id, action_ids, as_of
                )
                if selected_audits:
                    await session.execute(
                        update(AuditEvent)
                        .where(
                            AuditEvent.tenant_id == tenant_id,
                            AuditEvent.id.in_(selected_audits),
                        )
                        .values(sensitive_detail=None, detail_deleted_at=as_of)
                    )

                event_id: UUID | None = None
                evidence_sequence: int | None = None
                if decision_ids or selected_audits or action_count:
                    event_id, evidence_sequence = await self._append_evidence(
                        session,
                        tenant=tenant,
                        as_of=as_of,
                        decision_cutoff=decision_cutoff,
                        audit_cutoff=audit_cutoff,
                        decision_count=len(decision_ids),
                        action_count=action_count,
                        audit_count=len(selected_audits),
                        more=more,
                    )
                return _retention_result(
                    tenant_id,
                    False,
                    "MORE_AVAILABLE" if more else "COMPLETE",
                    as_of,
                    decision_cutoff,
                    audit_cutoff,
                    decision_details=len(decision_ids),
                    canonical_actions=action_count,
                    audit_sensitive_details=len(selected_audits),
                    evidence_event_id=event_id,
                    evidence_sequence=evidence_sequence,
                )
        except PrivacyUnavailableError:
            raise
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise PrivacyUnavailableError("retention transaction unavailable") from exc

    async def _append_evidence(
        self,
        session: AsyncSession,
        *,
        tenant: Tenant,
        as_of: datetime,
        decision_cutoff: datetime,
        audit_cutoff: datetime,
        decision_count: int,
        action_count: int,
        audit_count: int,
        more: bool,
    ) -> tuple[UUID, int]:
        metadata = {
            "format": AUDIT_FORMAT,
            "operation_id": str(uuid4()),
            "applied_at": as_of.isoformat(),
            "decision_cutoff": decision_cutoff.isoformat(),
            "audit_cutoff": audit_cutoff.isoformat(),
            "decision_retention_days": tenant.decision_retention_days,
            "audit_retention_days": tenant.audit_retention_days,
            "deleted": {
                "decision_details": decision_count,
                "canonical_actions": action_count,
                "audit_sensitive_details": audit_count,
            },
            "continuation_required": more,
            "legal_hold": False,
            "trusted_time_source": "postgresql.clock_timestamp",
        }
        return await _append_signed_event(
            session,
            tenant_id=tenant.id,
            signer=self._signer,
            event_type=RETENTION_EVENT_TYPE,
            principal_id=None,
            metadata=metadata,
        )


class PrivacyExportService:
    """Return an administrator-authorized, bounded, already-redacted tenant export page."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def export_page(
        self,
        principal: Principal,
        *,
        limit: int = 100,
        position: ExportPosition | None = None,
    ) -> ExportPage:
        tenant_id = _administrator_tenant(principal)
        if not 1 <= limit <= MAX_EXPORT_PAGE_SIZE:
            raise ValueError(f"limit must be between 1 and {MAX_EXPORT_PAGE_SIZE}")
        try:
            async with self._database.transaction() as session:
                generated_at = await _database_now(session)
                statement = (
                    select(Decision, CanonicalAction, AuditEvent)
                    .join(
                        CanonicalAction,
                        and_(
                            CanonicalAction.tenant_id == Decision.tenant_id,
                            CanonicalAction.id == Decision.action_id,
                        ),
                    )
                    .join(
                        AuditEvent,
                        and_(
                            AuditEvent.tenant_id == Decision.tenant_id,
                            AuditEvent.decision_id == Decision.id,
                            AuditEvent.event_type == "evaluation.decided",
                        ),
                    )
                    .where(Decision.tenant_id == tenant_id, Decision.created_at <= generated_at)
                )
                if position is not None:
                    statement = statement.where(
                        or_(
                            Decision.created_at < position.created_at,
                            and_(
                                Decision.created_at == position.created_at,
                                Decision.id < position.decision_id,
                            ),
                        )
                    )
                rows = list(
                    (
                        await session.execute(
                            statement.order_by(
                                Decision.created_at.desc(), Decision.id.desc()
                            ).limit(limit + 1)
                        )
                    ).all()
                )
                visible = rows[:limit]
                items = tuple(_export_item(*row) for row in visible)
                next_position = None
                if len(rows) > limit and visible:
                    last = visible[-1][0]
                    next_position = ExportPosition(
                        created_at=last.created_at.astimezone(UTC), decision_id=last.id
                    )
                payload = [item.model_dump(mode="json") for item in items]
                canonical_payload = _canonical_bytes(payload)
                if len(canonical_payload) > MAX_EXPORT_BYTES:
                    raise PrivacyUnavailableError("privacy export exceeds the page size limit")
                manifest = hashlib.sha256(canonical_payload).hexdigest()
                return ExportPage(
                    generated_at=generated_at,
                    items=items,
                    next_position=next_position,
                    manifest_digest=f"sha256:{manifest}",
                )
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise PrivacyUnavailableError("privacy export unavailable") from exc


async def _append_signed_event(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    signer: AuditSigner,
    event_type: str,
    principal_id: UUID | None,
    metadata: dict[str, object],
) -> tuple[UUID, int]:
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
    occurred_at = await _database_now(session)
    if previous is not None and occurred_at < previous.occurred_at:
        raise PrivacyUnavailableError("trusted database clock moved backwards")
    sequence = 1 if previous is None else previous.sequence + 1
    digest = audit_digest(
        tenant_id=tenant_id,
        sequence=sequence,
        event_type=event_type,
        decision_id=None,
        principal_id=principal_id,
        occurred_at=occurred_at,
        previous_digest=None if previous is None else previous.digest,
        integrity_metadata=metadata,
    )
    try:
        signature = await signer.sign(digest)
    except Exception as exc:  # noqa: BLE001 - signer diagnostics cannot cross this boundary
        raise PrivacyUnavailableError("privacy evidence signing unavailable") from exc
    if not signature or len(signature) > 8192 or not signer.key_id:
        raise PrivacyUnavailableError("privacy signer returned invalid evidence")
    event_id = uuid4()
    session.add(
        AuditEvent(
            id=event_id,
            tenant_id=tenant_id,
            sequence=sequence,
            event_type=event_type,
            decision_id=None,
            principal_id=principal_id,
            occurred_at=occurred_at,
            previous_digest=None if previous is None else previous.digest,
            digest=digest,
            signing_key_id=signer.key_id,
            signature=signature,
            integrity_metadata=metadata,
            sensitive_detail=None,
        )
    )
    await session.flush()
    return event_id, sequence


async def _upsert_human_principal(
    session: AsyncSession,
    tenant_id: UUID,
    principal: Principal,
    observed_at: datetime,
) -> UUID:
    principal_id = uuid4()
    value = await session.scalar(
        insert(PrincipalRecord)
        .values(
            id=principal_id,
            tenant_id=tenant_id,
            issuer=principal.issuer,
            subject=principal.subject,
            identity_kind=IdentityKind.HUMAN.value,
            workload_id=None,
            last_seen_at=observed_at,
        )
        .on_conflict_do_update(
            constraint="uq_principals_tenant_subject",
            set_={"last_seen_at": observed_at},
        )
        .returning(PrincipalRecord.id)
    )
    if value is None:
        raise PrivacyUnavailableError("administrative principal persistence failed")
    return value


async def _tombstone_unreferenced_actions(
    session: AsyncSession, tenant_id: UUID, action_ids: list[UUID], deleted_at: datetime
) -> int:
    if not action_ids:
        return 0
    live_decision = Decision.__table__.alias("live_decision")
    eligible = select(CanonicalAction.id).where(
        CanonicalAction.tenant_id == tenant_id,
        CanonicalAction.id.in_(action_ids),
        CanonicalAction.detail_deleted_at.is_(None),
        ~exists(
            select(live_decision.c.id).where(
                live_decision.c.tenant_id == tenant_id,
                live_decision.c.action_id == CanonicalAction.id,
                live_decision.c.detail_deleted_at.is_(None),
            )
        ),
    )
    ids = list((await session.scalars(eligible)).all())
    if ids:
        await session.execute(
            update(CanonicalAction)
            .where(CanonicalAction.tenant_id == tenant_id, CanonicalAction.id.in_(ids))
            .values(redacted_action=None, detail_deleted_at=deleted_at)
        )
    return len(ids)


def _retention_result(
    tenant_id: UUID,
    dry_run: bool,
    status: Literal["LEGAL_HOLD", "COMPLETE", "MORE_AVAILABLE"],
    as_of: datetime,
    decision_cutoff: datetime,
    audit_cutoff: datetime,
    *,
    decision_details: int = 0,
    canonical_actions: int = 0,
    audit_sensitive_details: int = 0,
    evidence_event_id: UUID | None = None,
    evidence_sequence: int | None = None,
) -> RetentionRunResult:
    return RetentionRunResult(
        tenant_id=tenant_id,
        mode="DRY_RUN" if dry_run else "APPLY",
        status=status,
        as_of=as_of,
        decision_cutoff=decision_cutoff,
        audit_cutoff=audit_cutoff,
        decision_details=decision_details,
        canonical_actions=canonical_actions,
        audit_sensitive_details=audit_sensitive_details,
        evidence_event_id=evidence_event_id,
        evidence_sequence=evidence_sequence,
    )


def _export_item(decision: Decision, action: CanonicalAction, audit: AuditEvent) -> ExportDecision:
    safe_action = redact_for_storage(action.redacted_action) if action.redacted_action else None
    return ExportDecision(
        trace_id=decision.trace_id,
        created_at=decision.created_at,
        agent_id=decision.agent_id,
        verdict=decision.verdict,
        behavioral_score=float(decision.behavioral_score),
        blast_radius=decision.blast_radius,
        policy_decision=decision.policy_decision,
        policy_pack_version=decision.policy_pack_version,
        response_status=decision.response_status,
        input_digest=f"sha256:{action.input_digest.hex()}",
        action=cast(dict[str, object] | None, safe_action),
        reasons=cast(tuple[dict[str, object], ...] | None, _safe_tuple(decision.reasons)),
        mitre_mappings=cast(
            tuple[dict[str, object], ...] | None, _safe_tuple(decision.mitre_mappings)
        ),
        predicted_next=_safe_object(decision.predicted_next),
        evidence_state=_safe_object(decision.evidence_state),
        pipeline_timings=_safe_object(decision.pipeline_timings),
        detail_deleted_at=decision.detail_deleted_at or action.detail_deleted_at,
        audit_sequence=audit.sequence,
        audit_digest=audit.digest.hex(),
    )


def _safe_tuple(value: object) -> tuple[object, ...] | None:
    safe = redact_for_storage(value) if value is not None else None
    return tuple(safe) if isinstance(safe, list) else None


def _safe_object(value: object) -> dict[str, object] | None:
    safe = redact_for_storage(value) if value is not None else None
    return cast(dict[str, object], safe) if isinstance(safe, dict) else None


def _administrator_tenant(principal: Principal) -> UUID:
    if principal.kind is not IdentityKind.HUMAN or not principal.has_capability(
        Capability.TENANT_ADMINISTER
    ):
        raise AuthorizationDeniedError
    try:
        return UUID(principal.tenant_id)
    except ValueError as exc:
        raise PrivacyUnavailableError("identity tenant is not a storage UUID") from exc


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(func.clock_timestamp())
    if not isinstance(value, datetime):
        raise PrivacyUnavailableError("trusted database time unavailable")
    return value.astimezone(UTC)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
