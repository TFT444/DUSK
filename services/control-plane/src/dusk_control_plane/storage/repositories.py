"""Tenant-bound repositories; no data access method accepts an optional tenant."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Generic, TypeVar, cast
from uuid import UUID, uuid4

from sqlalchemy import Select, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncSession

from dusk_control_plane.storage.models import (
    TENANT_SCOPED_MODELS,
    AgentRiskRollup,
    AuditEvent,
    Base,
    CanonicalAction,
    DashboardAggregate,
    Decision,
    IntegrationHealth,
    OutboxDelivery,
    PolicyMatch,
    PrincipalRecord,
    RoleAssignment,
)

ModelT = TypeVar("ModelT", bound=Base)


class IdempotencyConflictError(RuntimeError):
    """The same tenant/key pair was reused for a different canonical action."""


def _require_aware_datetime(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")


class TenantScopedRepository(Generic[ModelT]):
    """Minimal repository whose constructor makes tenant scope mandatory."""

    def __init__(self, session: AsyncSession, tenant_id: UUID, model: type[ModelT]) -> None:
        if model not in TENANT_SCOPED_MODELS:
            raise TypeError("repository model must be tenant scoped")
        self._session = session
        self.tenant_id = tenant_id
        self._model = model
        self._table = model.__table__

    async def get(self, entity_id: UUID) -> ModelT | None:
        statement = select(self._model).where(
            self._table.c.tenant_id == self.tenant_id,
            self._table.c.id == entity_id,
        )
        return cast(ModelT | None, await self._session.scalar(statement))

    async def add(self, entity: ModelT) -> ModelT:
        if getattr(entity, "tenant_id", None) != self.tenant_id:
            raise ValueError("entity tenant does not match repository tenant")
        self._session.add(entity)
        await self._session.flush()
        return entity

    async def list_by_id(self, *, limit: int = 100, after_id: UUID | None = None) -> list[ModelT]:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        statement: Select[tuple[ModelT]] = select(self._model).where(
            self._table.c.tenant_id == self.tenant_id
        )
        if after_id is not None:
            statement = statement.where(self._table.c.id > after_id)
        statement = statement.order_by(self._table.c.id).limit(limit)
        return list((await self._session.scalars(statement)).all())


@dataclass(frozen=True)
class DecisionWrite:
    action_id: UUID
    trace_id: UUID
    idempotency_key: str
    agent_id: str
    verdict: str
    behavioral_score: Decimal
    blast_radius: str
    reasons: list[dict[str, Any]]
    mitre_mappings: list[dict[str, Any]]
    predicted_next: dict[str, Any] | None
    policy_decision: str
    policy_pack_version: str
    evidence_state: dict[str, Any]
    pipeline_timings: dict[str, Any]
    response_status: str


class DecisionRepository(TenantScopedRepository[Decision]):
    def __init__(self, session: AsyncSession, tenant_id: UUID) -> None:
        super().__init__(session, tenant_id, Decision)

    async def get_by_trace_id(self, trace_id: UUID) -> Decision | None:
        return cast(
            Decision | None,
            await self._session.scalar(
                select(Decision).where(
                    Decision.tenant_id == self.tenant_id,
                    Decision.trace_id == trace_id,
                )
            ),
        )

    async def get_by_idempotency_key(self, idempotency_key: str) -> Decision | None:
        return cast(
            Decision | None,
            await self._session.scalar(
                select(Decision).where(
                    Decision.tenant_id == self.tenant_id,
                    Decision.idempotency_key == idempotency_key,
                )
            ),
        )

    async def add_idempotent(self, value: DecisionWrite) -> tuple[Decision, bool]:
        if not 1 <= len(value.idempotency_key) <= 200:
            raise ValueError("idempotency_key must contain 1 to 200 characters")
        decision_id = uuid4()
        statement = (
            insert(Decision)
            .values(
                id=decision_id,
                tenant_id=self.tenant_id,
                action_id=value.action_id,
                trace_id=value.trace_id,
                idempotency_key=value.idempotency_key,
                agent_id=value.agent_id,
                verdict=value.verdict,
                behavioral_score=value.behavioral_score,
                blast_radius=value.blast_radius,
                reasons=value.reasons,
                mitre_mappings=value.mitre_mappings,
                predicted_next=value.predicted_next,
                policy_decision=value.policy_decision,
                policy_pack_version=value.policy_pack_version,
                evidence_state=value.evidence_state,
                pipeline_timings=value.pipeline_timings,
                response_status=value.response_status,
            )
            .on_conflict_do_nothing(index_elements=[Decision.tenant_id, Decision.idempotency_key])
            .returning(Decision.id)
        )
        inserted_id = await self._session.scalar(statement)
        if inserted_id is not None:
            inserted = await self.get(inserted_id)
            if inserted is None:
                raise RuntimeError("inserted decision could not be read")
            return inserted, True
        existing = await self.get_by_idempotency_key(value.idempotency_key)
        if existing is None:
            raise RuntimeError("idempotency conflict could not be resolved")
        if existing.action_id != value.action_id:
            raise IdempotencyConflictError(
                "idempotency key was already used for a different canonical action"
            )
        return existing, False

    async def redact_detail_before(self, cutoff: datetime, deleted_at: datetime) -> int:
        _require_aware_datetime(cutoff, "cutoff")
        _require_aware_datetime(deleted_at, "deleted_at")
        result = cast(
            CursorResult[Any],
            await self._session.execute(
                update(Decision)
                .where(
                    Decision.tenant_id == self.tenant_id,
                    Decision.created_at < cutoff,
                    Decision.detail_deleted_at.is_(None),
                )
                .values(
                    reasons=None,
                    mitre_mappings=None,
                    predicted_next=None,
                    evidence_state=None,
                    pipeline_timings=None,
                    detail_deleted_at=deleted_at,
                )
            ),
        )
        return result.rowcount


class CanonicalActionRepository(TenantScopedRepository[CanonicalAction]):
    def __init__(self, session: AsyncSession, tenant_id: UUID) -> None:
        super().__init__(session, tenant_id, CanonicalAction)

    async def redact_detail_before(self, cutoff: datetime, deleted_at: datetime) -> int:
        _require_aware_datetime(cutoff, "cutoff")
        _require_aware_datetime(deleted_at, "deleted_at")
        result = cast(
            CursorResult[Any],
            await self._session.execute(
                update(CanonicalAction)
                .where(
                    CanonicalAction.tenant_id == self.tenant_id,
                    CanonicalAction.created_at < cutoff,
                    CanonicalAction.detail_deleted_at.is_(None),
                )
                .values(redacted_action=None, detail_deleted_at=deleted_at)
            ),
        )
        return result.rowcount


class RepositorySet:
    """Construct every data-access surface with one immutable tenant scope."""

    def __init__(self, session: AsyncSession, tenant_id: UUID) -> None:
        self.tenant_id = tenant_id
        self.principals = TenantScopedRepository(session, tenant_id, PrincipalRecord)
        self.roles = TenantScopedRepository(session, tenant_id, RoleAssignment)
        self.actions = CanonicalActionRepository(session, tenant_id)
        self.decisions = DecisionRepository(session, tenant_id)
        self.policy_matches = TenantScopedRepository(session, tenant_id, PolicyMatch)
        self.audit_events = TenantScopedRepository(session, tenant_id, AuditEvent)
        self.integration_health = TenantScopedRepository(session, tenant_id, IntegrationHealth)
        self.outbox = TenantScopedRepository(session, tenant_id, OutboxDelivery)
        self.agent_risk = TenantScopedRepository(session, tenant_id, AgentRiskRollup)
        self.dashboard = TenantScopedRepository(session, tenant_id, DashboardAggregate)
