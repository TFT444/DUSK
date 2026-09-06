"""Tenant-qualified SQLAlchemy models for authoritative control-plane state."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint("decision_retention_days BETWEEN 1 AND 3650", name="decision_retention"),
        CheckConstraint("audit_retention_days BETWEEN 1 AND 3650", name="audit_retention"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    slug: Mapped[str] = mapped_column(String(63), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    decision_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90, server_default=text("90")
    )
    audit_retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=365, server_default=text("365")
    )
    legal_hold: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class PrincipalRecord(Base):
    __tablename__ = "principals"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "id", name="uq_principals_tenant_id_id"),
        UniqueConstraint("tenant_id", "issuer", "subject", name="uq_principals_tenant_subject"),
        CheckConstraint("identity_kind IN ('workload', 'human')", name="identity_kind"),
        CheckConstraint(
            "(identity_kind = 'workload' AND workload_id IS NOT NULL) OR "
            "(identity_kind = 'human' AND workload_id IS NULL)",
            name="workload_identity_shape",
        ),
        Index("ix_principals_tenant_kind", "tenant_id", "identity_kind"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(256), nullable=False)
    identity_kind: Mapped[str] = mapped_column(String(16), nullable=False)
    workload_id: Mapped[str | None] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RoleAssignment(Base):
    __tablename__ = "role_assignments"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        ForeignKeyConstraint(
            ["tenant_id", "principal_id"],
            ["principals.tenant_id", "principals.id"],
            name="fk_role_assignments_principal",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "assigned_by_principal_id"],
            ["principals.tenant_id", "principals.id"],
            name="fk_role_assignments_assigned_by",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_role_assignments_tenant_id_id"),
        UniqueConstraint("tenant_id", "principal_id", "role", name="uq_role_assignment"),
        CheckConstraint(
            "role IN ('viewer', 'analyst', 'operator', 'auditor', 'administrator')",
            name="role",
        ),
        Index("ix_role_assignments_tenant_role", "tenant_id", "role"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    principal_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    assigned_by_principal_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class CanonicalAction(Base):
    __tablename__ = "canonical_actions"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "id", name="uq_canonical_actions_tenant_id_id"),
        CheckConstraint("octet_length(input_digest) = 32", name="input_digest_length"),
        CheckConstraint("schema_version > 0", name="schema_version"),
        CheckConstraint(
            "redacted_action IS NOT NULL OR detail_deleted_at IS NOT NULL",
            name="retention_tombstone",
        ),
        Index("ix_canonical_actions_tenant_created", "tenant_id", "created_at", "id"),
        Index("ix_canonical_actions_tenant_digest", "tenant_id", "input_digest"),
        Index(
            "ix_canonical_actions_search_document",
            text("to_tsvector('simple'::regconfig, redacted_action::text)"),
            postgresql_using="gin",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    input_digest: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    redacted_action: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    detail_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Decision(Base):
    __tablename__ = "decisions"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        ForeignKeyConstraint(
            ["tenant_id", "action_id"],
            ["canonical_actions.tenant_id", "canonical_actions.id"],
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_decisions_tenant_id_id"),
        UniqueConstraint("tenant_id", "trace_id", name="uq_decisions_tenant_trace"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_decisions_tenant_idempotency"),
        CheckConstraint("verdict IN ('ALLOW', 'BLOCK', 'WOULD-BLOCK')", name="verdict"),
        CheckConstraint("behavioral_score BETWEEN 0 AND 1", name="behavioral_score"),
        CheckConstraint(
            "policy_decision IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL', 'NOT_APPLICABLE')",
            name="policy_decision",
        ),
        CheckConstraint(
            "response_status IN ('PENDING', 'DELIVERY_PENDING', 'DELIVERED', 'FAILED', 'EXECUTED')",
            name="response_status",
        ),
        CheckConstraint(
            "reasons IS NOT NULL OR detail_deleted_at IS NOT NULL",
            name="retention_tombstone",
        ),
        Index("ix_decisions_tenant_created", "tenant_id", "created_at", "id"),
        Index("ix_decisions_tenant_verdict_created", "tenant_id", "verdict", "created_at"),
        Index("ix_decisions_tenant_agent_created", "tenant_id", "agent_id", "created_at"),
        Index(
            "ix_decisions_tenant_policy_created",
            "tenant_id",
            "policy_decision",
            "created_at",
            "id",
        ),
        Index(
            "ix_decisions_tenant_response_created",
            "tenant_id",
            "response_status",
            "created_at",
            "id",
        ),
        Index(
            "ix_decisions_search_agent",
            text("to_tsvector('simple'::regconfig, agent_id)"),
            postgresql_using="gin",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    action_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    trace_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, default=uuid4)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(256), nullable=False)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    behavioral_score: Mapped[Decimal] = mapped_column(Numeric(6, 5), nullable=False)
    blast_radius: Mapped[str] = mapped_column(String(32), nullable=False)
    reasons: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    mitre_mappings: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    predicted_next: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    policy_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_pack_version: Mapped[str] = mapped_column(String(128), nullable=False)
    evidence_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    pipeline_timings: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    response_status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    detail_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PolicyMatch(Base):
    __tablename__ = "policy_matches"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "decision_id"],
            ["decisions.tenant_id", "decisions.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_policy_matches_tenant_id_id"),
        UniqueConstraint("tenant_id", "decision_id", "rule_id", name="uq_policy_match_rule"),
        CheckConstraint("effect IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')", name="effect"),
        Index("ix_policy_matches_tenant_decision", "tenant_id", "decision_id"),
        Index("ix_policy_matches_tenant_rule", "tenant_id", "rule_id"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    decision_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(128), nullable=False)
    effect: Mapped[str] = mapped_column(String(32), nullable=False)
    safe_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        ForeignKeyConstraint(
            ["tenant_id", "decision_id"],
            ["decisions.tenant_id", "decisions.id"],
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "principal_id"],
            ["principals.tenant_id", "principals.id"],
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_audit_events_tenant_id_id"),
        UniqueConstraint("tenant_id", "sequence", name="uq_audit_events_tenant_sequence"),
        UniqueConstraint("tenant_id", "digest", name="uq_audit_events_tenant_digest"),
        CheckConstraint("sequence > 0", name="positive_sequence"),
        CheckConstraint("octet_length(digest) = 32", name="digest_length"),
        CheckConstraint(
            "previous_digest IS NULL OR octet_length(previous_digest) = 32",
            name="previous_digest_length",
        ),
        Index("ix_audit_events_tenant_occurred", "tenant_id", "occurred_at", "id"),
        Index("ix_audit_events_tenant_type_occurred", "tenant_id", "event_type", "occurred_at"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    chain_format: Mapped[str] = mapped_column(
        String(32), nullable=False, default="dusk.audit.v1", server_default=text("'dusk.audit.v1'")
    )
    decision_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    principal_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    previous_digest: Mapped[bytes | None] = mapped_column(LargeBinary)
    digest: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signing_key_id: Mapped[str | None] = mapped_column(String(512))
    signature: Mapped[bytes | None] = mapped_column(LargeBinary)
    integrity_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    sensitive_detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    detail_deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IntegrationHealth(Base):
    __tablename__ = "integration_health"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "id", name="uq_integration_health_tenant_id_id"),
        UniqueConstraint("tenant_id", "integration_key", name="uq_integration_health_key"),
        CheckConstraint(
            "status IN ('HEALTHY', 'DEGRADED', 'UNAVAILABLE', 'UNKNOWN')", name="status"
        ),
        CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="latency"),
        Index("ix_integration_health_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    integration_key: Mapped[str] = mapped_column(String(128), nullable=False)
    integration_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    safe_diagnostic_code: Mapped[str | None] = mapped_column(String(100))


class OutboxDelivery(Base):
    __tablename__ = "outbox_deliveries"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "decision_id"],
            ["decisions.tenant_id", "decisions.id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_outbox_deliveries_tenant_id_id"),
        UniqueConstraint("tenant_id", "delivery_id", name="uq_outbox_delivery_id"),
        UniqueConstraint("tenant_id", "deduplication_key", name="uq_outbox_deduplication"),
        CheckConstraint(
            "state IN ('PENDING', 'IN_FLIGHT', 'DELIVERED', 'DEAD_LETTER')", name="state"
        ),
        CheckConstraint(
            "destination_kind IN ('WEBHOOK', 'ENFORCEMENT_BROKER')",
            name="destination_kind",
        ),
        CheckConstraint("attempt_count >= 0 AND max_attempts > 0", name="attempts"),
        CheckConstraint("state_version > 0", name="state_version"),
        CheckConstraint(
            "acknowledgement_outcome IS NULL OR "
            "acknowledgement_outcome IN ('EXECUTED', 'REJECTED')",
            name="acknowledgement_outcome",
        ),
        CheckConstraint(
            "(acknowledgement_digest IS NULL AND acknowledgement_evidence IS NULL AND "
            "acknowledgement_signature IS NULL AND acknowledgement_outcome IS NULL AND "
            "acknowledged_at IS NULL) OR "
            "(acknowledgement_digest IS NOT NULL AND acknowledgement_evidence IS NOT NULL AND "
            "acknowledgement_signature IS NOT NULL AND acknowledgement_outcome IS NOT NULL AND "
            "acknowledged_at IS NOT NULL)",
            name="acknowledgement_shape",
        ),
        Index("ix_outbox_tenant_state_next", "tenant_id", "state", "next_attempt_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    decision_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    delivery_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, default=uuid4)
    deduplication_key: Mapped[str] = mapped_column(String(200), nullable=False)
    destination_key: Mapped[str] = mapped_column(String(128), nullable=False)
    destination_kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="WEBHOOK", server_default=text("'WEBHOOK'")
    )
    delivery_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    redacted_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    state: Mapped[str] = mapped_column(
        String(16), nullable=False, default="PENDING", server_default=text("'PENDING'")
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    max_attempts: Mapped[int] = mapped_column(
        Integer, nullable=False, default=10, server_default=text("10")
    )
    state_version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1, server_default=text("1")
    )
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_owner: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_http_status: Mapped[int | None] = mapped_column(Integer)
    safe_diagnostic_code: Mapped[str | None] = mapped_column(String(100))
    acknowledgement_digest: Mapped[bytes | None] = mapped_column(LargeBinary)
    acknowledgement_evidence: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    acknowledgement_signature: Mapped[bytes | None] = mapped_column(LargeBinary)
    acknowledgement_outcome: Mapped[str | None] = mapped_column(String(16))
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class AgentRiskRollup(Base):
    __tablename__ = "agent_risk_rollups"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "id", name="uq_agent_risk_rollups_tenant_id_id"),
        UniqueConstraint("tenant_id", "agent_id", name="uq_agent_risk_rollup"),
        CheckConstraint("risk_score BETWEEN 0 AND 1", name="risk_score"),
        CheckConstraint("decision_count >= 0 AND high_risk_count >= 0", name="counts"),
        Index("ix_agent_risk_tenant_score", "tenant_id", "risk_score", "agent_id"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(256), nullable=False)
    risk_score: Mapped[Decimal] = mapped_column(Numeric(6, 5), nullable=False)
    decision_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    high_risk_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class DashboardAggregate(Base):
    __tablename__ = "dashboard_aggregates"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "id", name="uq_dashboard_aggregates_tenant_id_id"),
        UniqueConstraint(
            "tenant_id",
            "bucket_start",
            "bucket_granularity",
            "metric_key",
            "dimension_key",
            name="uq_dashboard_aggregate_bucket",
        ),
        CheckConstraint("bucket_granularity IN ('hour', 'day')", name="bucket_granularity"),
        Index(
            "ix_dashboard_aggregates_tenant_metric_bucket",
            "tenant_id",
            "metric_key",
            "bucket_start",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    bucket_granularity: Mapped[str] = mapped_column(String(8), nullable=False)
    metric_key: Mapped[str] = mapped_column(String(100), nullable=False)
    dimension_key: Mapped[str] = mapped_column(
        String(256), nullable=False, default="", server_default=text("''")
    )
    dimensions: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    metric_value: Mapped[Decimal] = mapped_column(Numeric(20, 6), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class EvidenceReplayClaim(Base):
    """Minimal durable nonce claim for cryptographically signed provider evidence."""

    __tablename__ = "evidence_replay_claims"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "id", name="uq_evidence_replay_claims_tenant_id_id"),
        UniqueConstraint(
            "tenant_id",
            "source_identity",
            "nonce",
            name="uq_evidence_replay_claim",
        ),
        Index("ix_evidence_replay_claims_tenant_observed", "tenant_id", "observed_at", "id"),
    )

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tenant_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    source_identity: Mapped[str] = mapped_column(String(200), nullable=False)
    nonce: Mapped[str] = mapped_column(String(200), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claimed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


TENANT_SCOPED_MODELS = (
    PrincipalRecord,
    RoleAssignment,
    CanonicalAction,
    Decision,
    PolicyMatch,
    AuditEvent,
    IntegrationHealth,
    OutboxDelivery,
    AgentRiskRollup,
    DashboardAggregate,
    EvidenceReplayClaim,
)
