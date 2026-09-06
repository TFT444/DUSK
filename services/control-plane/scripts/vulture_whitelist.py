"""Framework-discovered storage symbols that vulture cannot resolve statically.

This file is scanned, not executed. SQLAlchemy consumes declarative mapped
attributes while constructing tables, Alembic reads revision protocol globals,
and pytest reads ``pytestmark`` during collection. Repository methods and
surfaces listed here are the intentionally public data-access contract for the
subsequent ordered API, audit, outbox, and aggregate issues.
"""

from dusk_control_plane.dashboard import (
    ActionBreakdown,
    AgentDetail,
    AgentRiskItem,
    AgentRiskPage,
    AgentRiskQuery,
    DashboardSummary,
    DashboardWindowQuery,
    DecisionVolume,
    DecisionVolumePoint,
    LatencyMetric,
    MetricValue,
)
from dusk_control_plane.decisions import DecisionListQuery
from dusk_control_plane.evaluations import PipelineTimings
from dusk_control_plane.observability import SafeJsonFormatter
from dusk_control_plane.operations import PolicyPage, PolicySummary
from dusk_control_plane.outbox import OutboxWorkerConfig, SystemDnsResolver
from dusk_control_plane.policy import EvidenceTrust
from dusk_control_plane.privacy import RetentionRunResult
from dusk_control_plane.storage.models import (
    AgentRiskRollup,
    AuditEvent,
    CanonicalAction,
    DashboardAggregate,
    EvidenceReplayClaim,
    IntegrationHealth,
    OutboxDelivery,
    PolicyMatch,
    PrincipalRecord,
    RoleAssignment,
    Tenant,
)
from dusk_control_plane.storage.repositories import (
    DecisionRepository,
    RepositorySet,
    TenantScopedRepository,
)

Tenant.slug
Tenant.display_name
Tenant.decision_retention_days
Tenant.audit_retention_days
Tenant.legal_hold
Tenant.updated_at

PrincipalRecord.last_seen_at

RoleAssignment.principal_id
RoleAssignment.assigned_by_principal_id
RoleAssignment.assigned_at

CanonicalAction.input_digest
CanonicalAction.schema_version
CanonicalAction.redacted_action

PolicyMatch.rule_id
PolicyMatch.rule_version
PolicyMatch.effect
PolicyMatch.safe_metadata

AuditEvent.sequence
AuditEvent.event_type
AuditEvent.chain_format
AuditEvent.principal_id
AuditEvent.occurred_at
AuditEvent.previous_digest
AuditEvent.digest
AuditEvent.integrity_metadata
AuditEvent.sensitive_detail

IntegrationHealth.integration_key
IntegrationHealth.integration_kind
IntegrationHealth.checked_at
IntegrationHealth.latency_ms
IntegrationHealth.safe_diagnostic_code

OutboxDelivery.delivery_id
OutboxDelivery.deduplication_key
OutboxDelivery.destination_key
OutboxDelivery.destination_kind
OutboxDelivery.delivery_kind
OutboxDelivery.redacted_payload
OutboxDelivery.attempt_count
OutboxDelivery.max_attempts
OutboxDelivery.state_version
OutboxDelivery.next_attempt_at
OutboxDelivery.last_attempt_at
OutboxDelivery.lease_owner
OutboxDelivery.locked_until
OutboxDelivery.delivered_at
OutboxDelivery.last_http_status
OutboxDelivery.safe_diagnostic_code
OutboxDelivery.acknowledgement_digest
OutboxDelivery.acknowledgement_evidence
OutboxDelivery.acknowledgement_signature
OutboxDelivery.acknowledgement_outcome
OutboxDelivery.acknowledged_at
OutboxDelivery.updated_at

AgentRiskRollup.risk_score
AgentRiskRollup.decision_count
AgentRiskRollup.high_risk_count
AgentRiskRollup.last_seen_at
AgentRiskRollup.updated_at

DashboardAggregate.bucket_start
DashboardAggregate.bucket_granularity
DashboardAggregate.metric_key
DashboardAggregate.dimension_key
DashboardAggregate.dimensions
DashboardAggregate.metric_value
DashboardAggregate.computed_at

EvidenceReplayClaim.source_identity
EvidenceReplayClaim.nonce
EvidenceReplayClaim.observed_at
EvidenceReplayClaim.claimed_at

TenantScopedRepository.list_by_id
DecisionRepository.get_by_trace_id
RepositorySet.policy_matches
RepositorySet.audit_events
RepositorySet.integration_health
RepositorySet.outbox
RepositorySet.agent_risk
RepositorySet.dashboard

# Alembic and pytest load these module-level protocol values by name.
down_revision
branch_labels
depends_on
pytestmark

# FastAPI discovers these nested handlers through decorators; response fields
# and enum members are public contract values consumed by generated clients.
evaluate_action
evaluation_unavailable
evidence_rejected
policy_unavailable
invalid_decision_cursor
decision_not_found
decision_query_unavailable
list_decisions
get_decision
dashboard_summary
dashboard_decision_volume
dashboard_action_breakdown
agent_risk
agent_detail
invalid_agent_risk_cursor
agent_not_found
dashboard_query_unavailable
invalid_operations_cursor
operations_unavailable
policies
policy_summary
integration_health
service_status
DecisionListQuery.require_utc
DecisionListQuery.reject_control_characters
DecisionListQuery.validate_range
PipelineTimings.behavioral_ms
PipelineTimings.baseline_ms
PipelineTimings.sie_ms
SafeJsonFormatter.format
RetentionRunResult.audit_sequence
EvidenceTrust.CONFLICTED
OutboxWorkerConfig.from_settings
SystemDnsResolver
AgentRiskQuery
DashboardWindowQuery
MetricValue.change_percent
LatencyMetric.sample_count
DashboardSummary.window_start
DashboardSummary.window_end
DashboardSummary.comparison_start
DashboardSummary.comparison_end
DecisionVolumePoint.allow
DecisionVolume.window_start
DecisionVolume.window_end
ActionBreakdown.window_start
ActionBreakdown.window_end
AgentRiskItem.would_block_count
AgentRiskPage.window_start
AgentRiskPage.window_end
AgentDetail.window_start
AgentDetail.window_end
FailingExporter.export
PolicyPage.pack_name
PolicySummary.pack_name
PolicySummary.counts_by_status
