"""Explicit dependency-injection and readiness interfaces."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta

from dusk.policies import PolicyPack

from dusk_control_plane.audit import (
    AuditSigner,
    DurableEvaluationService,
    PostgresDecisionEvidenceStore,
    ProviderBrokerIntentResolver,
)
from dusk_control_plane.config import Settings
from dusk_control_plane.dashboard import (
    AgentRiskCursorCodec,
    DashboardReader,
    PostgresDashboardReader,
)
from dusk_control_plane.decisions import DecisionCursorCodec, DecisionReader, PostgresDecisionReader
from dusk_control_plane.evaluations import (
    INSTRUMENTED_EVALUATION_STAGES,
    EvaluationService,
    PolicyEvaluationService,
)
from dusk_control_plane.identity import Authenticator, OidcAuthenticator
from dusk_control_plane.observability import TelemetryRuntime, build_telemetry
from dusk_control_plane.operations import (
    OperationsCursorCodec,
    OperationsReader,
    PostgresOperationsReader,
)
from dusk_control_plane.outbox import OutboxWorker
from dusk_control_plane.privacy import (
    PrivacyExportService,
    RetentionPolicyService,
    RetentionService,
)
from dusk_control_plane.storage.database import Database

ProbeCheck = Callable[[], Awaitable[None]]


@dataclass(frozen=True)
class DependencyProbe:
    """A bounded readiness check with a public, non-sensitive component name."""

    name: str
    critical: bool
    check: ProbeCheck

    def __post_init__(self) -> None:
        if not self.name or len(self.name) > 64:
            raise ValueError("dependency probe name must contain 1 to 64 characters")


@dataclass(frozen=True)
class AppContainer:
    """Application dependencies supplied to the FastAPI factory."""

    settings: Settings
    readiness_probes: tuple[DependencyProbe, ...] = ()
    authenticator: Authenticator | None = None
    database: Database | None = None
    evaluation_service: EvaluationService | None = None
    audit_signer: AuditSigner | None = None
    outbox_worker: OutboxWorker | None = None
    decision_reader: DecisionReader | None = None
    dashboard_reader: DashboardReader | None = None
    operations_reader: OperationsReader | None = None
    telemetry_runtime: TelemetryRuntime | None = None
    retention_service: RetentionService | None = None
    retention_policy_service: RetentionPolicyService | None = None
    privacy_export_service: PrivacyExportService | None = None

    @classmethod
    def build(  # noqa: C901
        cls,
        settings: Settings | None = None,
        readiness_probes: Sequence[DependencyProbe] = (),
        authenticator: Authenticator | None = None,
        database: Database | None = None,
        evaluation_service: EvaluationService | None = None,
        audit_signer: AuditSigner | None = None,
        outbox_worker: OutboxWorker | None = None,
        decision_reader: DecisionReader | None = None,
        dashboard_reader: DashboardReader | None = None,
        operations_reader: OperationsReader | None = None,
        policy_pack: PolicyPack | None = None,
        telemetry_runtime: TelemetryRuntime | None = None,
        retention_service: RetentionService | None = None,
        retention_policy_service: RetentionPolicyService | None = None,
        privacy_export_service: PrivacyExportService | None = None,
    ) -> AppContainer:
        resolved_settings = settings if settings is not None else Settings()
        resolved_telemetry = (
            telemetry_runtime
            if telemetry_runtime is not None
            else build_telemetry(resolved_settings)
        )
        resolved_database = (
            database
            if database is not None
            else Database.from_settings(resolved_settings)
            if resolved_settings.storage_enabled
            else None
        )
        resolved_probes = list(readiness_probes)
        if resolved_database is not None and not any(
            probe.name == "postgresql" for probe in resolved_probes
        ):
            resolved_probes.append(
                DependencyProbe(name="postgresql", critical=True, check=resolved_database.probe)
            )
        instrumented_evaluation_service = (
            evaluation_service.with_telemetry(resolved_telemetry.telemetry)
            if isinstance(evaluation_service, PolicyEvaluationService)
            else evaluation_service
        )
        durable_evaluation_service: EvaluationService | None = None
        if isinstance(instrumented_evaluation_service, DurableEvaluationService):
            durable_evaluation_service = instrumented_evaluation_service
        elif (
            instrumented_evaluation_service is not None
            and resolved_database is not None
            and audit_signer is not None
        ):
            durable_evaluation_service = DurableEvaluationService(
                instrumented_evaluation_service,
                PostgresDecisionEvidenceStore(
                    resolved_database, audit_signer, telemetry=resolved_telemetry.telemetry
                ),
                telemetry=resolved_telemetry.telemetry,
                intent_resolver=(
                    ProviderBrokerIntentResolver(
                        resolved_settings.enforcement_broker_destination_key
                    )
                    if resolved_settings.enforcement_broker_enabled
                    else None
                ),
            )
        if resolved_settings.outbox_worker_enabled and outbox_worker is None:
            raise ValueError("outbox_worker_enabled requires an injected outbox worker")
        resolved_outbox_worker = (
            outbox_worker.with_telemetry(resolved_telemetry.telemetry)
            if outbox_worker is not None
            else None
        )
        resolved_retention_service = retention_service
        resolved_retention_policy_service = retention_policy_service
        resolved_privacy_export_service = privacy_export_service
        if resolved_settings.privacy_lifecycle_enabled:
            if resolved_database is None or audit_signer is None:
                raise ValueError(
                    "privacy_lifecycle_enabled requires database and audit signer dependencies"
                )
            if resolved_retention_service is None:
                resolved_retention_service = RetentionService(
                    resolved_database,
                    audit_signer,
                    default_batch_size=resolved_settings.retention_batch_size,
                )
            if resolved_retention_policy_service is None:
                resolved_retention_policy_service = RetentionPolicyService(
                    resolved_database, audit_signer
                )
            if resolved_privacy_export_service is None:
                resolved_privacy_export_service = PrivacyExportService(resolved_database)
        resolved_decision_reader = decision_reader
        if resolved_settings.decision_read_api_enabled and resolved_decision_reader is None:
            if resolved_database is None or resolved_settings.decision_cursor_signing_key is None:
                raise ValueError("decision_read_api_enabled requires decision query dependencies")
            resolved_decision_reader = PostgresDecisionReader(
                resolved_database,
                DecisionCursorCodec(
                    resolved_settings.decision_cursor_signing_key.get_secret_value().encode()
                ),
            )
        resolved_dashboard_reader = dashboard_reader
        if resolved_settings.dashboard_read_api_enabled and resolved_dashboard_reader is None:
            if resolved_database is None or resolved_settings.decision_cursor_signing_key is None:
                raise ValueError("dashboard_read_api_enabled requires dashboard query dependencies")
            resolved_dashboard_reader = PostgresDashboardReader(
                resolved_database,
                AgentRiskCursorCodec(
                    resolved_settings.decision_cursor_signing_key.get_secret_value().encode()
                ),
            )
        resolved_operations_reader = operations_reader
        if resolved_settings.operations_read_api_enabled and resolved_operations_reader is None:
            if (
                resolved_database is None
                or resolved_settings.decision_cursor_signing_key is None
                or policy_pack is None
            ):
                raise ValueError(
                    "operations_read_api_enabled requires operational query dependencies"
                )
            resolved_operations_reader = PostgresOperationsReader(
                resolved_database,
                policy_pack,
                OperationsCursorCodec(
                    resolved_settings.decision_cursor_signing_key.get_secret_value().encode()
                ),
                stale_after=timedelta(
                    seconds=resolved_settings.integration_health_stale_after_seconds
                ),
                outbox_instrumented=resolved_settings.outbox_worker_enabled,
                instrumented_pipeline_stages=_instrumented_stages(
                    evaluation_service=evaluation_service,
                    durable_service=durable_evaluation_service,
                    outbox_worker=resolved_outbox_worker,
                ),
            )
        return cls(
            settings=resolved_settings,
            readiness_probes=tuple(resolved_probes),
            authenticator=(
                authenticator
                if authenticator is not None
                else OidcAuthenticator.from_settings(resolved_settings)
                if resolved_settings.v2_enabled
                else None
            ),
            database=resolved_database,
            evaluation_service=durable_evaluation_service,
            audit_signer=audit_signer,
            outbox_worker=resolved_outbox_worker,
            decision_reader=resolved_decision_reader,
            dashboard_reader=resolved_dashboard_reader,
            operations_reader=resolved_operations_reader,
            telemetry_runtime=resolved_telemetry,
            retention_service=resolved_retention_service,
            retention_policy_service=resolved_retention_policy_service,
            privacy_export_service=resolved_privacy_export_service,
        )


def _instrumented_stages(
    *,
    evaluation_service: EvaluationService | None,
    durable_service: EvaluationService | None,
    outbox_worker: OutboxWorker | None,
) -> tuple[str, ...]:
    stages: list[str] = ["response"]
    if isinstance(evaluation_service, PolicyEvaluationService):
        stages[0:0] = INSTRUMENTED_EVALUATION_STAGES
    if isinstance(durable_service, DurableEvaluationService) and not isinstance(
        evaluation_service, DurableEvaluationService
    ):
        insertion = len(stages) - 1
        stages[insertion:insertion] = ["persistence", "audit"]
    if outbox_worker is not None:
        stages.extend(("outbox", "broker_acknowledgement"))
    return tuple(stages)
