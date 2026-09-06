"""Real PostgreSQL migration, isolation, idempotency, and retention tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import time
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from dusk.policies import load_enterprise_pack
from opentelemetry import metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from dusk_control_plane.audit import (
    AuditCheckpoint,
    DurableCommitUnavailableError,
    DurableDecision,
    OutboxIntent,
    PostgresDecisionEvidenceStore,
    audit_digest,
    verify_audit_chain,
    verify_signed_audit_chain,
)
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dashboard import (
    AgentNotFoundError,
    AgentRiskCursorCodec,
    AgentRiskQuery,
    DashboardWindowQuery,
    PostgresDashboardReader,
)
from dusk_control_plane.decisions import (
    DecisionCursorCodec,
    DecisionListQuery,
    DecisionNotFoundError,
    InvalidDecisionCursorError,
    PostgresDecisionReader,
)
from dusk_control_plane.dependencies import AppContainer
from dusk_control_plane.evaluations import (
    CanonicalAction as EvaluationAction,
)
from dusk_control_plane.evaluations import (
    EvaluationRequest,
    EvaluationResponse,
    EvidenceEnvelope,
    PipelineTimings,
)
from dusk_control_plane.identity import IdentityKind, Principal, Role
from dusk_control_plane.migration import (
    _MIGRATION_LOCK_ID,
    MigrationLockUnavailableError,
    migrate,
)
from dusk_control_plane.observability import Telemetry
from dusk_control_plane.operations import (
    IntegrationHealthQuery,
    OperationsCursorCodec,
    PostgresOperationsReader,
)
from dusk_control_plane.outbox import (
    DeliveryDestination,
    DeliveryError,
    DestinationKind,
    OutboxWorker,
    OutboxWorkerConfig,
    StaticDestinationRegistry,
    TransportResponse,
)
from dusk_control_plane.privacy import (
    PrivacyExportService,
    PrivacyUnavailableError,
    RetentionPolicy,
    RetentionPolicyService,
    RetentionService,
)
from dusk_control_plane.provider_evidence import PostgresReplayStore
from dusk_control_plane.storage.database import Database
from dusk_control_plane.storage.models import (
    AuditEvent,
    CanonicalAction,
    Decision,
    IntegrationHealth,
    OutboxDelivery,
    PolicyMatch,
    PrincipalRecord,
    Tenant,
)
from dusk_control_plane.storage.repositories import (
    DecisionWrite,
    IdempotencyConflictError,
    RepositorySet,
)

DATABASE_URL = os.environ.get("DUSK_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    DATABASE_URL is None,
    reason="DUSK_TEST_DATABASE_URL is required for real PostgreSQL tests",
)


def _alembic_config() -> Config:
    return Config(str(Path(__file__).parents[2] / "alembic.ini"))


def test_deployment_migration_lock_prevents_concurrent_upgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert DATABASE_URL is not None
    monkeypatch.setenv("DUSK_CP_DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("DUSK_CP_ALEMBIC_CONFIG", str(Path(__file__).parents[2] / "alembic.ini"))

    async def exercise_lock() -> None:
        engine = create_async_engine(DATABASE_URL)
        async with engine.connect() as connection:
            assert await connection.scalar(
                text("SELECT pg_try_advisory_lock(:lock_id)"),
                {"lock_id": _MIGRATION_LOCK_ID},
            )
            with pytest.raises(MigrationLockUnavailableError):
                await migrate()
            await connection.execute(
                text("SELECT pg_advisory_unlock(:lock_id)"),
                {"lock_id": _MIGRATION_LOCK_ID},
            )
        await engine.dispose()

    asyncio.run(exercise_lock())


@pytest.fixture(scope="module", autouse=True)
def migrated_database() -> Iterator[None]:
    assert DATABASE_URL is not None
    previous = os.environ.get("DUSK_CP_DATABASE_URL")
    os.environ["DUSK_CP_DATABASE_URL"] = DATABASE_URL
    config = _alembic_config()
    command.downgrade(config, "base")
    command.upgrade(config, "head")
    command.check(config)
    try:
        yield
    finally:
        command.downgrade(config, "base")
        if previous is None:
            os.environ.pop("DUSK_CP_DATABASE_URL", None)
        else:
            os.environ["DUSK_CP_DATABASE_URL"] = previous


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    assert DATABASE_URL is not None
    value = create_async_engine(DATABASE_URL)
    try:
        yield value
    finally:
        await value.dispose()


def _decision(action_id: UUID, trace_id: UUID, key: str) -> DecisionWrite:
    return DecisionWrite(
        action_id=action_id,
        trace_id=trace_id,
        idempotency_key=key,
        agent_id="integration-agent",
        verdict="ALLOW",
        behavioral_score=Decimal("0.12500"),
        blast_radius="LOW",
        reasons=[{"code": "BASELINE_NORMAL"}],
        mitre_mappings=[],
        predicted_next=None,
        policy_decision="NOT_APPLICABLE",
        policy_pack_version="none",
        evidence_state={"degraded": False},
        pipeline_timings={"normalization_ms": 1},
        response_status="PENDING",
    )


def test_migration_upgrade_is_retryable_and_matches_current_metadata() -> None:
    config = _alembic_config()
    command.upgrade(config, "head")
    command.check(config)


def test_deployment_migration_applies_timeouts_to_alembic_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert DATABASE_URL is not None
    monkeypatch.setenv("DUSK_CP_DATABASE_URL", DATABASE_URL)
    monkeypatch.setenv("DUSK_CP_ALEMBIC_CONFIG", str(Path(__file__).parents[2] / "alembic.ini"))
    monkeypatch.setenv("DUSK_CP_MIGRATION_LOCK_TIMEOUT_MS", "1000")
    monkeypatch.setenv("DUSK_CP_MIGRATION_STATEMENT_TIMEOUT_MS", "30000")
    asyncio.run(migrate())


def test_latest_migration_supports_mixed_version_rollback_and_retry() -> None:
    config = _alembic_config()
    assert DATABASE_URL is not None

    async def table_names() -> set[str]:
        inspection_engine = create_async_engine(DATABASE_URL)
        try:
            async with inspection_engine.connect() as connection:
                return set(
                    await connection.run_sync(
                        lambda sync_connection: inspect(sync_connection).get_table_names()
                    )
                )
        finally:
            await inspection_engine.dispose()

    try:
        command.downgrade(config, "20260902_0004")
        tables = asyncio.run(table_names())
        assert "evidence_replay_claims" not in tables
        assert {"tenants", "decisions", "audit_events", "outbox_deliveries"} <= tables

        command.upgrade(config, "head")
        command.downgrade(config, "20260902_0004")
        command.upgrade(config, "head")
        command.check(config)
        assert "evidence_replay_claims" in asyncio.run(table_names())
    finally:
        command.upgrade(config, "head")


@pytest.mark.anyio
async def test_postgresql_ddl_rolls_back_after_interruption(engine: AsyncEngine) -> None:
    async with engine.connect() as connection:
        transaction = await connection.begin()
        await connection.execute(text("CREATE TABLE migration_interruption_probe (id integer)"))
        await transaction.rollback()
        tables = await connection.run_sync(
            lambda sync_connection: inspect(sync_connection).get_table_names()
        )
    assert "migration_interruption_probe" not in tables


@pytest.mark.anyio
async def test_provider_evidence_nonce_claim_is_atomic_and_tenant_scoped(
    engine: AsyncEngine,
) -> None:
    tenant_a, tenant_b = uuid4(), uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_a, slug=f"tenant-{tenant_a.hex}", display_name="Tenant A"),
                Tenant(id=tenant_b, slug=f"tenant-{tenant_b.hex}", display_name="Tenant B"),
            )
        )
    store = PostgresReplayStore(
        Database(engine, async_sessionmaker(engine, expire_on_commit=False))
    )

    first, duplicate = await asyncio.gather(
        store.claim(
            tenant_id=str(tenant_a),
            source_identity="aws-collector",
            nonce="cloudtrail-event-1",
            observed_at=datetime.now(UTC),
        ),
        store.claim(
            tenant_id=str(tenant_a),
            source_identity="aws-collector",
            nonce="cloudtrail-event-1",
            observed_at=datetime.now(UTC),
        ),
    )
    other_tenant = await store.claim(
        tenant_id=str(tenant_b),
        source_identity="aws-collector",
        nonce="cloudtrail-event-1",
        observed_at=datetime.now(UTC),
    )

    assert sorted((first, duplicate)) == [False, True]
    assert other_tenant is True


@pytest.mark.anyio
async def test_database_runtime_is_bounded_utc_and_readiness_checked() -> None:
    assert DATABASE_URL is not None
    settings = Settings(
        environment=Environment.TEST,
        storage_enabled=True,
        database_url=DATABASE_URL,
        database_statement_timeout_ms=4321,
    )
    database = Database.from_settings(settings)
    container = AppContainer.build(settings=settings, database=database)
    try:
        assert [(probe.name, probe.critical) for probe in container.readiness_probes] == [
            ("postgresql", True)
        ]
        await database.probe()
        async with database.engine.connect() as connection:
            timezone = await connection.scalar(text("SHOW timezone"))
            statement_timeout = await connection.scalar(text("SHOW statement_timeout"))
        assert timezone == "UTC"
        assert statement_timeout == "4321ms"
    finally:
        await database.close()


@pytest.mark.anyio
async def test_tenant_isolation_and_idempotency_are_database_enforced(
    engine: AsyncEngine,
) -> None:
    tenant_a, tenant_b = uuid4(), uuid4()
    action_a, action_a_conflict, action_b = uuid4(), uuid4(), uuid4()
    shared_key = "retry-key"

    async with AsyncSession(engine, expire_on_commit=False) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_a, slug=f"tenant-{tenant_a.hex}", display_name="Tenant A"),
                Tenant(id=tenant_b, slug=f"tenant-{tenant_b.hex}", display_name="Tenant B"),
            )
        )
        await session.flush()
        session.add_all(
            (
                CanonicalAction(
                    id=action_a,
                    tenant_id=tenant_a,
                    input_digest=b"a" * 32,
                    redacted_action={"operation": "read"},
                ),
                CanonicalAction(
                    id=action_b,
                    tenant_id=tenant_b,
                    input_digest=b"b" * 32,
                    redacted_action={"operation": "read"},
                ),
                CanonicalAction(
                    id=action_a_conflict,
                    tenant_id=tenant_a,
                    input_digest=b"e" * 32,
                    redacted_action={"operation": "write"},
                ),
            )
        )
        await session.flush()
        repositories_a = RepositorySet(session, tenant_a)
        repositories_b = RepositorySet(session, tenant_b)

        first, inserted = await repositories_a.decisions.add_idempotent(
            _decision(action_a, uuid4(), shared_key)
        )
        replay, replay_inserted = await repositories_a.decisions.add_idempotent(
            _decision(action_a, uuid4(), shared_key)
        )
        other_tenant, other_inserted = await repositories_b.decisions.add_idempotent(
            _decision(action_b, uuid4(), shared_key)
        )

        assert inserted is True
        assert replay_inserted is False
        assert replay.id == first.id
        assert other_inserted is True
        assert other_tenant.id != first.id
        assert await repositories_b.decisions.get(first.id) is None
        assert first.created_at.utcoffset() == timedelta(0)
        with pytest.raises(IdempotencyConflictError):
            await repositories_a.decisions.add_idempotent(
                _decision(action_a_conflict, uuid4(), shared_key)
            )


@pytest.mark.anyio
async def test_cross_tenant_foreign_key_is_rejected(engine: AsyncEngine) -> None:
    tenant_a, tenant_b, action_id = uuid4(), uuid4(), uuid4()
    async with AsyncSession(engine, expire_on_commit=False) as session:
        async with session.begin():
            session.add_all(
                (
                    Tenant(id=tenant_a, slug=f"tenant-{tenant_a.hex}", display_name="Tenant A"),
                    Tenant(id=tenant_b, slug=f"tenant-{tenant_b.hex}", display_name="Tenant B"),
                )
            )
            await session.flush()
            session.add(
                CanonicalAction(
                    id=action_id,
                    tenant_id=tenant_a,
                    input_digest=b"c" * 32,
                    redacted_action={"operation": "read"},
                )
            )
        with pytest.raises(IntegrityError):
            async with session.begin():
                session.add(
                    Decision(
                        tenant_id=tenant_b,
                        action_id=action_id,
                        trace_id=uuid4(),
                        idempotency_key="foreign-action",
                        agent_id="integration-agent",
                        verdict="BLOCK",
                        behavioral_score=Decimal("1.00000"),
                        blast_radius="HIGH",
                        reasons=[{"code": "TENANT_MISMATCH"}],
                        mitre_mappings=[],
                        policy_decision="DENY",
                        policy_pack_version="test",
                        evidence_state={},
                        pipeline_timings={},
                        response_status="PENDING",
                    )
                )


@pytest.mark.anyio
async def test_retention_redacts_detail_but_preserves_decision_identity(
    engine: AsyncEngine,
) -> None:
    tenant_id, action_id = uuid4(), uuid4()
    old = datetime.now(UTC) - timedelta(days=91)
    deleted_at = datetime.now(UTC)
    async with AsyncSession(engine, expire_on_commit=False) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
        await session.flush()
        session.add(
            CanonicalAction(
                id=action_id,
                tenant_id=tenant_id,
                input_digest=b"d" * 32,
                redacted_action={"credential": "[REDACTED]"},
                created_at=old,
            )
        )
        await session.flush()
        repository = RepositorySet(session, tenant_id)
        decision, _ = await repository.decisions.add_idempotent(
            _decision(action_id, uuid4(), "retention-key")
        )
        decision.created_at = old
        await session.flush()

        assert await repository.actions.redact_detail_before(deleted_at, deleted_at) == 1
        assert await repository.decisions.redact_detail_before(deleted_at, deleted_at) == 1
        await session.flush()
        stored = await session.scalar(select(Decision).where(Decision.id == decision.id))
        assert stored is not None
        assert stored.reasons is None
        assert stored.detail_deleted_at == deleted_at


@pytest.mark.anyio
async def test_tenant_leading_indexes_exist_in_postgresql(engine: AsyncEngine) -> None:
    async with engine.connect() as connection:
        indexes = await connection.run_sync(
            lambda sync_connection: {
                table: inspect(sync_connection).get_indexes(table)
                for table in (
                    "decisions",
                    "audit_events",
                    "outbox_deliveries",
                    "dashboard_aggregates",
                )
            }
        )
    for table_indexes in indexes.values():
        assert any(index["column_names"][0] == "tenant_id" for index in table_indexes)


def _evaluation_request(key: str) -> EvaluationRequest:
    return EvaluationRequest(
        action=EvaluationAction(
            agent_id="integration-agent",
            action_type="storage.delete",
            target="bucket-a",
            consequential=True,
            attributes={"credential": "must-not-persist"},
        ),
        evidence=(
            EvidenceEnvelope(
                domain="action",
                source_identity="cloud-audit",
                provenance="signed-event",
                observed_at=datetime.now(UTC),
                digest="sha256:" + "0" * 64,
                payload={"token": "unrestricted-provider-token"},
                tenant_id="tenant-a",
                key_id="test-key",
                nonce="test-nonce-00000001",
                signature="a" * 86,
            ),
        ),
        idempotency_key=key,
    )


def _evaluation_response() -> EvaluationResponse:
    return EvaluationResponse(
        trace_id=str(uuid4()),
        verdict="BLOCK",
        behavioral_score=Decimal("0.90000"),
        blast_radius="HIGH",
        reasons=("destructive action",),
        reason_codes=("POLICY_DENY",),
        mitre_attack=("T1485",),
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


class _TestSigner:
    key_id = "integration-test-key"

    async def sign(self, digest: bytes) -> bytes:
        return hmac.new(b"integration-test-only", digest, hashlib.sha256).digest()

    async def verify(self, digest: bytes, signature: bytes, key_id: str) -> bool:
        return key_id == self.key_id and hmac.compare_digest(await self.sign(digest), signature)


def _store(
    engine: AsyncEngine,
    signer: _TestSigner | None = None,
    telemetry: Telemetry | None = None,
) -> PostgresDecisionEvidenceStore:
    database = Database(engine, async_sessionmaker(engine, expire_on_commit=False))
    return PostgresDecisionEvidenceStore(database, signer or _TestSigner(), telemetry=telemetry)


@pytest.mark.anyio
async def test_atomic_decision_audit_and_outbox_commit_is_redacted_and_verifiable(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
    principal = Principal(
        "https://issuer.example",
        "subject",
        str(tenant_id),
        IdentityKind.WORKLOAD,
        workload_id="integration-agent",
    )
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    telemetry = Telemetry(
        tracer=tracer_provider.get_tracer("integration"), meter=metrics.get_meter("integration")
    )
    result = await _store(engine, telemetry=telemetry).persist(
        request=_evaluation_request("atomic-success"),
        response=_evaluation_response(),
        principal=principal,
    )
    async with AsyncSession(engine) as session:
        decision = await session.scalar(select(Decision).where(Decision.id == result.decision_id))
        action = await session.scalar(
            select(CanonicalAction).where(CanonicalAction.id == decision.action_id)
        )
        events = list(
            (
                await session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.tenant_id == tenant_id)
                    .order_by(AuditEvent.sequence)
                )
            ).all()
        )
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == result.decision_id)
        )
    assert decision is not None and action is not None and delivery is not None
    assert events[0].id == result.audit_event_id
    verify_audit_chain(tenant_id, events, result.checkpoint)
    await verify_signed_audit_chain(tenant_id, events, result.checkpoint, _TestSigner())
    persisted = repr(
        (action.redacted_action, decision.reasons, events[0].__dict__, delivery.redacted_payload)
    )
    assert "must-not-persist" not in persisted
    assert "unrestricted-provider-token" not in persisted
    assert action.redacted_action["attributes"]["credential"] == "[REDACTED]"
    assert decision.pipeline_timings["persistence_ms"] >= 0
    assert decision.pipeline_timings["audit_ms"] >= 0
    assert result.response.pipeline_timings.persistence_ms is not None
    assert result.response.pipeline_timings.audit_ms == result.audit_ms
    audit_span = next(
        span for span in span_exporter.get_finished_spans() if span.name.endswith("audit")
    )
    assert audit_span.attributes["dusk.decision.id"] == str(result.decision_id)
    assert audit_span.attributes["dusk.audit.event_id"] == str(result.audit_event_id)
    assert audit_span.attributes["dusk.outbox.delivery_id"] == str(result.delivery_id)


@pytest.mark.anyio
async def test_failure_at_outbox_boundary_rolls_back_decision_and_audit(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
    principal = Principal(
        "issuer", "subject", str(tenant_id), IdentityKind.WORKLOAD, workload_id="agent-a"
    )
    with pytest.raises(DurableCommitUnavailableError):
        await _store(engine).persist(
            request=_evaluation_request("atomic-rollback"),
            response=_evaluation_response(),
            principal=principal,
            intent=OutboxIntent(max_attempts=0),
        )
    async with AsyncSession(engine) as session:
        assert await session.scalar(select(Decision).where(Decision.tenant_id == tenant_id)) is None
        assert (
            await session.scalar(select(AuditEvent).where(AuditEvent.tenant_id == tenant_id))
            is None
        )
        assert (
            await session.scalar(
                select(OutboxDelivery).where(OutboxDelivery.tenant_id == tenant_id)
            )
            is None
        )


@pytest.mark.anyio
async def test_database_connection_loss_rolls_back_and_normal_retry_recovers(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    victim = await engine.connect()
    transaction = await victim.begin()
    backend_pid = await victim.scalar(text("SELECT pg_backend_pid()"))
    await victim.execute(
        text(
            "INSERT INTO tenants (id, slug, display_name) VALUES (:id, :slug, 'Interrupted tenant')"
        ),
        {"id": tenant_id, "slug": f"interrupted-{tenant_id.hex}"},
    )
    async with engine.connect() as terminator:
        assert (
            await terminator.scalar(
                text("SELECT pg_terminate_backend(:backend_pid)"),
                {"backend_pid": backend_pid},
            )
            is True
        )
        await terminator.commit()
    with pytest.raises(DBAPIError):
        await victim.execute(text("SELECT 1"))
    try:
        await transaction.rollback()
    except DBAPIError:
        pass
    await victim.invalidate()
    await victim.close()

    async with AsyncSession(engine) as session:
        assert await session.get(Tenant, tenant_id) is None
    async with AsyncSession(engine) as session, session.begin():
        session.add(
            Tenant(id=tenant_id, slug=f"recovered-{tenant_id.hex}", display_name="Recovered")
        )
    principal = Principal(
        "issuer", "subject", str(tenant_id), IdentityKind.WORKLOAD, workload_id="agent-a"
    )
    recovered = await _store(engine).persist(
        request=_evaluation_request("database-recovery"),
        response=_evaluation_response(),
        principal=principal,
    )
    assert recovered.inserted is True


@pytest.mark.anyio
async def test_concurrent_sequence_allocation_and_restart_recovery(engine: AsyncEngine) -> None:
    import asyncio

    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
    principal = Principal(
        "issuer", "subject", str(tenant_id), IdentityKind.WORKLOAD, workload_id="agent-a"
    )

    async def write(index: int):
        # A new store instance models independent workers and process restarts.
        return await _store(engine).persist(
            request=_evaluation_request(f"concurrent-{index}"),
            response=_evaluation_response(),
            principal=principal,
        )

    results = await asyncio.gather(*(write(index) for index in range(8)))
    async with AsyncSession(engine) as session:
        events = list(
            (
                await session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.tenant_id == tenant_id)
                    .order_by(AuditEvent.sequence)
                )
            ).all()
        )
    checkpoint = max((result.checkpoint for result in results), key=lambda value: value.sequence)
    assert [event.sequence for event in events] == list(range(1, 9))
    verify_audit_chain(tenant_id, events, checkpoint)


@pytest.mark.anyio
async def test_idempotent_retry_returns_original_durable_decision(engine: AsyncEngine) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
    principal = Principal(
        "issuer", "subject", str(tenant_id), IdentityKind.WORKLOAD, workload_id="agent-a"
    )
    request = _evaluation_request("idempotent-bundle")
    store = _store(engine)
    first_response = _evaluation_response()
    first = await store.persist(request=request, response=first_response, principal=principal)
    changed = first_response.model_copy(
        update={"trace_id": str(uuid4()), "verdict": "ALLOW", "policy_decision": "ALLOW"}
    )
    replay = await store.persist(request=request, response=changed, principal=principal)
    assert replay.inserted is False
    assert replay.decision_id == first.decision_id
    assert replay.response.trace_id == first.response.trace_id
    assert replay.response.verdict == "BLOCK"
    async with AsyncSession(engine) as session:
        for model in (Decision, AuditEvent, OutboxDelivery):
            count = len(
                list(
                    (await session.scalars(select(model).where(model.tenant_id == tenant_id))).all()
                )
            )
            assert count == 1


@pytest.mark.anyio
async def test_high_concurrency_duplicate_submission_commits_one_complete_bundle(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
    principal = Principal(
        "issuer", "subject", str(tenant_id), IdentityKind.WORKLOAD, workload_id="agent-a"
    )
    request = _evaluation_request("concurrent-idempotency")

    async def retry() -> DurableDecision:
        return await _store(engine).persist(
            request=request,
            response=_evaluation_response(),
            principal=principal,
        )

    results = await asyncio.gather(*(retry() for _ in range(20)))
    decision_ids = {result.decision_id for result in results}
    trace_ids = {result.response.trace_id for result in results}
    assert len(decision_ids) == len(trace_ids) == 1
    assert sum(result.inserted for result in results) == 1
    async with AsyncSession(engine) as session:
        for model in (CanonicalAction, Decision, AuditEvent, OutboxDelivery):
            rows = list(
                (await session.scalars(select(model).where(model.tenant_id == tenant_id))).all()
            )
            assert len(rows) == 1
        principal_rows = list(
            (
                await session.scalars(
                    select(PrincipalRecord).where(PrincipalRecord.tenant_id == tenant_id)
                )
            ).all()
        )
        assert len(principal_rows) == 1


@pytest.mark.anyio
async def test_idempotency_lock_does_not_block_another_tenant(engine: AsyncEngine) -> None:
    tenant_a, tenant_b = uuid4(), uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_a, slug=f"tenant-{tenant_a.hex}", display_name="Tenant A"),
                Tenant(id=tenant_b, slug=f"tenant-{tenant_b.hex}", display_name="Tenant B"),
            )
        )
    lock_connection = await engine.connect()
    lock_transaction = await lock_connection.begin()
    shared_key = "tenant-qualified-lock"
    await lock_connection.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:lock_key, 211))"),
        {"lock_key": f"{tenant_a}:{shared_key}"},
    )
    try:
        principal_b = Principal(
            "issuer", "subject-b", str(tenant_b), IdentityKind.WORKLOAD, workload_id="agent-b"
        )
        result = await asyncio.wait_for(
            _store(engine).persist(
                request=_evaluation_request(shared_key),
                response=_evaluation_response(),
                principal=principal_b,
            ),
            timeout=2,
        )
        assert result.inserted is True
        assert result.checkpoint.tenant_id == tenant_b
    finally:
        await lock_transaction.rollback()
        await lock_connection.close()


class _FailingSigner(_TestSigner):
    async def sign(self, digest: bytes) -> bytes:
        raise TimeoutError("managed signing service unavailable")


class _StalledSigner(_TestSigner):
    async def sign(self, digest: bytes) -> bytes:
        await asyncio.Event().wait()
        return await super().sign(digest)


@pytest.mark.anyio
async def test_signer_failure_rolls_back_every_evidence_record(engine: AsyncEngine) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
    principal = Principal(
        "issuer", "subject", str(tenant_id), IdentityKind.WORKLOAD, workload_id="agent-a"
    )
    with pytest.raises(DurableCommitUnavailableError):
        await _store(engine, _FailingSigner()).persist(
            request=_evaluation_request("signer-rollback"),
            response=_evaluation_response(),
            principal=principal,
        )
    async with AsyncSession(engine) as session:
        for model in (CanonicalAction, Decision, AuditEvent, OutboxDelivery):
            assert await session.scalar(select(model).where(model.tenant_id == tenant_id)) is None


@pytest.mark.anyio
async def test_cancelled_audit_signing_rolls_back_and_idempotent_retry_recovers(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
    principal = Principal(
        "issuer", "subject", str(tenant_id), IdentityKind.WORKLOAD, workload_id="agent-a"
    )
    request = _evaluation_request("cancelled-audit-signing")
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            _store(engine, _StalledSigner()).persist(
                request=request,
                response=_evaluation_response(),
                principal=principal,
            ),
            timeout=0.1,
        )
    async with AsyncSession(engine) as session:
        for model in (CanonicalAction, Decision, AuditEvent, OutboxDelivery):
            assert await session.scalar(select(model).where(model.tenant_id == tenant_id)) is None

    recovered = await _store(engine).persist(
        request=request,
        response=_evaluation_response(),
        principal=principal,
    )
    assert recovered.inserted is True


class _PublicResolver:
    async def resolve(self, hostname: str, port: int):
        return ("8.8.8.8",)


class _PrivateResolver:
    async def resolve(self, hostname: str, port: int):
        return ("169.254.169.254",)


class _Credentials:
    async def headers_for(self, destination_key: str):
        return {"Authorization": "Bearer test-only"}


class _AckVerifier:
    def __init__(self, valid: bool = True) -> None:
        self.valid = valid
        self.calls = 0

    async def verify(self, acknowledgement, payload: bytes) -> bool:
        self.calls += 1
        return self.valid and acknowledgement.signature == b"test-signature"


class _RecordingTransport:
    def __init__(self, responses=None) -> None:
        self.responses = list(responses or [TransportResponse(204, {})])
        self.claims = []
        self.active = 0
        self.max_active = 0

    async def send(self, claim, destination, credential_headers):
        import asyncio

        self.claims.append(claim)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0)
            value = self.responses[min(len(self.claims) - 1, len(self.responses) - 1)]
            if callable(value):
                value = value(claim)
            if isinstance(value, Exception):
                raise value
            return value
        finally:
            self.active -= 1


def _worker_config(*, batch_size: int = 20, concurrency: int = 4) -> OutboxWorkerConfig:
    return OutboxWorkerConfig(
        batch_size=batch_size,
        max_concurrency=concurrency,
        poll_interval_seconds=0.1,
        lease_seconds=10,
        connect_timeout_seconds=1,
        response_timeout_seconds=1,
        retry_base_seconds=1,
        retry_max_seconds=8,
        acknowledgement_max_age_seconds=300,
    )


def _worker(
    engine: AsyncEngine,
    transport,
    *,
    kind: DestinationKind = DestinationKind.WEBHOOK,
    verifier=None,
    batch_size: int = 20,
    concurrency: int = 4,
    now: datetime | None = None,
    resolver=None,
    telemetry: Telemetry | None = None,
) -> OutboxWorker:
    database = Database(engine, async_sessionmaker(engine, expire_on_commit=False))
    return OutboxWorker(
        database=database,
        destinations=StaticDestinationRegistry(
            [
                DeliveryDestination(
                    "decision-events", kind, "https://delivery.example.test/v1/events"
                )
            ]
        ),
        resolver=resolver or _PublicResolver(),
        credentials=_Credentials(),
        transport=transport,
        acknowledgement_verifier=verifier or _AckVerifier(),
        config=_worker_config(batch_size=batch_size, concurrency=concurrency),
        random=lambda: 0,
        clock=(lambda: now) if now is not None else lambda: datetime.now(UTC),
        telemetry=telemetry,
    )


async def _persist_outbox_fixture(engine: AsyncEngine, key: str, *, max_attempts: int = 10):
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"tenant-{tenant_id.hex}", display_name="Tenant"))
    principal = Principal(
        "issuer", "subject", str(tenant_id), IdentityKind.WORKLOAD, workload_id="agent-a"
    )
    durable = await _store(engine).persist(
        request=_evaluation_request(key),
        response=_evaluation_response(),
        principal=principal,
        intent=OutboxIntent(max_attempts=max_attempts),
    )
    return tenant_id, durable


async def _isolate_worker_queue(engine: AsyncEngine) -> None:
    """Complete records created by earlier module tests before a worker scenario."""
    async with AsyncSession(engine) as session, session.begin():
        rows = list(
            (
                await session.scalars(
                    select(OutboxDelivery).where(OutboxDelivery.state.in_(("PENDING", "IN_FLIGHT")))
                )
            ).all()
        )
        for row in rows:
            row.state = "DELIVERED"
            row.delivered_at = datetime.now(UTC)
            row.lease_owner = None
            row.locked_until = None


@pytest.mark.anyio
async def test_webhook_delivery_is_bounded_and_never_claims_execution(engine: AsyncEngine) -> None:
    await _isolate_worker_queue(engine)
    tenant_id, durable = await _persist_outbox_fixture(engine, "webhook-delivery")
    transport = _RecordingTransport()
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    telemetry = Telemetry(
        tracer=tracer_provider.get_tracer("outbox"), meter=metrics.get_meter("outbox")
    )
    stats = await _worker(engine, transport, concurrency=1, telemetry=telemetry).run_once()
    assert stats.claimed == stats.delivered == 1
    assert transport.max_active == 1
    async with AsyncSession(engine) as session:
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
        decision = await session.scalar(select(Decision).where(Decision.id == durable.decision_id))
    assert delivery is not None and decision is not None
    assert delivery.tenant_id == tenant_id
    assert delivery.state == "DELIVERED"
    assert delivery.attempt_count == 1
    assert delivery.delivered_at is not None
    assert decision.response_status == "DELIVERED"
    assert decision.response_status != "EXECUTED"
    delivery_span = next(
        span for span in span_exporter.get_finished_spans() if span.name.endswith("outbox")
    )
    assert delivery_span.attributes["dusk.decision.id"] == str(durable.decision_id)
    assert delivery_span.attributes["dusk.outbox.delivery_id"] == str(durable.delivery_id)


@pytest.mark.anyio
async def test_crash_style_retry_reuses_stable_delivery_id(engine: AsyncEngine) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _persist_outbox_fixture(engine, "at-least-once")
    transport = _RecordingTransport(
        [DeliveryError("TRANSPORT_UNAVAILABLE"), TransportResponse(204, {})]
    )
    first = await _worker(engine, transport).run_once()
    assert first.retried == 1
    async with AsyncSession(engine) as session, session.begin():
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
        assert delivery is not None
        delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    second = await _worker(engine, transport).run_once()
    assert second.delivered == 1
    assert len(transport.claims) == 2
    assert transport.claims[0].delivery_id == transport.claims[1].delivery_id


@pytest.mark.anyio
async def test_retry_limit_moves_delivery_to_dead_letter_with_safe_code(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _persist_outbox_fixture(engine, "dead-letter", max_attempts=2)
    transport = _RecordingTransport([TimeoutError("token=must-not-leak")])
    assert (await _worker(engine, transport).run_once()).retried == 1
    async with AsyncSession(engine) as session, session.begin():
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
        assert delivery is not None
        delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
    assert (await _worker(engine, transport).run_once()).dead_lettered == 1
    async with AsyncSession(engine) as session:
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
        decision = await session.scalar(select(Decision).where(Decision.id == durable.decision_id))
    assert delivery is not None and decision is not None
    assert delivery.state == "DEAD_LETTER"
    assert delivery.safe_diagnostic_code == "DELIVERY_UNAVAILABLE"
    assert "must-not-leak" not in repr(delivery.__dict__)
    assert decision.response_status == "FAILED"


@pytest.mark.anyio
async def test_batch_saturation_and_concurrency_are_strictly_bounded(engine: AsyncEngine) -> None:
    await _isolate_worker_queue(engine)
    for index in range(5):
        await _persist_outbox_fixture(engine, f"saturation-{index}")
    transport = _RecordingTransport()
    stats = await _worker(engine, transport, batch_size=2, concurrency=1).run_once()
    assert stats.claimed == 2
    assert transport.max_active == 1
    async with AsyncSession(engine) as session:
        pending = list(
            (
                await session.scalars(
                    select(OutboxDelivery).where(OutboxDelivery.state == "PENDING")
                )
            ).all()
        )
    assert len(pending) >= 3


def _ack_response(
    claim, *, tenant_id=None, outcome="EXECUTED", issued_at: datetime | None = None
) -> TransportResponse:
    issued_at = issued_at or datetime.now(UTC)
    return TransportResponse(
        200,
        {
            "dusk-ack-version": "dusk.broker-ack.v1",
            "dusk-ack-tenant-id": str(tenant_id or claim.tenant_id),
            "dusk-ack-decision-id": str(claim.decision_id),
            "dusk-ack-delivery-id": str(claim.delivery_id),
            "dusk-ack-outcome": outcome,
            "dusk-ack-issued-at": issued_at.isoformat(),
            "dusk-ack-nonce": "nonce-1",
            "dusk-ack-key-id": "broker-key-1",
            "dusk-ack-signature": base64.urlsafe_b64encode(b"test-signature").decode(),
        },
    )


async def _make_broker_delivery(engine: AsyncEngine, key: str):
    tenant_id, durable = await _persist_outbox_fixture(engine, key)
    async with AsyncSession(engine) as session, session.begin():
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
        assert delivery is not None
        delivery.destination_kind = "ENFORCEMENT_BROKER"
        delivery.delivery_kind = "ACTION_EXECUTION"
    return tenant_id, durable


@pytest.mark.anyio
async def test_only_bound_verified_broker_acknowledgement_sets_executed(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _make_broker_delivery(engine, "trusted-ack")
    verifier = _AckVerifier()
    transport = _RecordingTransport([_ack_response])
    span_exporter = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    telemetry = Telemetry(
        tracer=tracer_provider.get_tracer("broker"), meter=metrics.get_meter("broker")
    )
    result = await _worker(
        engine,
        transport,
        kind=DestinationKind.ENFORCEMENT_BROKER,
        verifier=verifier,
        telemetry=telemetry,
    ).run_once()
    assert result.delivered == 1
    assert verifier.calls == 1
    async with AsyncSession(engine) as session:
        decision = await session.scalar(select(Decision).where(Decision.id == durable.decision_id))
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
    assert decision is not None and delivery is not None
    assert decision.response_status == "EXECUTED"
    assert delivery.acknowledgement_outcome == "EXECUTED"
    assert delivery.acknowledgement_digest is not None
    assert delivery.acknowledgement_signature == b"test-signature"
    assert delivery.acknowledgement_evidence["delivery_id"] == str(delivery.delivery_id)
    spans = {span.name: span for span in span_exporter.get_finished_spans()}
    acknowledgement_span = spans["dusk.pipeline.broker_acknowledgement"]
    outbox_span = spans["dusk.pipeline.outbox"]
    assert acknowledgement_span.parent is not None
    assert acknowledgement_span.parent.span_id == outbox_span.context.span_id
    assert acknowledgement_span.attributes["dusk.outbox.delivery_id"] == str(durable.delivery_id)


@pytest.mark.anyio
async def test_broker_acknowledgement_freshness_uses_postgresql_not_worker_clock(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _make_broker_delivery(engine, "trusted-database-clock")
    skewed_worker_time = datetime.now(UTC) + timedelta(days=365)
    result = await _worker(
        engine,
        _RecordingTransport([_ack_response]),
        kind=DestinationKind.ENFORCEMENT_BROKER,
        now=skewed_worker_time,
    ).run_once()
    assert result.delivered == 1
    async with AsyncSession(engine) as session:
        decision = await session.scalar(select(Decision).where(Decision.id == durable.decision_id))
    assert decision is not None
    assert decision.response_status == "EXECUTED"


@pytest.mark.anyio
async def test_stale_broker_acknowledgement_fails_closed_against_postgresql_clock(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _make_broker_delivery(engine, "stale-database-clock")
    stale_time = datetime.now(UTC) - timedelta(seconds=301)
    result = await _worker(
        engine,
        _RecordingTransport([lambda claim: _ack_response(claim, issued_at=stale_time)]),
        kind=DestinationKind.ENFORCEMENT_BROKER,
        now=datetime.now(UTC) - timedelta(days=365),
    ).run_once()
    assert result.retried == 1
    async with AsyncSession(engine) as session:
        decision = await session.scalar(select(Decision).where(Decision.id == durable.decision_id))
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
    assert decision is not None and delivery is not None
    assert decision.response_status == "DELIVERY_PENDING"
    assert delivery.safe_diagnostic_code == "ACKNOWLEDGEMENT_STALE"
    assert delivery.acknowledgement_digest is None


@pytest.mark.anyio
async def test_trusted_broker_rejection_records_failed_not_executed(engine: AsyncEngine) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _make_broker_delivery(engine, "trusted-rejection")
    result = await _worker(
        engine,
        _RecordingTransport([lambda claim: _ack_response(claim, outcome="REJECTED")]),
        kind=DestinationKind.ENFORCEMENT_BROKER,
    ).run_once()
    assert result.delivered == 1
    async with AsyncSession(engine) as session:
        decision = await session.scalar(select(Decision).where(Decision.id == durable.decision_id))
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
    assert decision is not None and delivery is not None
    assert decision.response_status == "FAILED"
    assert delivery.acknowledgement_outcome == "REJECTED"


@pytest.mark.anyio
async def test_forged_or_mismatched_acknowledgement_never_sets_executed(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    tenant_id, durable = await _make_broker_delivery(engine, "forged-ack")
    forged = _RecordingTransport([lambda claim: _ack_response(claim, tenant_id=uuid4())])
    result = await _worker(engine, forged, kind=DestinationKind.ENFORCEMENT_BROKER).run_once()
    assert result.retried == 1
    async with AsyncSession(engine) as session:
        decision = await session.scalar(select(Decision).where(Decision.id == durable.decision_id))
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
    assert decision is not None and delivery is not None
    assert decision.tenant_id == tenant_id
    assert decision.response_status == "DELIVERY_PENDING"
    assert delivery.acknowledgement_digest is None
    assert delivery.safe_diagnostic_code == "ACKNOWLEDGEMENT_INVALID"


@pytest.mark.anyio
async def test_cryptographically_unverified_acknowledgement_never_sets_executed(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _make_broker_delivery(engine, "unverified-ack")
    verifier = _AckVerifier(valid=False)
    result = await _worker(
        engine,
        _RecordingTransport([_ack_response]),
        kind=DestinationKind.ENFORCEMENT_BROKER,
        verifier=verifier,
    ).run_once()
    assert result.retried == 1
    assert verifier.calls == 1
    async with AsyncSession(engine) as session:
        decision = await session.scalar(select(Decision).where(Decision.id == durable.decision_id))
    assert decision is not None
    assert decision.response_status == "DELIVERY_PENDING"


@pytest.mark.anyio
async def test_prohibited_destination_is_never_reached_and_dead_letters(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _persist_outbox_fixture(engine, "ssrf-block")
    transport = _RecordingTransport()
    result = await _worker(engine, transport, resolver=_PrivateResolver()).run_once()
    assert result.dead_lettered == 1
    assert transport.claims == []
    async with AsyncSession(engine) as session:
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
    assert delivery is not None
    assert delivery.safe_diagnostic_code == "DESTINATION_PROHIBITED"


@pytest.mark.anyio
async def test_expired_lease_is_reclaimed_after_worker_restart(engine: AsyncEngine) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _persist_outbox_fixture(engine, "lease-recovery")
    original_delivery_id = durable.delivery_id
    async with AsyncSession(engine) as session, session.begin():
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
        assert delivery is not None
        delivery.state = "IN_FLIGHT"
        delivery.lease_owner = uuid4()
        delivery.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        delivery.state_version += 1
    transport = _RecordingTransport()
    result = await _worker(engine, transport).run_once()
    assert result.delivered == 1
    assert transport.claims[0].delivery_id == original_delivery_id


@pytest.mark.anyio
async def test_expired_lease_at_attempt_limit_dead_letters_without_network(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _persist_outbox_fixture(engine, "exhausted-lease", max_attempts=2)
    async with AsyncSession(engine) as session, session.begin():
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
        assert delivery is not None
        delivery.state = "IN_FLIGHT"
        delivery.attempt_count = 2
        delivery.lease_owner = uuid4()
        delivery.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        delivery.state_version += 1
    transport = _RecordingTransport()
    result = await _worker(engine, transport).run_once()
    assert result.dead_lettered == 1
    assert transport.claims == []
    async with AsyncSession(engine) as session:
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
    assert delivery is not None
    assert delivery.safe_diagnostic_code == "ATTEMPTS_EXHAUSTED"


@pytest.mark.anyio
async def test_http_failure_persists_only_numeric_status_and_safe_code(
    engine: AsyncEngine,
) -> None:
    await _isolate_worker_queue(engine)
    _, durable = await _persist_outbox_fixture(engine, "http-status")
    result = await _worker(
        engine,
        _RecordingTransport([TransportResponse(503, {"x-provider-secret": "must-not-store"})]),
    ).run_once()
    assert result.retried == 1
    async with AsyncSession(engine) as session:
        delivery = await session.scalar(
            select(OutboxDelivery).where(OutboxDelivery.decision_id == durable.decision_id)
        )
    assert delivery is not None
    assert delivery.last_http_status == 503
    assert delivery.safe_diagnostic_code == "HTTP_REJECTED"
    assert "must-not-store" not in repr(delivery.__dict__)


async def _insert_investigation_decision(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    sequence: int,
    created_at: datetime,
    agent_id: str,
    action_type: str,
    verdict: str = "ALLOW",
    policy_decision: str = "ALLOW",
    response_status: str = "DELIVERED",
    degraded: bool = False,
    behavioral_score: Decimal = Decimal("0.75000"),
    total_ms: float = 4.2,
) -> UUID:
    action = CanonicalAction(
        tenant_id=tenant_id,
        input_digest=hashlib.sha256(f"{tenant_id}:{sequence}".encode()).digest(),
        redacted_action={
            "agent_id": agent_id,
            "action_type": action_type,
            "target": f"resource-{sequence}",
            "consequential": verdict != "ALLOW",
            "attributes": {"credential": "[REDACTED]", "region": "eu-west-2"},
        },
        created_at=created_at,
    )
    session.add(action)
    await session.flush()
    trace_id = uuid4()
    decision = Decision(
        tenant_id=tenant_id,
        action_id=action.id,
        trace_id=trace_id,
        idempotency_key=f"query-{tenant_id}-{sequence}",
        agent_id=agent_id,
        verdict=verdict,
        behavioral_score=behavioral_score,
        blast_radius="HIGH" if verdict != "ALLOW" else "LOW",
        reasons=[{"code": "POLICY_MATCH"}],
        mitre_mappings=[{"framework": "MITRE ATT&CK", "id": "T1098"}],
        predicted_next={"action": "observe"},
        policy_decision=policy_decision,
        policy_pack_version="2026.09",
        evidence_state={"degraded": degraded},
        pipeline_timings={"total_ms": total_ms},
        response_status=response_status,
        created_at=created_at,
    )
    session.add(decision)
    await session.flush()
    session.add_all(
        (
            PolicyMatch(
                tenant_id=tenant_id,
                decision_id=decision.id,
                rule_id=f"rule-{sequence}",
                rule_version="1",
                effect="DENY" if verdict == "BLOCK" else "ALLOW",
                safe_metadata={"title": "Safe rule metadata"},
            ),
            AuditEvent(
                tenant_id=tenant_id,
                sequence=sequence,
                event_type="evaluation.decided",
                decision_id=decision.id,
                occurred_at=created_at,
                previous_digest=None,
                digest=hashlib.sha256(f"audit:{tenant_id}:{sequence}".encode()).digest(),
                signing_key_id="kms/key/decision-read-test",
                signature=b"signed",
                integrity_metadata={"trace_id": str(trace_id)},
                sensitive_detail=None,
            ),
        )
    )
    return trace_id


def _investigation_reader(engine: AsyncEngine) -> PostgresDecisionReader:
    database = Database(engine, async_sessionmaker(engine, expire_on_commit=False))
    return PostgresDecisionReader(
        database, DecisionCursorCodec(b"integration-cursor-key-value-32!!")
    )


def _dashboard_reader(engine: AsyncEngine) -> PostgresDashboardReader:
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return PostgresDashboardReader(
        Database(engine, factory), AgentRiskCursorCodec(b"dashboard-integration-key-32bytes")
    )


def _human(tenant_id: UUID) -> Principal:
    return Principal(
        issuer="https://identity.example.test/",
        subject="analyst",
        tenant_id=str(tenant_id),
        kind=IdentityKind.HUMAN,
    )


@pytest.mark.anyio
async def test_decision_keyset_pages_are_stable_without_duplicates_or_gaps(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    base_time = datetime.now(UTC) - timedelta(minutes=10)
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"query-{tenant_id}", display_name="Query tenant"))
        await session.flush()
        original = [
            await _insert_investigation_decision(
                session,
                tenant_id=tenant_id,
                sequence=index,
                created_at=base_time + timedelta(seconds=index // 2),
                agent_id=f"agent-{index}",
                action_type="network.firewall.update",
            )
            for index in range(1, 8)
        ]
    reader = _investigation_reader(engine)
    query = DecisionListQuery(limit=3)
    first = await reader.list_decisions(query, _human(tenant_id))
    assert first.next_cursor is not None
    repeated_first = await reader.list_decisions(query, _human(tenant_id))
    assert [item.trace_id for item in repeated_first.items] == [
        item.trace_id for item in first.items
    ]

    async with AsyncSession(engine) as session, session.begin():
        await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=8,
            created_at=datetime.now(UTC),
            agent_id="new-after-snapshot",
            action_type="network.firewall.update",
        )

    seen = [item.trace_id for item in first.items]
    cursor = first.next_cursor
    while cursor is not None:
        page = await reader.list_decisions(
            DecisionListQuery(limit=2, cursor=cursor), _human(tenant_id)
        )
        assert page.snapshot_at == first.snapshot_at
        seen.extend(item.trace_id for item in page.items)
        cursor = page.next_cursor
    assert len(seen) == len(set(seen)) == len(original)
    assert set(seen) == set(original)


@pytest.mark.anyio
async def test_decision_filters_full_text_search_and_cursor_binding_use_postgresql(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    other_tenant = uuid4()
    created = datetime.now(UTC) - timedelta(minutes=1)
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_id, slug=f"filter-{tenant_id}", display_name="Filter tenant"),
                Tenant(id=other_tenant, slug=f"other-{other_tenant}", display_name="Other"),
            )
        )
        await session.flush()
        blocked_trace = await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=1,
            created_at=created,
            agent_id="payments-deployer",
            action_type="iam.role.assignment",
            verdict="BLOCK",
            policy_decision="DENY",
            response_status="FAILED",
            degraded=True,
        )
        await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=2,
            created_at=created + timedelta(seconds=1),
            agent_id="benign-agent",
            action_type="storage.read",
        )
        await _insert_investigation_decision(
            session,
            tenant_id=other_tenant,
            sequence=1,
            created_at=created,
            agent_id="payments-deployer",
            action_type="iam.role.assignment",
            verdict="BLOCK",
        )
    reader = _investigation_reader(engine)
    query = DecisionListQuery(
        limit=1,
        verdict="BLOCK",
        policy_decision="DENY",
        response_status="FAILED",
        evidence_degraded=True,
        agent_id="payments-deployer",
        action_type="iam.role.assignment",
        search="resource",
        created_from=created - timedelta(seconds=1),
        created_to=created + timedelta(seconds=1),
    )
    page = await reader.list_decisions(query, _human(tenant_id))
    assert [item.trace_id for item in page.items] == [blocked_trace]
    trace_search = await reader.list_decisions(
        DecisionListQuery(search=str(blocked_trace)), _human(tenant_id)
    )
    assert [item.trace_id for item in trace_search.items] == [blocked_trace]
    empty = await reader.list_decisions(
        DecisionListQuery(search="definitely-absent-decision"), _human(tenant_id)
    )
    assert empty.items == ()
    assert empty.next_cursor is None

    unfiltered = await reader.list_decisions(DecisionListQuery(limit=1), _human(tenant_id))
    assert unfiltered.next_cursor is not None
    with pytest.raises(InvalidDecisionCursorError):
        await reader.list_decisions(
            DecisionListQuery(cursor=unfiltered.next_cursor, verdict="BLOCK"),
            _human(tenant_id),
        )
    with pytest.raises(InvalidDecisionCursorError):
        await reader.list_decisions(
            DecisionListQuery(cursor=unfiltered.next_cursor), _human(other_tenant)
        )


@pytest.mark.anyio
async def test_decision_detail_is_redacted_tenant_bound_and_has_persisted_continuity(
    engine: AsyncEngine,
) -> None:
    tenant_id, other_tenant = uuid4(), uuid4()
    created = datetime.now(UTC) - timedelta(minutes=1)
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_id, slug=f"detail-{tenant_id}", display_name="Detail tenant"),
                Tenant(id=other_tenant, slug=f"hidden-{other_tenant}", display_name="Hidden"),
            )
        )
        await session.flush()
        trace_id = await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=1,
            created_at=created,
            agent_id="detail-agent",
            action_type="kubernetes.cluster_role.bind",
            verdict="BLOCK",
            policy_decision="DENY",
        )
        similar_trace = await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=2,
            created_at=created - timedelta(seconds=1),
            agent_id="detail-agent",
            action_type="storage.read",
        )
    reader = _investigation_reader(engine)
    detail = await reader.get_decision(trace_id, _human(tenant_id))
    assert detail.action is not None
    assert detail.action.attributes["credential"] == "[REDACTED]"
    assert "idempotency" not in detail.model_dump_json()
    assert detail.audit.sequence == 1
    assert detail.audit.digest
    assert detail.policy_matches[0].rule_id == "rule-1"
    assert [item.trace_id for item in detail.similar_decisions] == [similar_trace]
    with pytest.raises(DecisionNotFoundError):
        await reader.get_decision(trace_id, _human(other_tenant))

    deleted_at = datetime.now(UTC)
    async with AsyncSession(engine) as session, session.begin():
        stored = await session.scalar(
            select(Decision).where(Decision.tenant_id == tenant_id, Decision.trace_id == trace_id)
        )
        assert stored is not None
        stored_action = await session.scalar(
            select(CanonicalAction).where(
                CanonicalAction.tenant_id == tenant_id,
                CanonicalAction.id == stored.action_id,
            )
        )
        assert stored_action is not None
        stored.reasons = None
        stored.mitre_mappings = None
        stored.predicted_next = None
        stored.evidence_state = None
        stored.pipeline_timings = None
        stored.detail_deleted_at = deleted_at
        stored_action.redacted_action = None
        stored_action.detail_deleted_at = deleted_at
    retained = await reader.get_decision(trace_id, _human(tenant_id))
    assert retained.detail_available is False
    assert retained.action is None
    assert retained.reasons is None
    assert retained.audit.digest == detail.audit.digest


@pytest.mark.anyio
async def test_large_decision_dataset_remains_bounded_and_uses_query_indexes(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    created = datetime.now(UTC) - timedelta(hours=1)
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"large-{tenant_id}", display_name="Large tenant"))
        await session.flush()
        for index in range(1, 251):
            await _insert_investigation_decision(
                session,
                tenant_id=tenant_id,
                sequence=index,
                created_at=created + timedelta(milliseconds=index),
                agent_id="high-volume-agent" if index % 2 else "other-agent",
                action_type="network.firewall.update" if index % 3 else "storage.read",
            )
    reader = _investigation_reader(engine)
    durations: list[float] = []
    for _ in range(20):
        started = time.perf_counter()
        page = await reader.list_decisions(
            DecisionListQuery(limit=100, agent_id="high-volume-agent"), _human(tenant_id)
        )
        durations.append((time.perf_counter() - started) * 1000)
        assert len(page.items) == 100
    observed_p95 = sorted(durations)[18]
    assert observed_p95 <= 500

    async with engine.connect() as connection:
        indexes = {
            row[0]
            for row in (
                await connection.execute(
                    text(
                        "SELECT indexname FROM pg_indexes "
                        "WHERE schemaname = current_schema() AND tablename IN "
                        "('decisions', 'canonical_actions')"
                    )
                )
            ).all()
        }
    assert {
        "ix_decisions_tenant_created",
        "ix_decisions_tenant_policy_created",
        "ix_decisions_tenant_response_created",
        "ix_decisions_search_agent",
        "ix_canonical_actions_search_document",
    } <= indexes


@pytest.mark.anyio
async def test_dashboard_metrics_match_source_decisions_and_isolate_tenants(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    other_tenant = uuid4()
    now = datetime.now(UTC)
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_id, slug=f"dash-{tenant_id}", display_name="Dashboard"),
                Tenant(id=other_tenant, slug=f"dash-{other_tenant}", display_name="Other"),
            )
        )
        await session.flush()
        await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=1,
            created_at=now - timedelta(hours=2),
            agent_id="agent-critical",
            action_type="iam.role.assign",
            verdict="BLOCK",
            policy_decision="DENY",
            behavioral_score=Decimal("0.95000"),
            total_ms=10,
        )
        await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=2,
            created_at=now - timedelta(hours=1),
            agent_id="agent-safe",
            action_type="storage.read",
            behavioral_score=Decimal("0.20000"),
            total_ms=20,
        )
        await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=3,
            created_at=now - timedelta(hours=25),
            agent_id="agent-prior",
            action_type="storage.read",
            behavioral_score=Decimal("0.10000"),
        )
        await _insert_investigation_decision(
            session,
            tenant_id=other_tenant,
            sequence=1,
            created_at=now - timedelta(minutes=5),
            agent_id="foreign-agent",
            action_type="secret.read",
            verdict="BLOCK",
            behavioral_score=Decimal("1.00000"),
        )

    reader = _dashboard_reader(engine)
    principal = _human(tenant_id)
    summary = await reader.summary(DashboardWindowQuery(window="24h"), principal)
    assert summary.decisions.value == 2
    assert summary.decisions.previous_value == 1
    assert summary.blocked.value == 1
    assert summary.active_agents.value == 2
    assert summary.high_risk_decisions.value == 1
    assert summary.evaluation_latency.p95_ms == pytest.approx(19.5)
    assert summary.freshness.state == "available"
    assert summary.freshness.poll_after_seconds == 30

    volume = await reader.decision_volume(DashboardWindowQuery(window="24h"), principal)
    assert sum(point.total for point in volume.points) == 2
    assert sum(point.block for point in volume.points) == 1
    breakdown = await reader.action_breakdown(DashboardWindowQuery(window="24h"), principal)
    assert [(item.action_type, item.decision_count) for item in breakdown.items] == [
        ("iam.role.assign", 1),
        ("storage.read", 1),
    ]
    assert sum(item.share_percent for item in breakdown.items) == 100
    assert "foreign-agent" not in summary.model_dump_json()


@pytest.mark.anyio
async def test_agent_risk_ranking_cursor_detail_and_cross_tenant_not_found(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    other_tenant = uuid4()
    now = datetime.now(UTC)
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_id, slug=f"risk-{tenant_id}", display_name="Risk"),
                Tenant(id=other_tenant, slug=f"risk-{other_tenant}", display_name="Other"),
            )
        )
        await session.flush()
        for sequence, agent, score in (
            (1, "agent-high", Decimal("0.95000")),
            (2, "agent-medium", Decimal("0.75000")),
            (3, "agent-low", Decimal("0.25000")),
        ):
            await _insert_investigation_decision(
                session,
                tenant_id=tenant_id,
                sequence=sequence,
                created_at=now - timedelta(minutes=sequence),
                agent_id=agent,
                action_type="compute.start",
                verdict="BLOCK" if sequence == 1 else "ALLOW",
                behavioral_score=score,
                total_ms=sequence * 5,
            )

    reader = _dashboard_reader(engine)
    first = await reader.agent_risk(AgentRiskQuery(window="30d", limit=2), _human(tenant_id))
    assert [item.agent_id for item in first.items] == ["agent-high", "agent-medium"]
    assert first.next_cursor is not None
    async with AsyncSession(engine) as session, session.begin():
        await _insert_investigation_decision(
            session,
            tenant_id=tenant_id,
            sequence=4,
            created_at=datetime.now(UTC),
            agent_id="agent-late",
            action_type="compute.start",
            behavioral_score=Decimal("1.00000"),
        )
    second = await reader.agent_risk(
        AgentRiskQuery(window="30d", limit=2, cursor=first.next_cursor), _human(tenant_id)
    )
    assert [item.agent_id for item in second.items] == ["agent-low"]
    assert set(item.agent_id for item in first.items + second.items) == {
        "agent-high",
        "agent-medium",
        "agent-low",
    }
    assert "agent-late" not in {item.agent_id for item in first.items + second.items}

    detail = await reader.agent_detail(
        "agent-high", DashboardWindowQuery(window="30d"), _human(tenant_id)
    )
    assert detail.risk_score == 0.95
    assert detail.block_count == 1
    assert detail.recent_decisions[0].action_type == "compute.start"
    with pytest.raises(AgentNotFoundError):
        await reader.agent_detail(
            "agent-high", DashboardWindowQuery(window="30d"), _human(other_tenant)
        )


@pytest.mark.anyio
async def test_empty_dashboard_is_explicit_and_launch_load_is_bounded(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(Tenant(id=tenant_id, slug=f"empty-{tenant_id}", display_name="Empty"))
    reader = _dashboard_reader(engine)
    empty = await reader.summary(DashboardWindowQuery(), _human(tenant_id))
    assert empty.freshness.state == "empty"
    assert empty.freshness.source_last_updated_at is None
    assert empty.decisions.value == 0
    assert empty.evaluation_latency.p95_ms is None

    now = datetime.now(UTC)
    async with AsyncSession(engine) as session, session.begin():
        for sequence in range(1, 501):
            await _insert_investigation_decision(
                session,
                tenant_id=tenant_id,
                sequence=sequence,
                created_at=now - timedelta(seconds=sequence),
                agent_id=f"agent-{sequence % 50:02d}",
                action_type=f"action.{sequence % 10}",
                behavioral_score=Decimal(sequence % 100) / Decimal(100),
            )
    durations: list[float] = []
    for _ in range(20):
        started = time.perf_counter()
        page = await reader.agent_risk(AgentRiskQuery(limit=50), _human(tenant_id))
        durations.append((time.perf_counter() - started) * 1000)
        assert len(page.items) == 50
    assert sorted(durations)[18] <= 1000


@pytest.mark.anyio
async def test_operational_health_is_tenant_scoped_stale_aware_and_measured(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    other_tenant = uuid4()
    now = datetime.now(UTC)
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_id, slug=f"ops-{tenant_id}", display_name="Operations"),
                Tenant(id=other_tenant, slug=f"ops-{other_tenant}", display_name="Other"),
            )
        )
        await session.flush()
        session.add_all(
            (
                IntegrationHealth(
                    tenant_id=tenant_id,
                    integration_key="gate-primary",
                    integration_kind="gate",
                    status="HEALTHY",
                    checked_at=now,
                    latency_ms=8,
                ),
                IntegrationHealth(
                    tenant_id=tenant_id,
                    integration_key="sie-primary",
                    integration_kind="sie",
                    status="HEALTHY",
                    checked_at=now - timedelta(minutes=10),
                    latency_ms=21,
                    safe_diagnostic_code="postgresql://secret@internal",
                ),
                IntegrationHealth(
                    tenant_id=other_tenant,
                    integration_key="foreign-adapter",
                    integration_kind="adapter",
                    status="UNAVAILABLE",
                    checked_at=now,
                    safe_diagnostic_code="CONNECTION_FAILED",
                ),
            )
        )

    database = Database(
        engine,
        async_sessionmaker(engine, expire_on_commit=False),
    )
    reader = PostgresOperationsReader(
        database,
        load_enterprise_pack(),
        OperationsCursorCodec(b"x" * 32),
        stale_after=timedelta(minutes=2),
        instrumented_pipeline_stages=(
            "normalization",
            "behavioral",
            "policy",
            "persistence",
            "audit",
            "response",
        ),
    )
    principal = _human(tenant_id)
    page = await reader.integration_health(IntegrationHealthQuery(limit=1), principal)
    assert [item.integration_key for item in page.items] == ["gate-primary"]
    assert page.next_cursor is not None
    second = await reader.integration_health(
        IntegrationHealthQuery(limit=1, cursor=page.next_cursor), principal
    )
    assert second.items[0].status == "STALE"
    assert second.items[0].diagnostic_code == "STALE_MEASUREMENT"
    assert "foreign-adapter" not in page.model_dump_json() + second.model_dump_json()

    status = await reader.service_status(principal)
    components = {component.name: component for component in status.components}
    assert components["postgresql"].status == "healthy"
    assert components["gate"].status == "healthy"
    assert components["sie"].status == "unavailable"
    assert components["outbox"].status == "unmeasured"
    assert components["audit"].status == "unmeasured"
    assert components["adapters"].status == "unmeasured"
    assert status.instrumented_pipeline_stages == (
        "normalization",
        "behavioral",
        "policy",
        "persistence",
        "audit",
        "response",
    )


@pytest.mark.anyio
async def test_retention_is_bounded_legal_hold_safe_and_preserves_signed_chain(
    engine: AsyncEngine,
) -> None:
    tenant_id, held_tenant_id = uuid4(), uuid4()
    signer = _TestSigner()
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(
                    id=tenant_id,
                    slug=f"privacy-{tenant_id}",
                    display_name="Privacy tenant",
                    decision_retention_days=90,
                    audit_retention_days=365,
                ),
                Tenant(
                    id=held_tenant_id,
                    slug=f"held-{held_tenant_id}",
                    display_name="Held tenant",
                    decision_retention_days=1,
                    audit_retention_days=1,
                    legal_hold=True,
                ),
            )
        )
    durable = await _store(engine, signer).persist(
        request=_evaluation_request("privacy-expired"),
        response=_evaluation_response(),
        principal=Principal(
            "https://issuer.example",
            "privacy-workload",
            str(tenant_id),
            IdentityKind.WORKLOAD,
            workload_id="privacy-agent",
        ),
    )
    held = await _store(engine, signer).persist(
        request=_evaluation_request("held-expired"),
        response=_evaluation_response(),
        principal=Principal(
            "https://issuer.example",
            "held-workload",
            str(held_tenant_id),
            IdentityKind.WORKLOAD,
            workload_id="held-agent",
        ),
    )
    expired_at = datetime.now(UTC) - timedelta(days=400)
    async with AsyncSession(engine) as session, session.begin():
        decision = await session.get(Decision, durable.decision_id)
        held_decision = await session.get(Decision, held.decision_id)
        event = await session.get(AuditEvent, durable.audit_event_id)
        assert decision and held_decision and event
        action = await session.get(CanonicalAction, decision.action_id)
        held_action = await session.get(CanonicalAction, held_decision.action_id)
        assert action and held_action
        decision.created_at = expired_at
        action.created_at = expired_at
        held_decision.created_at = expired_at
        held_action.created_at = expired_at
        event.occurred_at = expired_at
        event.sensitive_detail = {"credential": "must-be-removed"}
        event.digest = audit_digest(
            tenant_id=tenant_id,
            sequence=event.sequence,
            event_type=event.event_type,
            decision_id=event.decision_id,
            principal_id=event.principal_id,
            occurred_at=expired_at,
            previous_digest=event.previous_digest,
            integrity_metadata=event.integrity_metadata,
        )
        event.signature = await signer.sign(event.digest)

    database = Database(engine, async_sessionmaker(engine, expire_on_commit=False))
    service = RetentionService(database, signer)
    administrator = Principal(
        "https://issuer.example",
        "privacy-administrator",
        str(tenant_id),
        IdentityKind.HUMAN,
        roles=frozenset({Role.ADMINISTRATOR}),
    )
    held_administrator = Principal(
        "https://issuer.example",
        "held-administrator",
        str(held_tenant_id),
        IdentityKind.HUMAN,
        roles=frozenset({Role.ADMINISTRATOR}),
    )
    preview = await service.run_once(administrator, dry_run=True, batch_size=1)
    assert preview.mode == "DRY_RUN"
    assert preview.status == "MORE_AVAILABLE"
    assert (preview.decision_details, preview.audit_sensitive_details) == (1, 0)
    async with AsyncSession(engine) as session:
        preview_decision = await session.get(Decision, durable.decision_id)
        assert preview_decision and preview_decision.reasons is not None

    applied = await service.run_once(administrator, dry_run=False, batch_size=1)
    assert applied.status == "MORE_AVAILABLE"
    assert (applied.decision_details, applied.canonical_actions) == (1, 1)
    assert applied.audit_sensitive_details == 0
    assert applied.evidence_event_id is not None
    resumed = await service.run_once(administrator, dry_run=False, batch_size=1)
    assert resumed.status == "COMPLETE"
    assert resumed.decision_details == 0
    assert resumed.audit_sensitive_details == 1
    assert resumed.evidence_event_id is not None
    held_result = await service.run_once(held_administrator, dry_run=False, batch_size=2)
    assert held_result.status == "LEGAL_HOLD"
    assert held_result.evidence_event_id is None

    async with AsyncSession(engine) as session:
        decision = await session.get(Decision, durable.decision_id)
        held_decision = await session.get(Decision, held.decision_id)
        old_event = await session.get(AuditEvent, durable.audit_event_id)
        assert decision and held_decision and old_event
        action = await session.get(CanonicalAction, decision.action_id)
        events = list(
            (
                await session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.tenant_id == tenant_id)
                    .order_by(AuditEvent.sequence)
                )
            ).all()
        )
    assert decision.reasons is None and decision.detail_deleted_at is not None
    assert action and action.redacted_action is None and action.detail_deleted_at is not None
    assert old_event.sensitive_detail is None and old_event.detail_deleted_at is not None
    assert held_decision.reasons is not None and held_decision.detail_deleted_at is None
    assert events[-1].event_type == "privacy.retention_applied"
    assert events[-2].integrity_metadata["deleted"] == {
        "decision_details": 1,
        "canonical_actions": 1,
        "audit_sensitive_details": 0,
    }
    assert events[-1].integrity_metadata["deleted"] == {
        "decision_details": 0,
        "canonical_actions": 0,
        "audit_sensitive_details": 1,
    }
    checkpoint = type(durable.checkpoint)(tenant_id, events[-1].sequence, events[-1].digest)
    await verify_signed_audit_chain(tenant_id, events, checkpoint, signer)


@pytest.mark.anyio
async def test_privacy_export_is_administrator_authorized_tenant_scoped_and_redacted(
    engine: AsyncEngine,
) -> None:
    tenant_id, other_tenant = uuid4(), uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_id, slug=f"export-{tenant_id}", display_name="Export"),
                Tenant(id=other_tenant, slug=f"foreign-{other_tenant}", display_name="Foreign"),
            )
        )
    for current, key in ((tenant_id, "export-local"), (other_tenant, "export-foreign")):
        await _store(engine).persist(
            request=_evaluation_request(key),
            response=_evaluation_response(),
            principal=Principal(
                "https://issuer.example",
                f"subject-{current}",
                str(current),
                IdentityKind.WORKLOAD,
                workload_id=f"agent-{current}",
            ),
        )
    service = PrivacyExportService(
        Database(engine, async_sessionmaker(engine, expire_on_commit=False))
    )
    administrator = Principal(
        "https://issuer.example",
        "privacy-administrator",
        str(tenant_id),
        IdentityKind.HUMAN,
        roles=frozenset({Role.ADMINISTRATOR}),
    )
    page = await service.export_page(administrator, limit=1)
    assert len(page.items) == 1
    assert page.items[0].action is not None
    serialized = page.model_dump_json()
    assert "export-foreign" not in serialized
    assert "must-not-persist" not in serialized
    assert "unrestricted-provider-token" not in serialized
    assert page.manifest_digest.startswith("sha256:")


@pytest.mark.anyio
async def test_retention_signing_failure_rolls_back_the_complete_batch(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(
            Tenant(
                id=tenant_id,
                slug=f"rollback-{tenant_id}",
                display_name="Rollback tenant",
                decision_retention_days=1,
            )
        )
    durable = await _store(engine).persist(
        request=_evaluation_request("retention-rollback"),
        response=_evaluation_response(),
        principal=Principal(
            "https://issuer.example",
            "rollback-workload",
            str(tenant_id),
            IdentityKind.WORKLOAD,
            workload_id="rollback-agent",
        ),
    )
    async with AsyncSession(engine) as session, session.begin():
        decision = await session.get(Decision, durable.decision_id)
        assert decision
        action = await session.get(CanonicalAction, decision.action_id)
        assert action
        decision.created_at = datetime.now(UTC) - timedelta(days=2)
        action.created_at = decision.created_at

    class FailingSigner:
        key_id = "unavailable-key"

        async def sign(self, digest: bytes) -> bytes:
            raise TimeoutError("private signer endpoint")

        async def verify(self, digest: bytes, signature: bytes, key_id: str) -> bool:
            return False

    service = RetentionService(
        Database(engine, async_sessionmaker(engine, expire_on_commit=False)),
        FailingSigner(),
    )
    with pytest.raises(PrivacyUnavailableError, match="signing unavailable"):
        await service.run_once(
            Principal(
                "https://issuer.example",
                "rollback-administrator",
                str(tenant_id),
                IdentityKind.HUMAN,
                roles=frozenset({Role.ADMINISTRATOR}),
            ),
            dry_run=False,
            batch_size=1,
        )
    async with AsyncSession(engine) as session:
        decision = await session.get(Decision, durable.decision_id)
        assert decision and decision.reasons is not None
        assert decision.detail_deleted_at is None


@pytest.mark.anyio
async def test_retention_policy_update_is_tenant_scoped_and_signed(engine: AsyncEngine) -> None:
    tenant_id, other_tenant = uuid4(), uuid4()
    signer = _TestSigner()
    async with AsyncSession(engine) as session, session.begin():
        session.add_all(
            (
                Tenant(id=tenant_id, slug=f"policy-{tenant_id}", display_name="Policy"),
                Tenant(id=other_tenant, slug=f"policy-{other_tenant}", display_name="Other"),
            )
        )
    service = RetentionPolicyService(
        Database(engine, async_sessionmaker(engine, expire_on_commit=False)), signer
    )
    administrator = Principal(
        "https://issuer.example",
        "retention-administrator",
        str(tenant_id),
        IdentityKind.HUMAN,
        roles=frozenset({Role.ADMINISTRATOR}),
    )
    policy = RetentionPolicy(
        decision_retention_days=120,
        audit_retention_days=400,
        legal_hold=True,
    )
    result = await service.configure(administrator, policy)
    assert result.evidence_event_id is not None
    unchanged = await service.configure(administrator, policy)
    assert unchanged.evidence_event_id is None

    async with AsyncSession(engine) as session:
        tenant = await session.get(Tenant, tenant_id)
        other = await session.get(Tenant, other_tenant)
        events = list(
            (
                await session.scalars(
                    select(AuditEvent)
                    .where(AuditEvent.tenant_id == tenant_id)
                    .order_by(AuditEvent.sequence)
                )
            ).all()
        )
    assert tenant and other
    assert (tenant.decision_retention_days, tenant.audit_retention_days, tenant.legal_hold) == (
        120,
        400,
        True,
    )
    assert (other.decision_retention_days, other.audit_retention_days, other.legal_hold) == (
        90,
        365,
        False,
    )
    assert len(events) == 1 and events[0].event_type == "privacy.retention_policy_updated"
    assert events[0].principal_id is not None
    await verify_signed_audit_chain(
        tenant_id,
        events,
        AuditCheckpoint(tenant_id, events[-1].sequence, events[-1].digest),
        signer,
    )


@pytest.mark.anyio
async def test_concurrent_reader_sees_only_precommit_or_complete_retention_state(
    engine: AsyncEngine,
) -> None:
    tenant_id = uuid4()
    async with AsyncSession(engine) as session, session.begin():
        session.add(
            Tenant(
                id=tenant_id,
                slug=f"concurrent-{tenant_id}",
                display_name="Concurrent retention",
                decision_retention_days=1,
            )
        )
    durable = await _store(engine).persist(
        request=_evaluation_request("retention-concurrent-read"),
        response=_evaluation_response(),
        principal=Principal(
            "https://issuer.example",
            "concurrent-workload",
            str(tenant_id),
            IdentityKind.WORKLOAD,
            workload_id="concurrent-agent",
        ),
    )
    async with AsyncSession(engine) as session, session.begin():
        decision = await session.get(Decision, durable.decision_id)
        assert decision
        action = await session.get(CanonicalAction, decision.action_id)
        assert action
        decision.created_at = datetime.now(UTC) - timedelta(days=2)
        action.created_at = decision.created_at

    entered, release = asyncio.Event(), asyncio.Event()

    class BlockingSigner(_TestSigner):
        async def sign(self, digest: bytes) -> bytes:
            entered.set()
            await release.wait()
            return await super().sign(digest)

    service = RetentionService(
        Database(engine, async_sessionmaker(engine, expire_on_commit=False)), BlockingSigner()
    )
    administrator = Principal(
        "https://issuer.example",
        "concurrent-administrator",
        str(tenant_id),
        IdentityKind.HUMAN,
        roles=frozenset({Role.ADMINISTRATOR}),
    )
    cleanup = asyncio.create_task(service.run_once(administrator, dry_run=False, batch_size=1))
    await asyncio.wait_for(entered.wait(), timeout=2)
    async with AsyncSession(engine) as session:
        before_commit = await session.get(Decision, durable.decision_id)
        assert before_commit and before_commit.reasons is not None
        assert before_commit.detail_deleted_at is None
    release.set()
    result = await asyncio.wait_for(cleanup, timeout=2)
    assert result.decision_details == 1
    async with AsyncSession(engine) as session:
        after_commit = await session.get(Decision, durable.decision_id)
        assert after_commit and after_commit.reasons is None
        assert after_commit.detail_deleted_at is not None
