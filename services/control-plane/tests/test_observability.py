"""OpenTelemetry, RED metric, correlation, and redaction boundary tests."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from io import StringIO
from uuid import uuid4

import pytest
from dusk.application import BehavioralDecision
from fastapi.testclient import TestClient
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import ValidationError

from dusk_control_plane.app import create_app
from dusk_control_plane.audit import AuditCheckpoint, DurableDecision, DurableEvaluationService
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dependencies import AppContainer
from dusk_control_plane.evaluations import (
    CanonicalAction,
    EvaluationRequest,
    EvidenceEnvelope,
    PolicyEvaluationService,
)
from dusk_control_plane.identity import IdentityKind, Principal
from dusk_control_plane.observability import (
    SafeJsonFormatter,
    Telemetry,
    TelemetryRuntime,
    build_telemetry,
)
from dusk_control_plane.policy import CombinedDecision, EnforcementMode
from dusk_control_plane.request_context import (
    reset_decision_trace_id,
    reset_request_id,
    set_decision_trace_id,
    set_request_id,
)


def _telemetry() -> tuple[Telemetry, InMemorySpanExporter, InMemoryMetricReader]:
    spans = InMemorySpanExporter()
    tracer_provider = TracerProvider()
    tracer_provider.add_span_processor(SimpleSpanProcessor(spans))
    metrics = InMemoryMetricReader()
    meter_provider = MeterProvider(metric_readers=(metrics,))
    telemetry = Telemetry(
        tracer=tracer_provider.get_tracer("test"), meter=meter_provider.get_meter("test")
    )
    return telemetry, spans, metrics


def test_stage_spans_are_correlated_redacted_and_record_failures() -> None:
    telemetry, exporter, _metrics = _telemetry()
    request_token = set_request_id("request-safe")
    trace_token = set_decision_trace_id("decision-safe")
    try:
        with telemetry.stage("normalization"):
            pass
        with pytest.raises(RuntimeError, match="CANARY_SECRET"):
            with telemetry.stage("policy"):
                raise RuntimeError("CANARY_SECRET token=do-not-export")
    finally:
        reset_decision_trace_id(trace_token)
        reset_request_id(request_token)

    spans = exporter.get_finished_spans()
    assert [span.name for span in spans] == [
        "dusk.pipeline.normalization",
        "dusk.pipeline.policy",
    ]
    assert spans[0].attributes == {
        "dusk.pipeline.stage": "normalization",
        "dusk.request.id": "request-safe",
        "dusk.decision.trace_id": "decision-safe",
        "dusk.outcome": "success",
        "dusk.duration_ms": spans[0].attributes["dusk.duration_ms"],
    }
    serialized = repr(spans)
    assert "CANARY_SECRET" not in serialized
    assert "do-not-export" not in serialized
    assert spans[1].attributes["dusk.outcome"] == "failure"


def test_red_metrics_have_only_bounded_dimensions() -> None:
    telemetry, _exporter, metric_reader = _telemetry()
    telemetry.record_request(
        method="DELETE",
        route="/v2/tenants/attacker-controlled-secret",
        status_code=503,
        duration_ms=12.5,
    )
    data = metric_reader.get_metrics_data()
    points = [
        point
        for resource in data.resource_metrics
        for scope in resource.scope_metrics
        for metric in scope.metrics
        for point in metric.data.data_points
    ]
    assert points
    for point in points:
        assert dict(point.attributes) == {
            "http.request.method": "OTHER",
            "http.route": "unmatched",
            "http.response.status_class": "5xx",
        }
    assert "attacker-controlled-secret" not in repr(data)


def test_structured_formatter_never_interpolates_arbitrary_log_data() -> None:
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJsonFormatter())
    logger = logging.getLogger("dusk.test.redaction")
    logger.handlers = [handler]
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.info(
        "raw action=%s token=%s",
        "CANARY_ACTION_PAYLOAD",
        "CANARY_CREDENTIAL",
        extra={"event_code": "evaluation.completed"},
    )
    document = json.loads(stream.getvalue())
    assert document["event"] == "evaluation.completed"
    assert document["logger"] == "dusk.test.redaction"
    assert "CANARY" not in stream.getvalue()


def test_http_response_span_and_red_metrics_use_route_template() -> None:
    telemetry, exporter, metric_reader = _telemetry()
    app = create_app(
        container=AppContainer(
            settings=Settings(environment=Environment.TEST),
            telemetry_runtime=TelemetryRuntime(telemetry),
        )
    )
    with TestClient(app) as client:
        response = client.get(
            "/livez",
            headers={"traceparent": "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
        )
    assert response.status_code == 200
    spans = exporter.get_finished_spans()
    response_span = next(span for span in spans if span.name == "dusk.pipeline.response")
    server_span = next(span for span in spans if span.name == "GET /livez")
    assert server_span.parent is not None
    assert server_span.parent.span_id == int("0123456789abcdef", 16)
    assert response_span.context.trace_id == server_span.context.trace_id
    assert response_span.parent is not None
    assert response_span.parent.span_id == server_span.context.span_id
    assert "/livez" in repr(metric_reader.get_metrics_data())


def test_observability_configuration_is_default_off_and_bounded() -> None:
    settings = Settings()
    assert settings.observability_enabled is False
    with pytest.raises(ValidationError, match="requires otlp_endpoint"):
        Settings(observability_enabled=True)
    with pytest.raises(ValidationError, match="HTTPS URL"):
        Settings(observability_enabled=True, otlp_endpoint="http://collector.internal")
    with pytest.raises(ValidationError, match="must not exceed"):
        Settings(
            observability_enabled=True,
            otlp_endpoint="https://collector.example.test",
            telemetry_queue_size=128,
            telemetry_batch_size=129,
        )
    malformed = Settings(
        observability_enabled=True,
        otlp_endpoint="https://collector.example.test",
        otlp_headers="not-json",
    )
    with pytest.raises(ValueError, match="JSON object"):
        build_telemetry(malformed)
    assert "not-json" not in repr(malformed)


def test_exporter_failure_never_changes_request_or_decision_outcome() -> None:
    class FailingExporter(SpanExporter):
        def export(self, spans) -> SpanExportResult:
            return SpanExportResult.FAILURE

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(FailingExporter()))
    telemetry = Telemetry(tracer=provider.get_tracer("test"), meter=metrics.get_meter("test"))
    completed = False
    with telemetry.stage("behavioral"):
        completed = True
    assert completed is True


class _RecordingTelemetry:
    def __init__(self) -> None:
        self.stages: list[tuple[str, str | None]] = []

    @contextmanager
    def stage(self, stage: str, **correlation: str | None) -> Iterator[None]:
        self.stages.append((stage, correlation.get("decision_trace_id")))
        yield


class _Behavioral:
    async def evaluate(self, action, principal) -> BehavioralDecision:
        return BehavioralDecision(
            trace_id=str(uuid4()),
            verdict="ALLOW",
            score=0.1,
            blast_radius="low",
            reasons=(),
            mitre_attack="",
            mitre_atlas="",
            predicted_next="none",
            target_class="none",
            target_tokens=frozenset(),
        )


class _Policy:
    async def evaluate(self, **kwargs) -> CombinedDecision:
        return CombinedDecision("ALLOW", (), "ALLOW", "1.0.0", (), False)


def _request() -> EvaluationRequest:
    return EvaluationRequest(
        action=CanonicalAction(
            agent_id="agent-a", action_type="read", target="object-a", consequential=False
        ),
        evidence=(
            EvidenceEnvelope(
                domain="action",
                source_identity="source-a",
                provenance="signed",
                observed_at=datetime(2026, 9, 4, tzinfo=UTC),
                digest="sha256:" + "0" * 64,
                payload={"type": "read"},
                tenant_id="tenant-a",
                key_id="test-key",
                nonce="test-nonce-00000001",
                signature="a" * 86,
            ),
        ),
        idempotency_key="request-a",
    )


def _principal() -> Principal:
    return Principal("issuer", "subject", str(uuid4()), IdentityKind.WORKLOAD)


@pytest.mark.anyio
async def test_evaluation_and_durability_services_emit_real_stage_boundaries() -> None:
    recording = _RecordingTelemetry()
    evaluator = PolicyEvaluationService(
        _Policy(),  # type: ignore[arg-type]
        _Behavioral(),
        mode=EnforcementMode.ENFORCE,
        telemetry=recording,  # type: ignore[arg-type]
    )
    response = await evaluator.evaluate(_request(), _principal())
    assert [stage for stage, _trace in recording.stages] == [
        "normalization",
        "behavioral",
        "policy",
    ]
    assert response.pipeline_timings.normalization_ms >= 0
    assert recording.stages[-1][1] == response.trace_id

    class Store:
        async def persist(self, **kwargs) -> DurableDecision:
            value = kwargs["response"]
            trace_id = uuid4()
            return DurableDecision(
                uuid4(),
                trace_id,
                uuid4(),
                uuid4(),
                AuditCheckpoint(uuid4(), 1, b"x" * 32),
                True,
                value.model_copy(
                    update={"trace_id": str(trace_id), "response_status": "DELIVERY_PENDING"}
                ),
                0.25,
            )

    durable = await DurableEvaluationService(
        evaluator,
        Store(),
        telemetry=recording,  # type: ignore[arg-type]
    ).evaluate(_request(), _principal())
    assert "persistence" in [stage for stage, _trace in recording.stages]
    assert durable.pipeline_timings.persistence_ms is not None
    assert durable.pipeline_timings.audit_ms == 0.25
    assert durable.pipeline_timings.total_ms >= durable.pipeline_timings.persistence_ms
