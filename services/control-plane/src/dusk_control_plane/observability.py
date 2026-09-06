"""Bounded OpenTelemetry and structured-log boundary for the control plane."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from time import perf_counter
from typing import Literal

from opentelemetry import metrics, propagate, trace
from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Status, StatusCode
from opentelemetry.trace.span import Span

from dusk_control_plane.config import Settings
from dusk_control_plane.request_context import get_decision_trace_id, get_request_id

PipelineStage = Literal[
    "normalization",
    "baseline",
    "behavioral",
    "sie",
    "policy",
    "persistence",
    "audit",
    "response",
    "outbox",
    "broker_acknowledgement",
]
Outcome = Literal["success", "failure"]
_EVENT_CODE = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ROUTES = frozenset(
    {
        "/livez",
        "/readyz",
        "/v2/evaluations",
        "/v2/dashboard/summary",
        "/v2/dashboard/decision-volume",
        "/v2/dashboard/action-breakdown",
        "/v2/decisions",
        "/v2/decisions/{trace_id}",
        "/v2/agents/risk",
        "/v2/agents/{agent_id}",
        "/v2/policies",
        "/v2/policies/summary",
        "/v2/integrations/health",
        "/v2/audit-events",
        "/v2/service/status",
    }
)


class Telemetry:
    """Emit only reviewed spans and low-cardinality RED metric dimensions."""

    def __init__(self, *, tracer: trace.Tracer, meter: metrics.Meter) -> None:
        self._tracer = tracer
        self._stage_duration = meter.create_histogram(
            "dusk.pipeline.stage.duration",
            unit="ms",
            description="Duration of an implemented decision-pipeline stage",
        )
        self._request_duration = meter.create_histogram(
            "dusk.http.server.duration", unit="ms", description="HTTP server request duration"
        )
        self._request_count = meter.create_counter(
            "dusk.http.server.requests", unit="{request}", description="HTTP server requests"
        )

    @contextmanager
    def request(self, *, method: str, headers: Mapping[str, str]) -> Iterator[Span]:
        safe_method = method if method in {"GET", "POST"} else "OTHER"
        parent_context = propagate.extract(dict(headers))
        with self._tracer.start_as_current_span(
            "HTTP request",
            context=parent_context,
            kind=trace.SpanKind.SERVER,
            attributes={"http.request.method": safe_method},
        ) as span:
            span.set_attribute("dusk.request.id", get_request_id())
            yield span

    @contextmanager
    def stage(
        self,
        stage: PipelineStage,
        *,
        decision_trace_id: str | None = None,
        decision_id: str | None = None,
        audit_event_id: str | None = None,
        delivery_id: str | None = None,
    ) -> Iterator[None]:
        started = perf_counter()
        outcome: Outcome = "success"
        with self._tracer.start_as_current_span(
            f"dusk.pipeline.{stage}", attributes={"dusk.pipeline.stage": stage}
        ) as span:
            request_id = get_request_id()
            span.set_attribute("dusk.request.id", request_id)
            resolved_trace_id = decision_trace_id or get_decision_trace_id()
            if resolved_trace_id is not None:
                span.set_attribute("dusk.decision.trace_id", resolved_trace_id)
            for key, value in (
                ("dusk.decision.id", decision_id),
                ("dusk.audit.event_id", audit_event_id),
                ("dusk.outbox.delivery_id", delivery_id),
            ):
                if value is not None and len(value) <= 64:
                    span.set_attribute(key, value)
            try:
                yield
            except BaseException:
                outcome = "failure"
                span.set_status(Status(StatusCode.ERROR))
                raise
            finally:
                duration_ms = (perf_counter() - started) * 1000
                span.set_attribute("dusk.outcome", outcome)
                span.set_attribute("dusk.duration_ms", duration_ms)
                self._stage_duration.record(
                    duration_ms, {"dusk.pipeline.stage": stage, "dusk.outcome": outcome}
                )

    def record_request(
        self, *, method: str, route: str, status_code: int, duration_ms: float
    ) -> None:
        safe_method = method if method in {"GET", "POST"} else "OTHER"
        safe_route = route if route in _ROUTES else "unmatched"
        status_class = f"{status_code // 100}xx" if 100 <= status_code <= 599 else "unknown"
        attributes = {
            "http.request.method": safe_method,
            "http.route": safe_route,
            "http.response.status_class": status_class,
        }
        self._request_count.add(1, attributes)
        self._request_duration.record(duration_ms, attributes)
        span = trace.get_current_span()
        span.update_name(f"{safe_method} {safe_route}")
        span.set_attribute("http.route", safe_route)
        span.set_attribute("http.response.status_code", status_code)
        if status_code >= 500:
            span.set_status(Status(StatusCode.ERROR))


class TelemetryRuntime:
    """Telemetry instruments plus owned SDK providers for bounded shutdown."""

    def __init__(
        self,
        telemetry: Telemetry,
        *,
        tracer_provider: TracerProvider | None = None,
        meter_provider: MeterProvider | None = None,
    ) -> None:
        self.telemetry = telemetry
        self._tracer_provider = tracer_provider
        self._meter_provider = meter_provider

    def shutdown(self) -> None:
        if self._meter_provider is not None:
            self._meter_provider.shutdown()
        if self._tracer_provider is not None:
            self._tracer_provider.shutdown()


def build_telemetry(settings: Settings) -> TelemetryRuntime:
    """Build no-op instruments unless bounded OTLP export is explicitly enabled."""
    if not settings.observability_enabled:
        return TelemetryRuntime(
            Telemetry(
                tracer=trace.get_tracer(settings.service_name, settings.service_version),
                meter=metrics.get_meter(settings.service_name, settings.service_version),
            )
        )
    if settings.otlp_endpoint is None:
        raise ValueError("otlp_endpoint is required")
    headers = _parse_headers(settings)
    resource = Resource.create(
        {
            "service.name": settings.service_name,
            "service.version": settings.service_version,
            "deployment.environment.name": settings.environment.value,
        }
    )
    trace_exporter = OTLPSpanExporter(
        endpoint=f"{settings.otlp_endpoint.rstrip('/')}/v1/traces",
        headers=headers,
        timeout=settings.telemetry_export_timeout_ms / 1000,
    )
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(
            trace_exporter,
            max_queue_size=settings.telemetry_queue_size,
            max_export_batch_size=settings.telemetry_batch_size,
            schedule_delay_millis=settings.telemetry_export_interval_ms,
            export_timeout_millis=settings.telemetry_export_timeout_ms,
        )
    )
    metric_exporter = OTLPMetricExporter(
        endpoint=f"{settings.otlp_endpoint.rstrip('/')}/v1/metrics",
        headers=headers,
        timeout=settings.telemetry_export_timeout_ms / 1000,
    )
    metric_reader = PeriodicExportingMetricReader(
        metric_exporter,
        export_interval_millis=settings.telemetry_export_interval_ms,
        export_timeout_millis=settings.telemetry_export_timeout_ms,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=(metric_reader,))
    return TelemetryRuntime(
        Telemetry(
            tracer=tracer_provider.get_tracer(settings.service_name, settings.service_version),
            meter=meter_provider.get_meter(settings.service_name, settings.service_version),
        ),
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
    )


def _parse_headers(settings: Settings) -> dict[str, str]:
    if settings.otlp_headers is None:
        return {}
    try:
        value = json.loads(settings.otlp_headers.get_secret_value())
    except json.JSONDecodeError as exc:
        raise ValueError("otlp_headers must be a JSON object") from exc
    if not isinstance(value, dict) or len(value) > 16:
        raise ValueError("otlp_headers must be a bounded JSON object")
    headers: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not _HEADER_NAME.fullmatch(key)
            or not isinstance(item, str)
            or not 1 <= len(item) <= 1024
            or "\r" in item
            or "\n" in item
        ):
            raise ValueError("otlp_headers contains an invalid entry")
        headers[key] = item
    return headers


class SafeJsonFormatter(logging.Formatter):
    """Emit an allow-listed JSON envelope and never interpolate arbitrary log data."""

    def format(self, record: logging.LogRecord) -> str:
        candidate = getattr(record, "event_code", "unclassified")
        event = (
            candidate
            if isinstance(candidate, str) and _EVENT_CODE.fullmatch(candidate)
            else "unclassified"
        )
        document: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "severity": record.levelname,
            "logger": record.name[:128],
            "event": event,
            "request_id": get_request_id(),
        }
        decision_trace_id = get_decision_trace_id()
        if decision_trace_id is not None:
            document["decision_trace_id"] = decision_trace_id
        span_context = trace.get_current_span().get_span_context()
        if span_context.is_valid:
            document["trace_id"] = trace.format_trace_id(span_context.trace_id)
            document["span_id"] = trace.format_span_id(span_context.span_id)
        return json.dumps(document, sort_keys=True, separators=(",", ":"))


def configure_structured_logging(level: str) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(SafeJsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
