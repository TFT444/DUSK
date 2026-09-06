# Control-plane observability contract

The production control plane uses OpenTelemetry traces and metrics plus
allow-listed JSON logs. Export is disabled by default and is never a dependency
of an authorization decision, audit commit, or HTTP response.

## Telemetry boundary

Set `DUSK_CP_OBSERVABILITY_ENABLED=true` only with an authenticated HTTPS OTLP
collector. `DUSK_CP_OTLP_HEADERS` is a secret JSON object supplied by the
deployment secret manager. Userinfo, query strings, fragments, clear-text
transport, newline-bearing headers, and unbounded header collections are
rejected at startup.

The SDK uses a bounded batch queue. Queue size, batch size, schedule interval,
and export timeout are validated. When the collector is slow or unavailable,
the SDK drops or retries telemetry within those bounds; request workers do not
perform synchronous exports and evaluation results are unaffected. Shutdown
flushes the owned providers during the service lifecycle.

Telemetry must never contain bearer tokens, cookies, credentials, prompts, raw
actions, evidence payloads, rule conditions, unrestricted provider responses,
or exception text. Span attributes are fixed in code. Metric dimensions are
limited to pipeline stage/outcome or HTTP method, reviewed route template, and
status class. Unknown methods and routes collapse to `OTHER` and `unmatched` to
bound cardinality. JSON logs intentionally omit message interpolation and emit
only severity, logger, reviewed event code, request ID, and decision trace ID.

## Correlation and measured stages

Server-generated request IDs correlate HTTP errors and logs. OpenTelemetry
trace context correlates spans. Once allocated, the decision trace ID is added
to policy, persistence, audit, outbox, and broker-acknowledgement spans. Audit
event, decision, and delivery UUIDs are included only on the relevant spans.

The current application emits real measurements for:

- canonical v2 request-to-policy-context normalization;
- behavioral evaluation;
- policy and trusted-evidence evaluation;
- durable PostgreSQL persistence;
- audit signing;
- HTTP response finalization;
- outbox delivery and verified broker acknowledgement when the worker is active.

Baseline and SIE durations remain `null` until their adapters expose distinct
measured boundaries. They must not be inferred from total time. Evaluation
responses and persisted decision evidence carry the measured normalization,
behavioral, policy, persistence, audit, and total durations. The operational
status API lists only stages instrumented in the active configuration.

## RED metrics and SLO gates

`dusk.http.server.requests` counts request rate and errors by status class.
`dusk.http.server.duration` records request duration in milliseconds.
`dusk.pipeline.stage.duration` records implemented stage duration and outcome.
Dashboard P95 continues to be calculated from persisted `total_ms` values;
telemetry is not an authoritative decision or audit store.

Release evidence uses real staging OIDC, PostgreSQL, service containers, and
approved provider sandboxes. The promotion gate requires:

- API availability of at least 99.9%;
- deterministic evaluation P95 at or below 250 ms;
- enriched evaluation P95 at or below 2 seconds;
- decision-list P95 at or below 500 ms;
- dashboard P95 at or below 1 second;
- no redaction canary, unbounded attribute, audit gap, or correlation gap.

These values are release thresholds, not synthetic production metrics. They
must be calculated from actual staging observations over the approved load and
soak windows. No code path fabricates compliance when samples are absent.

## Rollback

Disable `DUSK_CP_OBSERVABILITY_ENABLED` to stop OTLP export. Local no-op
instruments, health endpoints, decision processing, and durable evidence remain
available. No database migration is introduced by this change.
