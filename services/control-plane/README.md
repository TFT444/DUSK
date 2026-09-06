# DUSK production control plane

Cloud-neutral container, Helm, image-admission, promotion, and rollback
instructions are documented in
[`docs/control-plane-deployment.md`](../../docs/control-plane-deployment.md).
They can be validated locally without AWS, Azure, or managed Kubernetes
accounts; live-provider qualification remains deferred to issue #251.

This directory contains the independently deployable FastAPI service. It does
not import or run the Flask application in `dusk-agent-harness`, and
it does not expose `/v1/gate`. Operational endpoints are always available. The
authenticated v2 evaluation route is registered only when its feature flag is
enabled and fails closed until a policy/evaluation service with live evidence,
PostgreSQL, and managed audit-signing prerequisites is activated.

When separately activated, the PostgreSQL-backed decision investigation API
provides tenant-scoped `GET /v2/decisions` and
`GET /v2/decisions/{trace_id}`. Its filters, pagination consistency,
authorization projections, and redaction contract are documented in
[`docs/control-plane-decision-investigation-api.md`](../../docs/control-plane-decision-investigation-api.md).

## Local development

```bash
python -m pip install -e './services/control-plane[dev]'
DUSK_CP_API_DOCS_ENABLED=true dusk-control-plane
```

The process binds to `127.0.0.1:8080` by default. The local Compose service is
disabled unless its explicit profile is selected:

```bash
docker compose -f services/control-plane/compose.yml \
  --profile control-plane up --build
```

Operational routes:

- `GET /livez`: process lifecycle only; never checks external dependencies.
- `GET /readyz`: bounded checks for registered critical dependencies.
- `GET /openapi.json`: available only when `DUSK_CP_API_DOCS_ENABLED=true`.

Every response receives a server-generated `X-Request-ID`. Error bodies contain
only a stable code, safe message, request ID, and retryability. API documentation
is disabled by default and cannot be enabled in staging or production.

## Configuration

All settings use the `DUSK_CP_` prefix. Unknown variables are ignored so other
DUSK components can share the process environment safely; malformed recognized
settings fail startup.

| Variable | Default | Constraint |
|---|---|---|
| `DUSK_CP_ENVIRONMENT` | `local` | `local`, `test`, `development`, `staging`, or `production` |
| `DUSK_CP_HOST` | `127.0.0.1` | Non-empty host passed to Uvicorn |
| `DUSK_CP_PORT` | `8080` | `1..65535` |
| `DUSK_CP_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` |
| `DUSK_CP_API_DOCS_ENABLED` | `false` | Forbidden in staging and production |
| `DUSK_CP_V2_ENABLED` | `false` | Registers authenticated v2 routing; evaluation requires an activated service |
| `DUSK_CP_READINESS_TIMEOUT_MS` | `1000` | `50..5000` per probe |
| `DUSK_CP_MAX_REQUEST_BODY_BYTES` | `1048576` | `1024..10485760` |

When `DUSK_CP_V2_ENABLED=true`, the service requires `DUSK_CP_OIDC_ISSUER`,
`DUSK_CP_OIDC_AUDIENCE`, and `DUSK_CP_OIDC_JWKS_URI`. Issuer and JWKS values must
use HTTPS. Cache, timeout, token-size, JWKS-size, clock-skew, maximum-token-age,
claim-name, and algorithm controls use the corresponding `DUSK_CP_OIDC_*`
settings and have validated safe bounds. The complete claim and route contract is
documented in
[`docs/control-plane-identity-authorization.md`](../../docs/control-plane-identity-authorization.md).

| OIDC variable | Default | Constraint |
|---|---|---|
| `DUSK_CP_OIDC_ISSUER` | unset | Required for v2; exact HTTPS issuer without credentials, query, or fragment |
| `DUSK_CP_OIDC_AUDIENCE` | unset | Required for v2; exact API audience |
| `DUSK_CP_OIDC_JWKS_URI` | unset | Required for v2; HTTPS endpoint without credentials or fragment |
| `DUSK_CP_OIDC_ALGORITHMS` | `["RS256"]` | Non-empty, unique JSON array of supported asymmetric algorithms |
| `DUSK_CP_OIDC_TENANT_CLAIM` | `dusk_tenant_id` | Bounded custom claim name |
| `DUSK_CP_OIDC_IDENTITY_KIND_CLAIM` | `dusk_identity_kind` | Bounded custom claim name |
| `DUSK_CP_OIDC_ROLES_CLAIM` | `dusk_roles` | Bounded custom claim name |
| `DUSK_CP_OIDC_WORKLOAD_CLAIM` | `dusk_workload_id` | Bounded custom claim name; all four custom names must be distinct |
| `DUSK_CP_OIDC_CLOCK_SKEW_SECONDS` | `30` | `0..120` |
| `DUSK_CP_OIDC_MAX_TOKEN_AGE_SECONDS` | `3600` | `60..86400` |
| `DUSK_CP_OIDC_JWKS_TTL_SECONDS` | `300` | `30..900`; stale keys are never used after expiry |
| `DUSK_CP_OIDC_JWKS_MIN_REFRESH_SECONDS` | `5` | `1..60`; bounds repeated unknown-key refreshes |
| `DUSK_CP_OIDC_HTTP_TIMEOUT_SECONDS` | `2.0` | `0.1..10.0` |
| `DUSK_CP_OIDC_MAX_JWKS_BYTES` | `262144` | `1024..1048576` |
| `DUSK_CP_OIDC_MAX_JWKS_KEYS` | `32` | `1..128` |
| `DUSK_CP_OIDC_MAX_TOKEN_BYTES` | `16384` | `1024..65536` |

## PostgreSQL storage

PostgreSQL is disabled by default. When `DUSK_CP_STORAGE_ENABLED=true`,
`DUSK_CP_DATABASE_URL` is required and must use the
`postgresql+asyncpg://` SQLAlchemy dialect. The URL is treated as a secret and
must come from the deployment secret manager. SQL parameters are hidden from
engine diagnostics. Pool size, overflow, queue timeout, and statement timeout
are bounded by the corresponding `DUSK_CP_DATABASE_*` settings.

| Storage variable | Default | Constraint |
|---|---|---|
| `DUSK_CP_STORAGE_ENABLED` | `false` | Requires a database URL when enabled |
| `DUSK_CP_DATABASE_URL` | unset | Secret `postgresql+asyncpg://` URL |
| `DUSK_CP_DATABASE_POOL_SIZE` | `10` | `1..100` persistent connections per process |
| `DUSK_CP_DATABASE_MAX_OVERFLOW` | `10` | `0..100` temporary overflow connections |
| `DUSK_CP_DATABASE_POOL_TIMEOUT_SECONDS` | `5.0` | `0.1..30.0` for pool and connection acquisition |
| `DUSK_CP_DATABASE_STATEMENT_TIMEOUT_MS` | `5000` | `100..60000` server-enforced statement timeout |
| `DUSK_CP_EVALUATION_TIMEOUT_SECONDS` | `10` | `0.1..30` fail-closed end-to-end v2 evaluation deadline |
| `DUSK_CP_DECISION_READ_API_ENABLED` | `false` | Requires v2, PostgreSQL, and a cursor-signing key |
| `DUSK_CP_DASHBOARD_READ_API_ENABLED` | `false` | Requires v2, PostgreSQL, and a cursor-signing key |
| `DUSK_CP_OPERATIONS_READ_API_ENABLED` | `false` | Requires v2, PostgreSQL, an active policy pack, and a cursor-signing key |
| `DUSK_CP_INTEGRATION_HEALTH_STALE_AFTER_SECONDS` | `120` | `30..3600`; older measurements are reported as stale |
| `DUSK_CP_OBSERVABILITY_ENABLED` | `false` | Requires an authenticated HTTPS OTLP endpoint when enabled |
| `DUSK_CP_OTLP_ENDPOINT` | unset | HTTPS collector base URL without credentials, query, or fragment |
| `DUSK_CP_OTLP_HEADERS` | unset | Secret bounded JSON object containing collector authentication headers |
| `DUSK_CP_TELEMETRY_QUEUE_SIZE` | `2048` | `128..16384` queued records |
| `DUSK_CP_TELEMETRY_BATCH_SIZE` | `256` | `1..2048` and no greater than queue size |
| `DUSK_CP_TELEMETRY_EXPORT_INTERVAL_MS` | `5000` | `1000..60000` |
| `DUSK_CP_TELEMETRY_EXPORT_TIMEOUT_MS` | `1000` | `100..10000` |
| `DUSK_CP_PRIVACY_LIFECYCLE_ENABLED` | `false` | Enables injected retention and controlled-export services; requires v2, PostgreSQL, and an audit signer |
| `DUSK_CP_RETENTION_BATCH_SIZE` | `100` | Maximum records per cleanup transaction; `1..500` |
| `DUSK_CP_DECISION_CURSOR_SIGNING_KEY` | unset | Secret with at least 32 characters; rotate only after existing cursors expire |

The decision investigation API is separately activated with
`DUSK_CP_DECISION_READ_API_ENABLED=true`. Its opaque cursors are authenticated
with `DUSK_CP_DECISION_CURSOR_SIGNING_KEY`; supply that value from the deployment
secret manager and keep it consistent across replicas.

The policy catalogue and operational-state API is separately activated with
`DUSK_CP_OPERATIONS_READ_API_ENABLED=true`. It exposes the active policy-pack
version and lifecycle counts to auditors, and tenant-scoped integration and
service status to operators. Component health is based on live database checks
or persisted collector measurements. Missing collectors are reported as
`unmeasured`, stale records as `stale`, and stored diagnostics are suppressed
unless their code is explicitly allow-listed. Disabling the flag removes these
routes without changing the schema or the `/v1/gate` compatibility boundary.
The complete response, authorization, freshness, and rollback contract is in
[`docs/control-plane-policy-operations-api.md`](../../docs/control-plane-policy-operations-api.md).

OpenTelemetry export and structured JSON logging are documented in
[`docs/control-plane-observability.md`](../../docs/control-plane-observability.md),
including the telemetry threat boundary, fixed metric dimensions, measured
pipeline stages, exporter backpressure behavior, and staging SLO gates.

Retention enforcement, legal holds, signed deletion evidence, controlled
administrative export, and restore constraints are documented in
[`docs/control-plane-data-lifecycle.md`](../../docs/control-plane-data-lifecycle.md).

Transactional outbox workers are separately disabled by default. Enabling them
requires storage plus injected destination, credential, DNS, pinned transport,
and acknowledgement-verification dependencies.

| Outbox variable | Default | Constraint |
|---|---|---|
| `DUSK_CP_OUTBOX_WORKER_ENABLED` | `false` | Requires PostgreSQL and an injected worker |
| `DUSK_CP_OUTBOX_BATCH_SIZE` | `20` | `1..200` rows claimed per transaction |
| `DUSK_CP_OUTBOX_MAX_CONCURRENCY` | `4` | `1..32` and no greater than batch size |
| `DUSK_CP_OUTBOX_POLL_INTERVAL_SECONDS` | `1.0` | `0.1..60.0` |
| `DUSK_CP_OUTBOX_LEASE_SECONDS` | `30` | `5..600` and longer than the bounded external attempt |
| `DUSK_CP_OUTBOX_CONNECT_TIMEOUT_SECONDS` | `3.0` | `0.1..10.0` |
| `DUSK_CP_OUTBOX_RESPONSE_TIMEOUT_SECONDS` | `5.0` | `0.1..30.0` |
| `DUSK_CP_OUTBOX_RETRY_BASE_SECONDS` | `1.0` | `0.1..60.0` |
| `DUSK_CP_OUTBOX_RETRY_MAX_SECONDS` | `300.0` | `1.0..3600.0` and at least retry base |
| `DUSK_CP_OUTBOX_ACKNOWLEDGEMENT_MAX_AGE_SECONDS` | `300` | `30..3600` |
| `DUSK_CP_ENFORCEMENT_BROKER_ENABLED` | `false` | Requires v2, PostgreSQL, and the outbox worker |
| `DUSK_CP_ENFORCEMENT_BROKER_DESTINATION_KEY` | `provider-enforcement-broker` | Trusted registry key; never a request-controlled URL |

When broker routing is enabled, only an `ALLOW` decision creates an
`ACTION_EXECUTION` intent for the credential-holding broker. `BLOCK` and
`WOULD-BLOCK` decisions create only `DECISION_RECORDED` webhook intents. The
broker receives the action digest, decision identity, audit sequence, and trace
identity; it does not receive provider credentials through the control plane.
An action is reported as `EXECUTED` only after a fresh, cryptographically
verified broker acknowledgement bound to the tenant, decision, and delivery.

Start the pinned local PostgreSQL profile and apply the schema with:

```bash
docker compose -f services/control-plane/compose.yml --profile storage up -d
export DUSK_CP_DATABASE_URL='postgresql+asyncpg://dusk_control_plane:local-development-only@127.0.0.1:5432/dusk_control_plane'
alembic -c services/control-plane/alembic.ini upgrade head
```

Migrations are additive during forward deployment and run inside PostgreSQL's
transactional DDL boundary. The service image includes the immutable migration
history. Rollback is explicit:

```bash
alembic -c services/control-plane/alembic.ini downgrade -1
```

The baseline schema stores tenant-qualified principals and roles, redacted
canonical actions, decisions, policy matches, tamper-evident audit metadata,
integration health, transactional outbox deliveries, agent-risk rollups, and
dashboard aggregates. Durable provider-evidence nonce claims prevent replay
across replicas without retaining provider payloads. It does not store raw requests, tokens, credentials,
prompts, or unrestricted provider payloads. Decision details can be tombstoned
without deleting decision identity or audit-integrity metadata.

The dashboard and agent-risk read API is separately controlled by
`DUSK_CP_DASHBOARD_READ_API_ENABLED` and remains disabled by default. When
enabled with v2, PostgreSQL, and the cursor signing key, it exposes
tenant-qualified summaries, UTC decision volume, action breakdown, and analyst
agent investigation views. Metric definitions, freshness semantics, and
rollback are documented in
[`docs/control-plane-dashboard-agent-api.md`](../../docs/control-plane-dashboard-agent-api.md).

Consequential v2 activation additionally requires an `AuditSigner` backed by a
managed KMS or HSM key. The application wraps the policy evaluator with the
durable evidence boundary only when both PostgreSQL and the signer are injected;
otherwise `/v2/evaluations` remains fail closed. The canonical transaction,
signature, checkpoint, redaction, verification, and rollback contract is
documented in
[`docs/control-plane-audit-evidence.md`](../../docs/control-plane-audit-evidence.md).
Reliable delivery, SSRF enforcement, retry, lease, deduplication, and broker
acknowledgement semantics are documented in
[`docs/control-plane-outbox-delivery.md`](../../docs/control-plane-outbox-delivery.md).
The failure matrix, bounded recovery objectives, fault-injection evidence, and
operator recovery procedure are documented in
[`docs/control-plane-resilience.md`](../../docs/control-plane-resilience.md).

CloudTrail, Azure Activity Log, and Kubernetes AdmissionReview normalization is
strict and extracts only canonical policy fields. Production collectors sign
each domain envelope with a provisioned Ed25519 key. The control plane verifies
the signature, active key ID, source/domain allow-list, authenticated tenant,
payload digest, freshness, and durable nonce before policy evaluation. Every v2
evidence envelope therefore requires `tenant_id`, `key_id`, `nonce`, and
`signature`; caller-asserted trust markers remain prohibited. Provider field
mappings and launch certification requirements are documented in
[`docs/provider-certification.md`](../../docs/provider-certification.md).
