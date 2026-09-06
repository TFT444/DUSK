# Production control-plane threat model

This document covers the planned multi-tenant FastAPI service described by
[ADR 0001](adr/0001-production-control-plane.md). It does not describe these
controls as shipped. The existing package and Flask example remain covered by
the project [threat model](threat-model.md).

## Security objectives

1. A principal can see or affect only its claim-derived tenant and allowed role.
2. A consequential action cannot proceed without verified identity, required
   evidence and policy, durable audit evidence, and required broker acknowledgement.
3. Sensitive input does not enter persistence, telemetry, errors, or outbound
   diagnostics outside its reviewed redacted schema.
4. Every authoritative decision is traceable to policy/evidence and a
   tamper-evident audit record.
5. Failure and recovery do not create cross-tenant access, duplicate execution,
   lost audit evidence, or an invented lifecycle state.
6. The frozen v1 behavior is not weakened or silently changed.

## Assets

- Tenant boundary and role assignments.
- OIDC configuration, JWKS trust, and workload/human identity claims.
- Canonical actions, input digests, decisions, policy matches, and evidence state.
- Audit sequence/digests and deletion evidence.
- Outbox intents, delivery identifiers, and broker acknowledgements.
- Policy packs and activation prerequisites.
- Database, signing, broker, webhook, and telemetry credentials.
- Availability and integrity of evaluation and read APIs.

## Actors and assumptions

| Actor | Trust level | Assumption |
|---|---|---|
| Workload client | Untrusted request producer, authenticated identity | It may be compromised and may replay or manipulate actions/evidence |
| Human console user | Authenticated but least privilege | It may attempt role escalation or cross-tenant inference |
| OIDC provider | Configured identity authority | Keys rotate; provider and network can be unavailable |
| Evidence provider/adapter | Trusted only for configured evidence domains | Provenance, source identity, freshness, and digest are verified |
| SIE | Optional, untrusted enrichment output | It can time out or return malformed/adversarial content |
| Policy pack/runtime | Authorization input | Version and activation prerequisites are verified |
| PostgreSQL | Authoritative durable store | Platform encryption/backups and least-privilege access are configured |
| Outbox worker | Privileged delivery component | It has bounded egress and no authority to rewrite decisions |
| Enforcement broker | Downstream execution authority | It authenticates scoped delivery and returns signed/trusted acknowledgement |
| Telemetry backend | Operational data recipient | It receives allow-listed redacted data and can be unavailable |

Cloud administrators and database operators remain privileged platform actors;
separation of duties, managed-service audit, backup access, and key management
are deployment controls rather than application authorization.

## Data flows and trust boundaries

### Evaluation path

1. TLS ingress applies request-size, rate, and concurrency limits.
2. OIDC validation establishes issuer, audience, subject, identity kind, and
   tenant. Failure stops the request.
3. The API schema validates and bounds canonical action and evidence envelopes.
4. The redaction boundary creates the only persistable action representation
   and computes the digest over canonical input.
5. The evaluator calculates deterministic behavioral signals; SIE may add
   explicitly degraded optional enrichment.
6. The policy engine consumes only verified evidence and applies fixed precedence.
7. One PostgreSQL transaction writes decision, audit sequence/digest, and outbox
   intent. Consequential evaluation cannot succeed if it does not commit.
8. A bounded worker validates the destination and delivers by stable ID.
9. Only an authenticated broker acknowledgement advances lifecycle to `EXECUTED`.

### Console read path

1. TLS ingress and OIDC establish a human identity and tenant.
2. Route authorization establishes the minimum role.
3. The repository includes tenant scope in the SQL query and selects a
   role-specific redacted projection.
4. Lists use bounded filters, UTC ranges, stable sort, and opaque versioned cursors.
5. Dashboard and health responses expose measured freshness and explicit
   empty/degraded/unavailable state.

### Retention path

1. A tenant-scoped bounded job selects expired records using the configured UTC
   policy and legal-hold predicate.
2. Restricted detail is removed or tombstoned in a transaction.
3. Audit integrity metadata and deletion evidence remain verifiable.
4. Exports pass through the same tenant, role, schema, size, and redaction boundaries.

## Abuse cases and required mitigations

| ID | Abuse case | Boundary at risk | Required mitigation | Verification evidence |
|---|---|---|---|---|
| TM-01 | Caller supplies another tenant in body, query, header, or object ID | Identity/repository | Ignore request tenant; claim-derived scope in every query and cache key | Cross-tenant object/list/filter tests |
| TM-02 | Viewer escalates role or calls workload endpoint | OIDC/RBAC | Server-owned role mapping; identity-kind and minimum-role checks per route | Full authorization matrix |
| TM-03 | Forged, expired, wrong-audience, or algorithm-confused token | OIDC/JWKS | Pin issuer/audience/algorithms; verify signature and time claims | Negative token suite with real OIDC staging |
| TM-04 | Stale JWKS accepts revoked key or outage bypasses auth | OIDC/JWKS | Bounded cache/refresh; fail closed; no unverified fallback | Rotation, stale-key, outage tests |
| TM-05 | Replay creates duplicate decisions or execution | API/storage/broker | Tenant-scoped idempotency key and stable delivery ID; broker deduplication | Concurrent duplicate/recovery tests |
| TM-06 | Caller fabricates fresh policy evidence | Evidence/policy | Configured source identity, provenance, freshness, digest, and domain allow-list | Forged/stale/domain-confusion tests |
| TM-07 | Required evidence or policy is unavailable | Policy | Fixed precedence; consequential action fails closed and records safe degradation | Failure truth-table tests |
| TM-08 | SIE times out or injects malformed/hostile output | Enrichment | Treat as optional untrusted data; validate/size bound; deterministic fallback | Timeout/malformed/redaction tests |
| TM-09 | Secret is nested in before/after or provider payload | Redaction/persistence | Strict schema, byte/depth limits, recursive key/value redaction; prohibit raw storage | Nested/encoded/oversize regression corpus |
| TM-10 | Database commits decision without audit/outbox, or vice versa | Transaction | Single transaction and constraints; fail consequential request closed | Failure injection at each write boundary |
| TM-11 | Audit rows are changed, deleted, reordered, or spliced across tenants | Audit | Tenant chain sequence and cryptographic digest over canonical metadata | Offline verifier and tamper cases |
| TM-12 | Webhook URL reaches loopback, metadata, private service, or changes after DNS check | Worker egress | Scheme/host allow-list, resolve-and-connect policy, network egress controls, redirect denial | SSRF/DNS-rebinding tests |
| TM-13 | Forged broker response claims execution | Broker | Mutual/trusted authentication, decision/delivery binding, replay protection | Forged/mismatched acknowledgement tests |
| TM-14 | Gate `ALLOW` is displayed as executed | Lifecycle | Separate decision from response status; only broker acknowledgement sets `EXECUTED` | Lifecycle state-machine tests |
| TM-15 | Shadow evaluation triggers webhook, memory, broker, or durable effects | Shadow | Isolated ports/state and side-effect-disabled execution context | Side-effect canaries and store assertions |
| TM-16 | Cursor/filter/search reveals another tenant or permits resource exhaustion | Read API | Signed/versioned opaque cursor, allow-listed bounded filters, tenant SQL predicate, statement timeout | Fuzz, isolation, and load tests |
| TM-17 | Aggregate/cache key omits tenant or returns invented fallback metric | Dashboard | Tenant-qualified key/query; measured freshness; explicit unavailable/empty state | Canary tenants and source-query reconciliation |
| TM-18 | Logs/traces/errors export secrets or high-cardinality attacker fields | Telemetry | Field allow-list, recursive redaction, truncation, cardinality budgets, safe errors | Secret canaries and exporter inspection |
| TM-19 | Cleanup deletes legal hold or breaks the audit chain | Retention | Hold predicate, bounded resumable batches, preserved integrity metadata/deletion proof | Hold/clock/crash/retry verifier tests |
| TM-20 | Migration interruption or rollback makes old service unsafe | Deployment/schema | Expand/contract, mixed-version tests, migration lock, backward-compatible rollback | Upgrade/interruption/rollback drill |
| TM-21 | Outbox saturation exhausts API workers or loses delivery | Worker | Bounded pools/queues, backpressure, retries with jitter, dead letter, metrics | Saturation/soak/crash tests |
| TM-22 | Compromised build or configuration changes trust roots | Supply chain/deploy | Signed digest, SBOM/provenance, admission verification, secret manager, reviewed config | Promotion/signature/config evidence |
| TM-23 | v2 refactor changes v1 auth, verdict, rounding, or side effects | Compatibility | Golden parity gate and separate adapters/routes | Byte parity with documented normalization |

## Failure policy matrix

| Failure | Consequential v2 evaluation | Non-consequential v2 evaluation | Read API | Legacy v1 |
|---|---|---|---|---|
| Identity unverifiable | Fail closed | Fail closed | Deny | Existing behavior |
| Required policy/evidence unavailable | Fail closed | Apply documented policy; expose degradation | N/A | Existing behavior |
| PostgreSQL/audit commit unavailable | Fail closed | Return retryable failure; do not claim durable decision | Explicit unavailable | Existing behavior |
| Required broker acknowledgement unavailable | Do not claim execution; fail/hold per policy | Do not claim execution | Show measured pending/failed state | Existing behavior |
| SIE unavailable | Deterministic evaluation with degradation unless policy requires evidence | Deterministic evaluation with degradation | Similarity unavailable explicitly | Existing fallback |
| Telemetry exporter unavailable | Continue with bounded loss/buffering; no auth bypass | Same | Same | Existing behavior |
| Outbox saturated | Preserve committed intent; apply bounded backpressure | Same | Show measured degradation | Existing behavior |

Exact HTTP status and retryability are specified by the
[API conventions](control-plane-api-conventions.md); no failure path returns a
successful durable or executed state when the corresponding evidence is absent.

## Residual risks and exclusions

- A fully privileged platform/database administrator may subvert application
  controls; platform separation of duties and managed audit are required.
- DUSK authorizes a proposed action but cannot prove provider-side execution
  semantics without a trusted broker/adapter acknowledgement.
- Behavioral scoring can have false positives or negatives; policy precedence,
  watch mode, explainability, and staged evidence reduce but do not eliminate them.
- Console mutation, policy editing, human approval execution, quarantine, and
  release are excluded from the first read-only release and must receive a new
  threat-model review before introduction.

## Review record

| Role | Reviewer | Date | Decision | Evidence |
|---|---|---|---|---|
| Security owner | Pending | — | Pending | Link to review/PR approval |
| Engineering owner | Pending | — | Pending | Link to review/PR approval |

The author must not fill the approval rows on a reviewer's behalf.
