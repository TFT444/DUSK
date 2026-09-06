# ADR 0001: Separate production control plane

- Status: Accepted
- Date: 2026-08-28
- Decision owners: Security and Engineering
- Approval record: Security and Engineering approved by TFT444; API conventions
  approved by TAMIMTFT
- Tracking issue: [#190](https://github.com/ShieldTech-Ltd/DUSK/issues/190)

## Context

DUSK currently ships a Python package, CLI, and a self-contained Flask example.
The example owns `/v1/gate`; it is deliberately not a production, multi-tenant
service. The security operations console needs durable decisions, workload and human
identity, tenant isolation, policy evidence, audit continuity, and operational
read APIs without changing that existing seam.

The authoritative security analysis is the
[production control-plane threat model](../production-control-plane-threat-model.md).
The public interface rules are the
[control-plane API conventions](../control-plane-api-conventions.md).

## Decision

Build an independently deployable FastAPI service. Do not promote or import the
Flask application in `dusk-agent-harness`. Shared evaluation logic
may later move behind application-layer interfaces, but the v1 adapter remains
the compatibility authority.

PostgreSQL is the control plane's system of record. A single transaction commits a
redacted decision, its tenant-scoped audit-chain record, and transactional
outbox intent. SIE is optional enrichment and is never an authorization or
audit store. External webhooks and enforcement brokers are reached only by
bounded outbox workers.

Generic OIDC authenticates every v2 call. Validated claims determine tenant,
principal, and identity kind; request content never does. Workload identities
submit evaluations. Human identities use read-only console APIs under Viewer,
Analyst, Operator, Auditor, or Administrator roles. Policy mutation and approval
workflows are outside the first release.

The first release exposes `POST /v2/evaluations` and tenant-scoped read APIs for
dashboard, decisions, agents, policies, integrations, audit, and service
status. All production metrics come from measured or persisted state. The
console polls every 30 seconds and renders explicit empty, stale, degraded, or
unavailable states.

## Compatibility boundary

`/v1/gate` is frozen: request and response bodies, authentication, status
codes, scoring and rounding, trace behavior, watch/enforce behavior, SIE
fallback, webhook intent, offense memory, health behavior, and downstream
non-execution must not drift. Golden tests are required before shared evaluator
work. Existing package, CLI, examples, and public imports remain supported.

All database migrations use additive expand/contract changes. New routing,
evaluation, workers, and persistence behavior is feature-flagged off by
default. A deployment can roll back its service image and routing while leaving
the compatible schema in place.

## Identity and authorization boundary

Machine and human identities are separate trust classes:

| Identity | Allowed capability | Forbidden capability |
|---|---|---|
| Workload | Submit an evaluation for its claim-derived tenant and permitted agent scope | Console reads, tenant selection, role administration |
| Human | Read resources allowed by its tenant role | Evaluation submission, request-selected tenant, policy mutation at launch |

The service validates issuer, audience, signature algorithm, signature, expiry,
not-before, subject, tenant mapping, identity kind, and required claims. JWKS
rotation has a bounded cache and refresh policy. Missing or unverifiable
identity fails closed.

Object and list authorization always includes tenant scope in the repository
query. Authorization followed by an unscoped lookup is prohibited because it
creates a time-of-check/time-of-use and identifier-enumeration boundary.

## Data classification and retention

| Class | Examples | Storage rule |
|---|---|---|
| Prohibited | Tokens, credentials, prompts, raw requests, unrestricted provider payloads | Never persist or emit to telemetry |
| Restricted | Redacted canonical before/after values, identity subject, decision reasons | Schema validate, size limit, recursively redact, platform encryption at rest, role-project reads |
| Integrity evidence | Input digest, policy version/matches, audit sequence and digest, deletion evidence | Append-only semantics; retain integrity metadata when detail expires |
| Operational | Bounded timings, lifecycle state, integration health, aggregate counts | Tenant qualify where applicable; never synthesize unavailable values |
| Public | API schema, safe policy catalogue fields, service version | Reviewed allow-list only |

Decision detail defaults to 90-day retention. Audit metadata defaults to 365
days. Tenant policy and legal holds may extend retention. Cleanup removes
expired restricted detail without breaking audit-chain verification.

## Evaluation and failure policy

Policy and behavioral results use this precedence:

1. Policy `DENY` returns `BLOCK` in enforce mode or `WOULD-BLOCK` in watch mode.
2. `REQUIRE_APPROVAL` returns `WOULD-BLOCK` with `APPROVAL_REQUIRED`.
3. Degraded required evidence on a consequential action fails closed.
4. Behavioral threshold refusal applies when no stronger policy result exists.
5. Otherwise the result is `ALLOW`.

Consequential v2 evaluation fails closed when identity, required policy,
durable decision/audit commit, or required enforcement acknowledgement is
unavailable. Optional SIE enrichment fails soft and reports degradation. Read
APIs report unavailable or stale state rather than inventing values. Legacy v1
keeps its current failure behavior.

An `ALLOW` is permission to proceed, not evidence of execution. `EXECUTED` may
be recorded only after a trusted broker acknowledgement. Shadow evaluation uses
isolated state and disables persistence effects, webhooks, broker calls, and
offense-memory updates.

## Service boundaries and data flow

```text
workload -> TLS ingress -> OIDC/RBAC -> v2 evaluation -> evaluator -> policy
                                      |                    |          |
                                      |                    +-> SIE (optional)
                                      v
                              PostgreSQL transaction
                         decision + audit link + outbox intent
                                      |
                                      v
                              bounded outbox worker
                              webhook / broker -> acknowledgement

human console -> TLS ingress -> OIDC/RBAC -> tenant-scoped read repository
                                            -> PostgreSQL aggregates/records
```

Trust is re-established at every arrow. Provider evidence is accepted only from
configured sources with source identity, provenance, freshness, and digest.
Outbound destinations are allow-listed and protected against SSRF and DNS
rebinding. Telemetry export receives allow-listed, redacted fields only.

## Deployment and broker boundary

The same signed OCI digest, SBOM, and provenance is promoted through development,
staging, and production. The container runs non-root with a read-only root
filesystem. External OIDC, managed PostgreSQL, secret manager, TLS ingress,
network policies, and autoscaling are deployment dependencies.

The Gate never holds broad provider credentials. An enforcement broker owns the
downstream credential and execution boundary, validates a scoped decision and
delivery identifier, deduplicates requests, and returns an authenticated
acknowledgement. Broker failure cannot be translated into `EXECUTED`.

## Alternatives rejected

- Promoting the Flask example: it couples production identity, persistence, and
  workers to an example boundary and risks v1 drift.
- Using SIE as the decision store: optional semantic enrichment does not provide
  relational transactions, tenant constraints, or authoritative audit evidence.
- Caller-supplied tenant identity: it makes tenant isolation depend on untrusted
  request data.
- Direct webhook delivery in the request transaction: it cannot atomically
  preserve decision evidence and reliable delivery across failures.
- A separate search cluster at launch: PostgreSQL filtering and bounded search
  meet the launch scope with a smaller data-exfiltration surface.

## Consequences

The design adds PostgreSQL, OIDC, migrations, and worker operations, but gives
the platform an explicit durable and tenant-safe boundary. v1 and v2 can evolve
independently. Feature flags, additive migrations, and digest-based promotion
permit routing rollback without destructive schema rollback.

## Approval checklist

- [x] Security owner approves trust boundaries, abuse cases, data classes, and
  fail-closed policy.
- [x] Engineering owner approves service ownership, compatibility boundary,
  migrations, operations, and rollback.
- [x] API reviewers approve the v2 conventions and error/cursor contracts.
- [x] Decisions or exceptions raised in review are linked here before status is
  changed from Proposed to Accepted.

Implementation issues remain blocked on this ADR until both owner approvals are
recorded. Approval must be a named, dated review or pull-request approval; a
checkbox changed by the author is not sufficient.

## Review record

| Role | Reviewer | Date | Decision | Evidence |
|---|---|---|---|---|
| Security owner | TFT444 | 2026-08-28 | Approved | [PR #211][pr-211] |
| Engineering owner | TFT444 | 2026-08-28 | Approved | [PR #211][pr-211] |
| API reviewer | TAMIMTFT | 2026-08-28 | Approved | [PR #209][pr-209] |

[pr-209]: https://github.com/ShieldTech-Ltd/DUSK/pull/209
[pr-211]: https://github.com/ShieldTech-Ltd/DUSK/pull/211
