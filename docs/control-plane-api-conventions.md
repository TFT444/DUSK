# Control-plane API conventions

These conventions govern the planned `/v2` FastAPI service. They do not change
the frozen `/v1/gate` contract in
`dusk-agent-harness/contracts/gate.openapi.yaml`.

## Identity and authorization

- Bearer tokens are validated against configured generic OIDC issuer, audience,
  signing algorithms, JWKS, time claims, and required identity claims.
- Tenant and principal always come from validated claims. A tenant-like request
  field is invalid or ignored as data; it never selects authorization scope.
- `POST /v2/evaluations` requires a workload identity. Console reads require a
  human identity and the documented minimum role.
- Viewer reads dashboard and decision summaries. Analyst reads full decisions,
  agents, and investigative audit views. Operator adds operational status.
  Auditor reads immutable audit and policy evidence. Administrator adds tenant
  and role administration; policy mutation is not in the launch API.

## Resources

```text
POST /v2/evaluations
GET  /v2/dashboard/summary
GET  /v2/dashboard/decision-volume
GET  /v2/dashboard/action-breakdown
GET  /v2/decisions
GET  /v2/decisions/{trace_id}
GET  /v2/agents/risk
GET  /v2/agents/{agent_id}
GET  /v2/policies
GET  /v2/policies/summary
GET  /v2/integrations/health
GET  /v2/audit-events
GET  /v2/service/status
```

The reviewed OpenAPI document is authoritative once the service scaffold lands.
Generated client types must come from it.

## Evaluation request and response

An evaluation request contains a bounded canonical action, trusted-evidence
envelopes, provenance/freshness/source/digest metadata, and an idempotency key.
It cannot select tenant or principal. The response contains trace ID, verdict,
behavioral score, blast radius, safe reasons and MITRE mappings, predicted next
action, policy result and pack version, safe matched rules, evidence degradation,
response lifecycle, genuine stage timings, and similar-decision references.

Idempotency is scoped to the authenticated tenant. Reuse with the same canonical
digest returns the original authoritative result; reuse with different input is
a conflict. An `ALLOW` decision is not an `EXECUTED` lifecycle state.

## Errors and request IDs

Every response carries a server-generated request ID. An error body has exactly
this stable top-level shape:

```json
{
  "error": {
    "code": "SAFE_STABLE_CODE",
    "message": "Safe description without internal detail",
    "request_id": "01J...",
    "retryable": false
  }
}
```

Codes are stable, documented identifiers. Messages must not contain tokens,
claims, SQL, stack traces, provider payloads, internal hostnames, or policy
secrets. Retryability describes whether retrying the same operation is safe and
potentially useful; it is not inferred solely from status class.

Use standard HTTP semantics: 400 invalid syntax/schema/filter, 401 absent or
invalid identity, 403 insufficient identity kind/role, 404 tenant-scoped object
not found (including objects in another tenant), 409 idempotency conflict, 422
well-formed but semantically invalid evidence, 429 bounded rate/concurrency,
503 unavailable required dependency, and 504 bounded upstream timeout. The
OpenAPI document defines the exact operation mappings.

## Time, sorting, filtering, and pagination

- Timestamps are RFC 3339 UTC instants. Inputs with offsets are normalized to
  UTC; naive timestamps are rejected.
- Time ranges use inclusive `from` and exclusive `to`, with a documented maximum
  window and default.
- Each endpoint has an explicit allow-list of typed filters. Unknown filters are
  rejected. Search input and result counts are bounded.
- Lists use stable descending event time plus an immutable unique tie-breaker.
- Cursors are opaque, versioned, integrity-protected, tenant/filter-bound, and
  expire after a documented interval. They are never raw offsets or IDs.
- Responses expose `items`, `next_cursor`, and measured `as_of` time. Empty
  `items` is distinct from unavailable data.

## State and freshness

Dashboard clients poll every 30 seconds. APIs return measured `as_of` and, where
applicable, freshness/health state: `current`, `stale`, `degraded`, or
`unavailable`. They never substitute sample, cached-from-another-tenant,
hard-coded, or randomly generated data. A genuinely empty result is `empty`,
not `unavailable`.

Lifecycle state is based on recorded events. At minimum it distinguishes the
evaluation decision, durable persistence, delivery pending/retrying/dead-letter,
broker acknowledged execution, and confirmed failure. Only an authenticated,
decision-bound broker acknowledgement may establish execution.

## Compatibility and versioning

- `/v1/gate` remains governed by its frozen OpenAPI and golden parity tests.
- v2 changes are additive within the version. Removing or changing field
  meaning requires a new API version and coordinated client migration.
- Database and cursor formats carry explicit versions; deployments tolerate the
  previous service version during rollback.
- Feature flags default off. Shadow traffic is not observable as an authoritative
  decision and cannot trigger durable or external side effects.
