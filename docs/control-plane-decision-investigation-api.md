# Decision investigation API

## Security and authorization boundary

`GET /v2/decisions` and `GET /v2/decisions/{trace_id}` are disabled by default.
They require human OIDC identities, and the tenant is always derived from the
validated token. Request headers, query parameters, and bodies cannot select a
tenant.

- `viewer`, `analyst`, and `operator` may read decision summaries.
- `analyst` and `operator` may read full investigation detail.
- `auditor` uses the immutable audit and policy-evidence APIs; it does not gain
  decision-detail access through these routes.
- `administrator` does not implicitly gain investigation access. Administrative
  and investigative duties remain separated.

Cross-tenant object lookup returns the same `DECISION_NOT_FOUND` response as an
unknown trace identifier. Responses come only from PostgreSQL; the service does
not generate synthetic decisions or substitute fallback records.

## List contract

`GET /v2/decisions` accepts only these query parameters:

| Parameter | Meaning |
|---|---|
| `limit` | Page size from 1 to 100; default 50 |
| `cursor` | Opaque, authenticated continuation cursor |
| `created_from`, `created_to` | Inclusive ISO 8601 UTC bounds |
| `verdict` | `ALLOW`, `WOULD-BLOCK`, or `BLOCK` |
| `policy_decision` | `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, or `NOT_APPLICABLE` |
| `response_status` | Persisted delivery/execution lifecycle state |
| `evidence_degraded` | Exact boolean evidence-state filter |
| `agent_id` | Exact, case-sensitive agent identifier |
| `action_type` | Exact canonical action type |
| `search` | Up to 100 characters of PostgreSQL full-text search, or an exact trace UUID |

Unknown parameters, non-UTC timestamps, reversed ranges, invalid enum values,
oversized inputs, and control characters are rejected with the standardized
validation envelope.

Results are sorted by `(created_at DESC, decision_id DESC)`. The decision ID is
an internal tie-breaker and is not exposed. The first page records PostgreSQL's
transaction clock as `snapshot_at`; continuation pages exclude decisions newer
than that boundary and use keyset pagination. Under the documented consistency
model, decision identities and creation timestamps are immutable and newly
appended decisions cannot cause duplicates or omissions in an active traversal.
Mutable lifecycle/filter fields reflect committed state at each request, so a
client requiring a fresh lifecycle view starts a new traversal.

Cursors are versioned, base64url encoded, HMAC authenticated, and bound to the
claim-derived tenant plus the exact filter set. Page size may change between
requests. Reusing a cursor under another tenant or filter, modifying it, or
presenting an unsupported version returns `INVALID_CURSOR`.

## Detail and redaction

The detail response contains the persisted redacted canonical action and input
digest, decision reasons, MITRE mappings, predicted action, policy-pack version,
safe policy matches, evidence-degradation state, measured pipeline timings,
response lifecycle, audit-chain continuity, and up to five recent persisted
decisions with the same agent or action type.

Only allow-listed canonical action fields are projected. Credentials, tokens,
prompts, raw requests, provider payloads, unrestricted response bodies, and
idempotency keys are never returned. When retention has removed investigation
detail, `detail_available` is false, nullable detail fields remain null, and the
decision identity and audit continuity remain available.

## PostgreSQL execution and SLO evidence

Keyset traversal uses the tenant/creation index. Exact verdict, agent, policy,
and lifecycle filters use tenant-leading indexes. Search uses immutable
`simple`-configuration `tsvector` GIN indexes over the persisted agent identifier
and redacted canonical action. Queries remain bounded by a page size of 100 and
the database statement timeout.

The launch gate is list-read p95 at or below 500 ms against the approved launch
dataset under representative concurrency. CI proves query correctness and
index presence; staging records the authoritative load-test percentile from
real PostgreSQL. No latency value is synthesized when that measurement is
unavailable.

## Activation and rollback

Set all of the following through deployment configuration and the secret
manager: `DUSK_CP_V2_ENABLED=true`, `DUSK_CP_STORAGE_ENABLED=true`,
`DUSK_CP_DECISION_READ_API_ENABLED=true`, and a consistent
`DUSK_CP_DECISION_CURSOR_SIGNING_KEY` of at least 32 characters. Apply migration
`20260902_0004` before activation.

To roll back, disable the decision read API before reverting the application.
The migration adds indexes only; dropping them does not alter stored decisions.
Existing cursors become invalid after signing-key rotation or endpoint rollback,
which is an intentional safe failure.
