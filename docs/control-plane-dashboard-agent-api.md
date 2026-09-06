# Dashboard and agent-risk read API

The dashboard and agent investigation endpoints read authoritative,
tenant-qualified PostgreSQL decisions. They do not generate sample values and
do not fall back to an empty response when PostgreSQL is unavailable. The
feature flag `DUSK_CP_DASHBOARD_READ_API_ENABLED` is disabled by default.

All time boundaries and buckets use UTC. The database clock fixes a snapshot
for each response. Clients should poll again after the returned
`poll_after_seconds` value, currently 30 seconds. `available` means at least
one source record contributed to the response; `empty` means the query
succeeded but no source records matched. A query failure returns the standard
retryable `DASHBOARD_QUERY_UNAVAILABLE` error instead.

## Windows and aggregation definitions

The `window` query parameter is allowlisted to `24h`, `7d`, or `30d`. Its end
is the PostgreSQL snapshot time and its start is exactly the corresponding
duration earlier. Summary comparisons use the immediately preceding window of
equal duration. Records satisfy `created_at >= start AND created_at < end`.

| Field | Source and calculation |
| --- | --- |
| Decisions | `count(*)` |
| Allowed, blocked, would-block | `count(*) FILTER (WHERE verdict = ...)` |
| Active agents | `count(DISTINCT agent_id)` |
| High-risk decisions | Behavioral score greater than or equal to `0.8` |
| Change percent | `(current - previous) / previous * 100`; `null` when the comparison is zero |
| Evaluation latency | PostgreSQL `percentile_cont(0.95)` over numeric `pipeline_timings.total_ms`; sample count is returned |
| Decision volume | Verdict counts grouped by UTC hour for `24h`, otherwise UTC day; only source-populated buckets are returned |
| Action breakdown | Count by redacted canonical `action_type`, ordered by count descending then type ascending; unavailable retained detail is grouped as `unknown` |
| Agent risk score | Maximum behavioral score in the selected window |
| High-risk agent count | Decisions for that agent with behavioral score at least `0.8` |
| First/last seen | Minimum/maximum decision timestamp in the selected window |

Action breakdown is capped at 100 distinct action types. Agent detail returns
the latest 20 persisted decision references. Neither response exposes raw
requests, credentials, prompts, provider payloads, or unrestricted action
data.

## Ranking and pagination

`GET /v2/agents/risk` orders agents by risk score descending, high-risk count
descending, last-seen timestamp descending, and agent ID ascending. Pages use
a versioned HMAC-authenticated cursor bound to the tenant, filters, snapshot,
and complete ordering tuple. Changing the tenant or filters, tampering with a
cursor, or using an unknown cursor version returns `INVALID_CURSOR`.

The stable-page guarantee assumes decision timestamps are immutable and are
assigned from the trusted service/database clock, as they are in the write
path. Records committed after the snapshot have later timestamps and are
visible on the next 30-second poll, not midway through pagination.

## Authorization and rollback

Dashboard routes require a human principal with `dashboard:read`; viewers and
analysts receive the same aggregate projection. Agent routes require
`agent:investigate`, which excludes viewers. Tenant identity always comes from
validated OIDC claims.

Rollback disables `DUSK_CP_DASHBOARD_READ_API_ENABLED`. No source data or
schema is removed. The existing aggregate tables remain reserved for a future
transactional refresh job; they are not read until freshness and recovery can
be proven against source decisions.

The launch performance gate is p95 at or below one second for dashboard reads
using the approved staging dataset and deployment topology. The PostgreSQL
integration suite provides a pre-merge regression gate over persisted data;
it is not presented as production telemetry.
