# Control-plane data lifecycle and compliance export

## Scope and security boundary

The data-lifecycle service enforces tenant-specific retention for restricted
decision detail and audit-event sensitive detail. PostgreSQL remains the system
of record. A scheduler may invoke `RetentionService.run_once` only after the
`DUSK_CP_PRIVACY_LIFECYCLE_ENABLED` deployment flag is enabled and the same
production database and audit signer used by decision persistence are injected.
The service accepts a validated human administrator principal rather than a
tenant identifier and derives its tenant scope exclusively from that identity.

Cleanup crosses confidentiality, availability, and compliance boundaries. Each
transaction locks the tenant policy before checking legal hold, uses PostgreSQL
`clock_timestamp()` as its trusted UTC time source, and qualifies every select
and update by the selected tenant. A concurrent legal-hold change and cleanup
therefore serialize on the tenant row. A hold prevents both dry-run mutation and
deletion evidence because no deletion occurs.

## Retention policy

The schema defaults are exactly:

- decision restricted detail: 90 days;
- audit sensitive detail: 365 days.

Tenant policy permits 1 through 3,650 days. Retention uses the strict predicate
`created_at < cutoff`; a record exactly at the cutoff remains active until the
next run. Decision tombstoning removes reasons, MITRE detail, predicted action,
evidence state, pipeline timings, and the canonical redacted action when no
non-tombstoned decision still references it. Stable decision identity, input
digest, verdict, policy version, response state, and audit-integrity evidence
remain available. Audit cleanup removes only `sensitive_detail`; sequence,
predecessor, canonical integrity metadata, digest, signature, and signing-key
identifier remain unchanged.

`RetentionPolicyService.configure` is the application-layer configuration
boundary. It accepts only a validated human principal with the explicit
`tenant:administer` capability, resolves the tenant from that principal, locks
the tenant row, and validates both periods before writing. Every effective
change appends a signed `privacy.retention_policy_updated` event containing the
bounded before/after policy and the persisted administrative principal link.
Submitting the already-active policy is idempotent and creates no duplicate
event. No public policy-mutation route is exposed in the read-only launch API.

The initial additive storage migration already introduced tenant policy,
legal-hold, and tombstone fields before this worker was activated. This change
therefore requires no destructive migration.

## Bounded, resumable execution

Dry-run is the default. A run selects at most `retention_batch_size` records,
where the configured default is 100 and the enforced maximum is 500. It returns
`MORE_AVAILABLE` when another transaction is required. Repeated calls converge
because only rows without a tombstone are eligible. A crash before commit rolls
back detail removal and its evidence event together; a retry safely selects the
same rows. Per-tenant locking prevents two workers from producing overlapping
batches.

Every applied non-empty batch appends `privacy.retention_applied` to the tenant's
signed audit chain in the same transaction. Its bounded integrity metadata
records a generated operation identifier, both cutoffs, effective policy days,
per-class deletion counts, continuation state, legal-hold state, and trusted
time-source identifier. Signing or database failure rolls the complete batch
back. The event contains no deleted content.

## Compliance export

`PrivacyExportService` is an application-layer export boundary for controlled
administrative workflows; it is not a public launch API. It requires a human
principal with the explicit `tenant:administer` capability and derives tenancy
only from validated identity claims. Analyst, operator, auditor, viewer, and
workload identities are rejected.

Exports use stable `(created_at DESC, decision_id DESC)` keyset pages of at most
100 decisions and enforce an 8 MiB canonical page limit. The projection contains
persisted decision fields, the already
redacted canonical action when retained, tombstone state, and audit continuity.
It excludes identity subjects, idempotency keys, raw requests, prompts,
credentials, tokens, unrestricted provider payloads, audit sensitive detail,
and outbox payloads. Every projected JSON value passes through the recursive
redaction boundary again. The page includes a SHA-256 manifest digest over its
canonical item representation; it is integrity evidence, not a signature.

## Redaction controls

Sensitive field names are recursively masked and container depth, item count,
string length, and canonical byte size are bounded. The value scanner also
masks bearer credentials, JWT-shaped values, AWS access-key identifiers,
private-key headers, and URLs containing user information. This is defence in
depth: prohibited data must still be rejected before persistence and must never
be treated as safe merely because a detector did not recognize its format.

## Recovery and rollback

Disable `DUSK_CP_PRIVACY_LIFECYCLE_ENABLED` to stop new cleanup batches. This
does not reverse committed tombstones. Deletion is intentionally irreversible
inside the live database. Recovery requires an approved, encrypted backup that
predates deletion, authorization from the data owner and security owner, and a
tenant-isolated restore into a controlled environment. Restoring a production
database in place would also rewind audit and decision state and is prohibited
without a documented incident-recovery decision.

The application code can be rolled back while retaining the additive baseline
columns. Before production activation, staging must prove dry-run counts,
bounded retries, legal holds, chain continuity, cross-tenant isolation, export
authorization/redaction, and restore procedures using real PostgreSQL and the
approved signing service.
