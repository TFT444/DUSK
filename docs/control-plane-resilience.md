# Control-plane resilience and recovery

This document defines the production failure contract for the DUSK control
plane. It covers the v2 service only. The frozen `/v1/gate` behavior remains
unchanged.

## Recovery objectives

- **Authoritative decision RPO: zero committed records.** A successful v2
  response is returned only after the canonical action, decision, signed audit
  event, and outbox intent commit atomically. A transaction interrupted before
  commit is not authoritative and is retried with the same tenant-qualified
  idempotency key.
- **Control-plane RTO: five minutes.** After PostgreSQL, the identity provider,
  or the policy dependency is healthy, readiness and a safe request retry must
  succeed within five minutes. No cache bypass or database edit is permitted.
- **Outbox recovery RTO: six minutes for an eligible intent.** With default
  settings, an abandoned lease is reclaimable after 30 seconds and a scheduled
  retry becomes eligible within the 300-second maximum backoff. Polling and a
  bounded network attempt fit inside the remaining margin. Draining an entire
  backlog is capacity-dependent and is governed by the batch and concurrency
  limits rather than this per-intent objective.
- **Audit RPO: zero committed decisions.** Every committed decision has exactly
  one linked signed audit event and at least one durable delivery intent. A gap
  blocks release and incident recovery.

These are engineering objectives and configuration-derived bounds, not fabricated production
measurements. Staging and production RTO evidence must
contain observed timestamps from the deployed services.

## Fault qualification matrix

| Fault | Boundary and expected behavior | Recovery evidence |
| --- | --- | --- |
| PostgreSQL outage or connection loss | Consequential v2 evaluation fails closed with retryable `EVALUATION_UNAVAILABLE`; an interrupted transaction leaves no partial evidence. Read APIs return their bounded, retryable unavailable error. | `test_consequential_evaluation_fails_closed_on_storage_outage`, `test_database_connection_loss_rolls_back_and_normal_retry_recovers` |
| Stalled evaluation dependency | The complete authenticated v2 evaluation has a validated 0.1-to-30-second deadline (10 seconds by default). Cancellation rolls back in-flight transaction state and returns retryable `EVALUATION_UNAVAILABLE`. | `test_stalled_evaluation_is_cancelled_by_fail_closed_request_deadline`, `test_cancelled_audit_signing_rolls_back_and_idempotent_retry_recovers` |
| Policy dependency failure | Evaluation fails closed with retryable `POLICY_UNAVAILABLE`; behavioral allow cannot bypass policy. | `test_policy_provider_outage_fails_closed` |
| Identity-provider outage or expired JWKS | Authentication fails closed with retryable `IDENTITY_PROVIDER_UNAVAILABLE`; stale signing keys are never accepted. | `test_expired_cache_never_falls_back_to_stale_key_during_outage`, `test_identity_provider_recovery_revalidates_without_stale_bypass`, authorization API tests |
| SIE timeout | Optional semantic enrichment fails soft to the deterministic local embedding. It remains non-authoritative for policy and audit. | `test_sie_timeout_uses_deterministic_fail_soft_embedding` |
| Outbox saturation | The API preserves committed intents. Each worker claims no more than `outbox_batch_size` and performs no more than `outbox_max_concurrency` deliveries. | `test_batch_saturation_and_concurrency_are_strictly_bounded` |
| Duplicate submission | A tenant-qualified transactional advisory lock serializes identical idempotency keys across replicas. All callers receive the first complete response; one action, decision, audit event, and delivery exist. | `test_high_concurrency_duplicate_submission_commits_one_complete_bundle` |
| Migration interruption | PostgreSQL transactional DDL rolls back. The latest additive migration can be downgraded to the preceding revision and reapplied; preceding service tables remain usable during rollback. | `test_postgresql_ddl_rolls_back_after_interruption`, `test_latest_migration_supports_mixed_version_rollback_and_retry` |
| Worker crash | An `IN_FLIGHT` claim has a database-time lease. A replacement worker reclaims it with the same delivery ID; stale worker completion cannot overwrite the new state version. | `test_expired_lease_is_reclaimed_after_worker_restart` and stale-result outbox tests |
| Clock anomaly | Decision, audit, lease, retry, and broker-acknowledgement freshness use PostgreSQL time. A skewed worker clock neither accepts stale acknowledgements nor rejects fresh ones. | `test_broker_acknowledgement_freshness_uses_postgresql_not_worker_clock`, `test_stale_broker_acknowledgement_fails_closed_against_postgresql_clock` |
| Partial dependency recovery | Recovery is by normal readiness, authentication, evaluation, and idempotent retry paths. No authorization, tenant, policy, or audit check is disabled. | database recovery, JWKS rotation, and outbox lease-recovery tests |
| High concurrency | Database constraints and tenant-qualified locks preserve one idempotent bundle, gap-free tenant audit sequences, and independent tenant state. Pool, statement, request, batch, and worker concurrency settings are bounded. | `test_concurrent_sequence_allocation_and_restart_recovery`, `test_idempotency_lock_does_not_block_another_tenant`, duplicate and tenant-isolation tests |

The CI integration lane runs these storage and worker cases against PostgreSQL,
not an in-memory substitute. Unit-level identity and dependency fault injection
is isolated to automated tests. Deployment qualification must repeat the matrix
against the real OIDC authority and deployed service containers.

## Operator recovery procedure

1. Stop routing new v2 evaluations when a mandatory dependency is unhealthy.
   Do not redirect traffic to an unaudited evaluator. `/v1/gate` continues only
   under its existing, separately owned contract.
2. Preserve logs, traces, database diagnostics, and the deployment digest. Never
   place tokens, credentials, raw requests, or provider payloads in evidence.
3. Restore the failed dependency and wait for `/readyz` to report every critical
   component as ready. Optional enrichment may remain explicitly degraded.
4. Run `alembic current` and `alembic check` from the same signed service image.
   If an upgrade was interrupted, rerun the idempotent upgrade. Roll back only to
   the documented preceding revision; never edit Alembic or application tables
   manually.
5. Retry unacknowledged client requests with their original idempotency keys.
   A different input under the same key must remain a conflict. Allow expired
   outbox leases and eligible retries to recover through the worker; do not
   rewrite delivery state.
6. Reconcile tenant counts and links for canonical actions, decisions, audit
   events, and outbox deliveries. Verify the signed audit chain and confirm no
   duplicate `(tenant_id, idempotency_key)`, audit sequence gap, orphan, or
   cross-tenant reference exists.
7. Resume traffic gradually only after the recovery checks pass, the RPO is
   confirmed, and observed recovery time is within the relevant RTO. Escalate
   any audit gap, tenant-isolation finding, or unexplained decision drift; do not
   repair it with an ad hoc database update.

## Local qualification

Set `DUSK_TEST_DATABASE_URL` to a disposable PostgreSQL database, then run:

```sh
pytest -q -n 0 services/control-plane/tests/integration
pytest -q services/control-plane/tests tests/test_trace_vector.py
```

The database must contain no production data. The integration fixture upgrades
from base to head, verifies schema parity, exercises rollback/reapply, and
downgrades to base on completion.
