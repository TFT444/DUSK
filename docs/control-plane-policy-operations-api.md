# Policy catalogue and operational-state API

These read-only `/v2` endpoints expose the active policy pack and measured
dependency state. They are disabled by default and do not alter the legacy
`/v1/gate` contract.

## Authorization and tenancy

- `GET /v2/policies` and `GET /v2/policies/summary` require a human identity
  with `policy-evidence:read` (the `auditor` role at launch).
- `GET /v2/integrations/health` and `GET /v2/service/status` require a human
  identity with `operations:read` (the `operator` role at launch).
- Tenant identity is derived exclusively from validated OIDC claims. Tenant
  query or body fields are rejected by the strict request schemas.

Policy and integration lists use stable ascending identifiers and signed,
tenant- and filter-bound cursors. Policy filters are `status`, `category`, and
`severity`; integration filters are `status` and `integration_kind`.

## Data provenance

Policy responses are generated from the injected active `PolicyPack`; versions
and lifecycle counts are never hard-coded. Catalogue entries expose only
reviewed metadata and omit rule conditions, test vectors, and contextual input
values.

Integration health is read from tenant-qualified PostgreSQL records. A record
older than `DUSK_CP_INTEGRATION_HEALTH_STALE_AFTER_SECONDS` is returned as
`STALE`, regardless of its stored status. Only fixed public diagnostic codes
may cross the API boundary; arbitrary stored strings are omitted.

Service status reports `gate`, `postgresql`, `sie`, `outbox`, `audit`, and
`adapters`. PostgreSQL is checked by the request's database transaction. Gate,
SIE, and adapter state comes from current collector records. Outbox health is
reported only when the worker is enabled, while audit health requires persisted
tenant evidence. Missing measurements are `unmeasured`, never `healthy`.
Pipeline stages are listed only when their timings are emitted by the active
evaluation pipeline.

The service reports overall `unavailable` when any measured component is
unavailable and `degraded` when state is degraded or unmeasured. Empty
integration results return an explicit `empty` state. Query failure returns the
standard retryable `OPERATIONAL_DATA_UNAVAILABLE` envelope without exception,
topology, credential, or endpoint detail.

## Deployment and rollback

This change uses the existing additive `integration_health` schema and requires
no migration. Activate the routes only after injecting the reviewed policy pack
and enabling `DUSK_CP_OPERATIONS_READ_API_ENABLED`. Rollback consists of
disabling that flag; collectors and existing records may remain in place.
