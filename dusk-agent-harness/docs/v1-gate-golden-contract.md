# Frozen v1 Gate golden contract

Issue #191 freezes the existing Flask boundary before application-layer
evaluation is extracted. Machine-readable snapshots live in
`contracts/v1-gate-golden.json`; the parity runner is
`tests/contract/test_v1_gate_golden.py`.

## Frozen behavior

- Success responses, verdicts, score rounding, reason order, MITRE arrays,
  blast radius, predicted-next text, and similar-decision references.
- Watch and enforce behavior.
- Schema, malformed JSON, authentication, request-size, and method failures,
  including status, selected public headers, and body.
- `/health` success and stable degradation codes for baseline and offense-store
  failure.
- Decision/report/alert webhook selection and exact payload context.
- Decision-history and offense-memory creation, including no side effects for
  rejected requests.
- Optional SIE unavailability falling back to the deterministic result.
- Client orchestration: `ALLOW` and `WOULD-BLOCK` reach the downstream example;
  `BLOCK` does not.

Focused suites continue to exercise SIE timeout and malformed responses,
offense persistence across restart, bounded history, webhook SSRF/backpressure,
configuration coercion, and provider adapters. The golden suite adds exact
compatibility evidence at their public seam.

## Normalization policy

Only nondeterministic or semantically insignificant values are normalized:

1. UUID generation uses recorded 32-character hexadecimal IDs.
2. JSON objects use canonical sorted-key serialization without insignificant
   whitespace. Array order, strings, numbers, nulls, and field presence remain
   exact.
3. `Content-Type` and `WWW-Authenticate` are compared. Framework transport
   headers such as `Date`, `Server`, and computed `Content-Length` are excluded.

No verdict, score, reason, status, side effect, or execution behavior is
normalized. A changed golden is a public-contract change and requires explicit
compatibility review; snapshots must never be refreshed merely to make a
refactor pass.
