# Control-plane decision evidence

The production control plane treats durable evidence as part of the
authorization boundary. A v2 evaluation is not returned as authorized until
PostgreSQL has committed its redacted canonical action, decision, policy
matches, tenant audit event, and transactional outbox intent in one transaction.
This extends the evidence contract in issue #158; it does not define a second
audit format.

## Transaction and failure policy

`PostgresDecisionEvidenceStore` performs the complete write in one SQLAlchemy
transaction. A PostgreSQL transaction advisory lock derived from the tenant UUID
serializes sequence allocation, including concurrent attempts to append the
first tenant event. Unique tenant-qualified constraints provide a second line
of defence. A database, signing-service, constraint, or commit failure rolls
back every record and produces the retryable `EVALUATION_UNAVAILABLE` boundary.

Idempotency is scoped by tenant. The stored SHA-256 input digest must match on a
retry; reuse with different input fails closed. A valid retry returns the
original persisted response and trace continuity rather than a newly evaluated,
unaudited result.

## Canonical audit format

The format identifier is `dusk.audit.v1`. The SHA-256 digest covers canonical
UTF-8 JSON containing:

- format and tenant identity;
- monotonic tenant sequence and event type;
- decision and authenticated principal identifiers;
- PostgreSQL `clock_timestamp()` in UTC;
- the previous digest;
- versioned integrity metadata.

Integrity metadata records the input digest, trace, verdict, behavioral score,
policy decision and pack version, safe matched-rule identifiers and versions,
evidence-degradation state, evidence owner, retention state, delivery state,
redaction result, and trusted time source. An injected `AuditSigner` signs every
digest through a managed KMS or HSM boundary. The database stores the signature
and non-secret signing-key identifier. Missing or unavailable signing is a
fail-closed condition.

Verification recomputes every digest in sequence, checks tenant continuity,
predecessors, monotonic time, and every external signature, then compares the
tail with an independently retained `AuditCheckpoint`. The checkpoint is
required to detect deletion of the final event; an internal chain alone cannot
prove that its own tail was not removed. Mutation, deletion, reordering,
cross-tenant splicing, signature mismatch, and checkpoint mismatch are explicit
integrity failures.

## Data minimization

Only schema-validated canonical action fields enter redacted storage. Recursive
redaction masks authorization, cookie, credential, password, prompt, secret,
session, and token fields. Nesting, collection sizes, strings, and serialized
content are bounded. Evidence payloads, raw requests, credentials, tokens,
prompts, and unrestricted provider responses are never persisted. The outbox
contains identifiers, lifecycle state, verdict, and audit digest only.

## Migration and rollback

Migration `20260901_0002` adds the chain-format marker, signing-key identifier,
and signature columns. The signing columns remain nullable for records written
before activation; new durable writes require them. The format marker also
remains inside the signed integrity metadata, so downgrading the additive
columns does not invalidate previously written digest evidence or the legacy
digest verifier. Routing must be rolled back before schema downgrade.

The legacy Python package, CLI, agent harness, and frozen `/v1/gate` boundary do
not use this transaction and retain their existing behavior.
