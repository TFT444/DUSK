# Control-plane outbox delivery

The production control plane delivers committed outbox intents with bounded,
at-least-once workers. The request transaction never calls a webhook or
credential-holding broker. Workers cross that network boundary only after the
decision, signed audit event, and stable delivery ID are durable.

## Claim and recovery protocol

Each worker claims at most `outbox_batch_size` rows with PostgreSQL
`FOR UPDATE SKIP LOCKED`. A claim changes the row to `IN_FLIGHT`, increments the
attempt and state versions, and records a worker UUID and expiring lease before
network I/O begins. Completion is accepted only when the lease owner and state
version still match. A worker crash leaves an expiring claim; another worker can
reclaim it without changing the delivery ID.

At-least-once delivery means a crash after a receiver accepts a request but
before PostgreSQL records completion can send the request again. Every request
therefore carries the stable UUID in both `Dusk-Delivery-ID` and
`Idempotency-Key`. Webhook and broker receivers must retain that key and return
the original result for duplicates. They must not use transport retries as new
execution requests.

Failures use exponential backoff with equal jitter. The delay cap is
`min(retry_max, retry_base * 2^(attempt-1))`; the selected delay is bounded to
the upper half of that cap. Attempts, batch size, concurrency, DNS answers,
payload size, response headers, connect time, response time, lease duration,
and acknowledgement age are all bounded. Exhausted or permanent failures enter
`DEAD_LETTER` with a safe diagnostic code. Exception text, URLs, credentials,
response bodies, and provider payloads are never persisted as diagnostics.

## Destination and SSRF controls

Outbox rows store a destination key, not a URL or credential. A trusted,
immutable registry maps that key to a destination class and HTTPS URL. URLs
with user information, query strings, fragments, control characters, or
non-ASCII paths are rejected. Credentials are obtained immediately before send
from an injected secret provider and cannot override routing, content, or
idempotency headers.

DNS is resolved for every attempt with a bounded timeout. Empty, oversized,
mixed, malformed, loopback, private, link-local, unspecified, reserved,
multicast, and non-global answers fail closed. The HTTPS transport receives only
the approved IP addresses and connects the socket directly to one of them while
retaining the configured hostname for TLS certificate verification and the
HTTP `Host` header. Redirects are not followed and response bodies are not
trusted or read. This prevents a second DNS lookup from turning validation into
a rebinding bypass. Deployment network policy must independently restrict
worker egress to approved resolvers and external destinations.

## Broker acknowledgement contract

Webhook `2xx` delivery can establish `DELIVERED`; it can never establish
`EXECUTED`. An enforcement broker must return these response headers:

- `Dusk-Ack-Tenant-ID`
- `Dusk-Ack-Version` (`dusk.broker-ack.v1`)
- `Dusk-Ack-Decision-ID`
- `Dusk-Ack-Delivery-ID`
- `Dusk-Ack-Outcome` (`EXECUTED` or `REJECTED`)
- `Dusk-Ack-Issued-At` (UTC timestamp)
- `Dusk-Ack-Nonce`
- `Dusk-Ack-Key-ID`
- `Dusk-Ack-Signature` (padded base64url)

The signature covers canonical JSON containing those fields except the
signature. The worker checks tenant, decision, and delivery binding, timestamp
freshness, schema bounds, and a configured cryptographic verifier. Only a valid
`EXECUTED` acknowledgement advances the decision to `EXECUTED`. A Gate `ALLOW`,
webhook success, missing acknowledgement, stale response, wrong identifier, or
invalid signature does not. The bounded canonical acknowledgement fields,
external signature, evidence digest, outcome, trusted receipt time, and
sanitized HTTP status are stored so the result remains independently
verifiable; response bodies are discarded.

## Lifecycle and rollback

Outbox lifecycle is `PENDING -> IN_FLIGHT -> DELIVERED` or `DEAD_LETTER`, with
expired `IN_FLIGHT` claims returning through a new leased attempt. Decision
lifecycle is derived from all durable intents: verified broker execution wins;
dead letter or trusted rejection is `FAILED`; all delivered intents are
`DELIVERED`; otherwise the decision remains `DELIVERY_PENDING`.

Migration `20260902_0003` additively introduces destination class, state version,
lease owner, last-attempt time, acknowledgement digest/outcome/time, and related
constraints. To roll back, stop every worker first. The migration downgrade
preserves pending rows, destination keys, stable delivery IDs, attempt counts,
and redacted payloads so a compatible worker can replay them.

The worker feature flag is disabled by default. Production activation requires
real PostgreSQL, a trusted destination registry, secret provider, DNS resolver,
pinned HTTPS transport, and broker acknowledgement verifier. Unit and contract
tests use isolated doubles; staging certification must use the deployed service
and approved webhook and broker endpoints.
