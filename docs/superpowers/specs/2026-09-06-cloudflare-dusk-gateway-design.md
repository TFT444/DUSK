# Cloudflare DUSK Gateway Design

## Goal

Provide a deployable Cloudflare Worker named `dusk` that acts as a fail-closed, authenticated HTTP boundary in front of the Python DUSK enforcement service.

## Scope

The Worker accepts only `POST /v1/actions/evaluate`. It rejects unsupported methods, paths, oversized JSON bodies, invalid JSON, missing authentication, and absent runtime configuration. Valid requests are forwarded unchanged to the configured DUSK enforcement origin. The Worker returns the upstream response without treating the gateway as an enforcement engine.

The Python policy decision, signed permit issuance, and restricted execution remain in DUSK. The Worker cannot authorize an action by itself and must never bypass DUSK when the upstream is unavailable.

## Architecture

```text
Client or Cloudflare AI Gateway
        |
        | Bearer token and bounded JSON action envelope
        v
Cloudflare Worker: dusk
        |
        | HTTPS POST /v1/actions/evaluate
        | DUSK_ORIGIN secret
        v
Python DUSK enforcement service
        |
        | policy decision, permit, restricted executor
        v
Action result and trace ID
```

## Configuration

`wrangler.jsonc` defines the Worker name, TypeScript entry point, current compatibility date, observability logs, and traces. It must not contain credentials.

Two Worker secrets are configured outside Git:

- `DUSK_ORIGIN`: HTTPS base URL for the DUSK enforcement service.
- `DUSK_GATEWAY_TOKEN`: shared bearer token accepted by the Worker.

The Worker returns `503` if either secret is absent. It sends the upstream request using an internal authentication header derived from `DUSK_GATEWAY_TOKEN`; a future production rollout should replace this shared-secret hop with Cloudflare Access service tokens or mTLS.

## Request Contract

The request must use `POST /v1/actions/evaluate`, `Content-Type: application/json`, and `Authorization: Bearer <token>`. The body is limited to 64 KiB and must be a JSON object. The Worker passes the bounded JSON body to the DUSK origin and preserves the upstream status and body. It adds only `X-DUSK-Gateway: cloudflare-worker` and a generated `X-DUSK-Request-ID` header.

## Failure Handling

- Invalid client request: `400`, `401`, `404`, `405`, or `413` without forwarding.
- Missing configuration: `503` without forwarding.
- Upstream network failure: `502` without a fallback action.
- Upstream response: returned as received, with a request ID header for correlation.

No request bodies, credentials, or upstream response bodies are logged. Structured logs include only method, route, status, request ID, and latency.

## Testing and Deployment Evidence

Tests run in the Workers runtime. They cover authentication, invalid requests, size limits, missing secrets, successful forwarding, upstream failure, and no-forward failure paths. `wrangler deploy --dry-run` verifies bundle packaging. Cloudflare Workers Builds then validates the same Worker from the connected repository.

A real production end-to-end test requires a reachable HTTPS DUSK service and both Worker secrets configured in the Cloudflare dashboard. Until then, successful local tests and a successful build demonstrate deployability, not a live DUSK enforcement deployment.
