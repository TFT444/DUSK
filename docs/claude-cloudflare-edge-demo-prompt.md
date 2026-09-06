# Claude prompt: DUSK Cloudflare edge demo

Work in `C:\DUSK\DUSK` on a new isolated branch. Do not modify, retry, deploy, or configure the existing Cloudflare Worker service named `dusk`.

## Objective

Implement a backend-first, controlled Cloudflare edge demonstration for DUSK. It must prove one simulated action is allowed and executed, while one prompt-injection-marked simulated action is blocked before execution.

This is not a production deployment. Do not claim Cloudflare endorsement, partnership, compliance certification, universal agent safety, or production readiness.

## Existing code to reuse

Reuse the existing DUSK implementation where possible:

- `src/dusk/secure_action_flow.py`
- `src/dusk/permits.py`
- `src/dusk/proxy.py`
- `src/dusk/policies/`

Do not create a second, incompatible permit format, policy engine, or permit verifier. The enforcement chain must remain:

`Worker transport -> DUSK policy authorization -> signed, action-bound, short-lived permit -> restricted fake executor independently verifies permit -> redacted receipt`

The Worker is transport only. It must never be the final execution-control boundary.

## Scope

Create these components:

- `cloudflare-demo/` as an isolated Worker project.
- `cloudflare-demo/src/index.ts` with a strict `POST /api/demo-actions` route.
- `cloudflare-demo/src/contracts.ts` and `cloudflare-demo/src/demo-actions.ts`.
- `src/dusk/demo_cloudflare.py` as a narrowly scoped local Python demo-policy HTTP service.
- Python and Worker tests.
- `docs/cloudflare-edge-demo.md` with local run, security boundaries, limitations, and deployment checklist.

Do not build a browser frontend in this PR. The API and automated local end-to-end evidence come first. A dashboard can be a later PR.

## Fake actions only

Accept exactly these action names:

- `demo.read_status`
- `demo.rotate_demo_key`

Accept exactly these risk signals:

- `normal`
- `prompt_injection`

Rules:

- `demo.read_status` with `normal` may be allowed and produce a fixed non-sensitive result.
- `demo.rotate_demo_key` with `prompt_injection` must be blocked. It must issue no permit and make no state change.
- A normal `demo.rotate_demo_key` may only change process-local demo state, such as a counter. It must never access or rotate a real key.
- Reject unknown actions, unknown signals, unexpected request fields, and secret-bearing fields.

## Security requirements

- Use canonical action serialization and SHA-256 action digesting.
- Permits must be Ed25519-signed, action-bound, tenant-bound, agent-bound, short-lived, and single-use.
- The restricted fake executor must verify signature, expiry, action digest, identity binding, and replay state before any fake execution.
- Fail closed: malformed input, malformed upstream response, timeout, failed authentication, invalid permit, replay, expiry, altered action, mismatch, policy error, or executor error must return `BLOCKED` with `executed: false`.
- Receipts must contain only safe metadata such as correlation ID, decision, reason code, permit ID when issued, action digest, execution status, and timestamp. Never include payloads, signatures, raw keys, shared secrets, source IPs, or tool output.
- The Worker must use a strict schema, JSON body size limit, fixed upstream path, a short timeout, and no arbitrary URL forwarding.
- Authenticate Worker-to-policy requests with HMAC over method, path, timestamp, nonce, and canonical JSON body. Validate with constant-time comparison. Reject stale timestamps and replayed nonces.
- Bind the local Python service to loopback only. A Cloudflare Tunnel is optional for later preview testing.
- Do not put secrets in source, tests, config files, logs, receipts, or documentation examples.

## Tests required

Write tests before implementation where practical. Include:

1. Allowed `demo.read_status` with a valid permit and `executed: true`.
2. Prompt-injection `demo.rotate_demo_key` blocked with no permit and `executed: false`.
3. Unknown action and unknown signal rejected.
4. Expired permit blocked.
5. Replayed permit blocked.
6. Permit with changed action blocked.
7. Tenant or agent mismatch blocked.
8. Missing or invalid HMAC authentication blocked.
9. Stale timestamp and replayed nonce blocked.
10. Malformed JSON, oversized body, unsupported method, and unknown route rejected.
11. Policy-service timeout, malformed response, and outage return `BLOCKED` without execution.
12. Receipt redaction tests proving sensitive fields do not appear.

## Verification

Run the relevant commands and report their exact results:

- focused Python tests
- focused Worker tests and type check
- Ruff for changed Python files
- mypy for changed Python module(s)
- `git diff --check`
- full relevant test suite if practical

Inspect the final diff for security, dependency declarations, originality, and compatibility with existing DUSK abstractions. Do not commit, push, open a PR, create Cloudflare resources, set Cloudflare secrets, create a tunnel, or deploy. Stop after verified local implementation and provide:

1. files changed
2. exact tests run and results
3. local end-to-end evidence for allow and block paths
4. remaining deployment prerequisites
5. known limitations

## Deployment boundary

A later, separately approved step may create a new Worker called `dusk-edge-demo`, configured with root directory `cloudflare-demo/`, its own secrets, and a preview `workers.dev` URL. Never reuse the existing `dusk` service.
