# DUSK Cloudflare Edge Demo

Local-only demonstration of DUSK policy enforcement on a Cloudflare Worker.
**Not a production deployment. Not a certification claim.**

## What this demo proves

| Path | Action | Signal | Expected result |
|------|--------|--------|-----------------|
| Allow | `demo.read_status` | `normal` | `executed: true`, signed permit issued and verified |
| Block | `demo.rotate_demo_key` | `prompt_injection` | `executed: false`, no permit, no state change |

## Enforcement chain

```
Client
  └─▶ Worker  POST /api/demo-actions
        │   (strict schema · body-size limit · method guard)
        │
        ├─▶ Python policy service  POST /v1/demo/evaluate
        │   (HMAC-signed · timestamp · nonce · fail-closed)
        │   → ALLOW: Ed25519 permit issued
        │   → BLOCK: reason code returned, chain stops
        │
        └─▶ Python restricted executor  POST /v1/demo/execute
            (permit verified independently: expiry · replay · digest · identity · signature)
            → executed: true  (process-local counter only, no real key access)
            → receipt: correlation_id, decision, reason_code, permit_id, action_digest, timestamp
```

The Worker is transport only. The Python service is the final enforcement boundary.

## Security properties

- **Ed25519 permits**: action-bound, tenant-bound, agent-bound, short-lived (60 s), single-use.
- **HMAC auth**: Worker signs every upstream call with method, path, timestamp, nonce, and body. Constant-time comparison. Stale timestamps (>30 s) and replayed nonces are rejected.
- **Fail-closed**: any upstream error, timeout, malformed response, invalid permit, replay, expiry, altered action, or identity mismatch returns `BLOCKED` with `executed: false`.
- **Receipt redaction**: receipts contain only correlation ID, decision, reason code, permit ID (on allow), action digest, and timestamp. No payloads, signatures, IPs, or secret values.
- **Body limit**: Worker rejects bodies >4096 bytes before parsing.

## Running locally

### 1. Start the Python policy service

```bash
cd C:\DUSK\DUSK
# Generate a random HMAC secret and export it for both processes
$env:DEMO_HMAC_SECRET = python -c "import secrets; print(secrets.token_hex(32))"

python - <<'EOF'
import os
from dusk.demo_cloudflare import DemoServer
DemoServer(hmac_secret=bytes.fromhex(os.environ["DEMO_HMAC_SECRET"])).serve_forever()
EOF
```

### 2. Run the Worker locally (separate terminal)

```bash
cd C:\DUSK\DUSK\cloudflare-demo
npm install
# Set secrets for the local dev session
npx wrangler secret put HMAC_SECRET   # paste the value from $env:DEMO_HMAC_SECRET
npx wrangler dev
```

### 3. Send demo requests

**Allow path**
```bash
curl -X POST http://localhost:8788/api/demo-actions \
  -H "Content-Type: application/json" \
  -d '{"action":"demo.read_status","signal":"normal","tenant_id":"demo-tenant","agent_id":"demo-agent","correlation_id":"test-1"}'
```

Expected: `{"executed":true,"decision":"ALLOW",...}`

**Block path**
```bash
curl -X POST http://localhost:8788/api/demo-actions \
  -H "Content-Type: application/json" \
  -d '{"action":"demo.rotate_demo_key","signal":"prompt_injection","tenant_id":"demo-tenant","agent_id":"demo-agent","correlation_id":"test-2"}'
```

Expected: `{"executed":false,"decision":"BLOCKED","reason_code":"PROMPT_INJECTION_DETECTED",...}`

## Running tests

**Python (20 tests covering all 12 prompt scenarios)**
```bash
cd C:\DUSK\DUSK
python -m pytest tests/test_demo_cloudflare.py -v
```

**TypeScript Worker (16 tests)**
```bash
cd C:\DUSK\DUSK\cloudflare-demo
npm test
```

**Type check**
```bash
cd C:\DUSK\DUSK\cloudflare-demo
npx tsc --noEmit
```

## Deployment prerequisites (future, separately approved step)

1. Create a new Worker named `dusk-edge-demo` with root `cloudflare-demo/`.
2. Set `HMAC_SECRET` via `wrangler secret put HMAC_SECRET`. **Never commit a real secret.**
3. Run the Python service on a trusted host; expose via Cloudflare Tunnel (optional) or keep loopback-only.
4. Confirm the `POLICY_URL` var in `wrangler.toml` points to the correct service address.
5. Do not reuse or modify the existing `dusk` Worker.

## Known limitations

- The Python service uses `http.server` (single-threaded). Suitable for demo only.
- `DEMO_HMAC_SECRET` is a process-local demo key. Rotate it every session; it never persists.
- `demo.rotate_demo_key` with `normal` signal increments a process-local counter; it never touches real keys.
- The Cloudflare Tunnel is not configured. The Worker can only reach the Python service when both run on the same machine with the Worker via `wrangler dev`.
- No browser frontend. The API and automated tests are the E2E evidence.
