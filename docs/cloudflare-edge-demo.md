# DUSK Cloudflare Edge Demo

A controlled Cloudflare edge demo for DUSK action authorization.
It is not a production deployment or a guarantee of agent safety.

## What this demo proves

| Path | Action | risk_signal | Expected result |
|------|--------|-------------|-----------------|
| Allow | `demo.read_status` | `normal` | `executed: true`, signed permit issued and verified |
| Block | `demo.rotate_demo_key` | `prompt_injection` | `executed: false`, no permit, no state change |

## Enforcement chain

```
Client
  Browser (public/index.html + app.js) OR curl
    |
    POST /api/demo-actions
    |
  Cloudflare Worker (src/index.ts)
    |  strict schema, body-size limit, method guard
    |
    POST /v1/demo/authorize-and-execute   (HMAC-signed)
    |
  Python policy service (src/dusk/demo_cloudflare.py)
    |  timestamp freshness, nonce replay guard, HMAC verify
    |  DUSK policy pack evaluation
    |  Ed25519 permit issuance
    |  Executor: expiry, replay, digest, identity, signature
    |
    DemoReceipt: decision, reason_code, executed, permit_id, action_digest
    |
  Worker adds correlation_id and timestamp, returns to client
```

The Worker is transport only. The Python service is the final enforcement boundary.

## Security properties

- **Ed25519 permits**: action-bound, tenant-bound, agent-bound, short-lived (60 s), single-use.
- **HMAC auth**: Worker signs every upstream call with method, path, timestamp, nonce, and body. Constant-time comparison. Stale timestamps (>30 s) and replayed nonces are rejected.
- **Fail-closed**: any upstream error, timeout, malformed response, invalid permit, replay, expiry, altered action, or identity mismatch returns `BLOCKED` with `executed: false`.
- **Receipt redaction**: receipts contain only correlation ID, decision, reason code, permit ID (on allow), action digest, and timestamp. No payloads, signatures, IPs, or secret values.
- **Body limit**: Worker rejects bodies >4096 bytes before parsing.
- **Single endpoint**: `POST /v1/demo/authorize-and-execute` runs the full pipeline atomically; no partial execution risk.

## Running locally

### 1. Start the Python policy service

```bash
# From the repo root (Windows PowerShell)
$env:DUSK_DEMO_SHARED_SECRET = python -c "import secrets; print(secrets.token_hex(32))"

python - <<'EOF'
import os
from dusk.demo_cloudflare import DemoServer
DemoServer(hmac_secret=bytes.fromhex(os.environ["DUSK_DEMO_SHARED_SECRET"])).serve_forever()
EOF
```

### 2. Run the Worker locally (separate terminal)

```bash
cd cloudflare-demo
npm install
npx wrangler secret put DUSK_DEMO_SHARED_SECRET   # paste the value from step 1
npx wrangler dev --config wrangler.jsonc
```

The Worker serves the dashboard at `http://localhost:8788/` and the API at `/api/demo-actions`.

### 3. Use the dashboard or curl

**Allow path**
```bash
curl -X POST http://localhost:8788/api/demo-actions \
  -H "Content-Type: application/json" \
  -d '{"action":"demo.read_status","risk_signal":"normal","tenant_id":"demo-tenant","agent_id":"demo-agent","correlation_id":"test-1"}'
```

Expected: `{"decision":"ALLOWED","executed":true,...}`

**Block path**
```bash
curl -X POST http://localhost:8788/api/demo-actions \
  -H "Content-Type: application/json" \
  -d '{"action":"demo.rotate_demo_key","risk_signal":"prompt_injection","tenant_id":"demo-tenant","agent_id":"demo-agent","correlation_id":"test-2"}'
```

Expected: `{"decision":"BLOCKED","executed":false,"reason_code":"PROMPT_INJECTION_DETECTED",...}`

**Health check**
```bash
curl http://localhost:8788/healthz
```

Expected: `{"status":"ok"}`

## Running tests

**Python unit tests (20 tests) and HTTP-level tests (9 tests)**
```bash
cd /c/DUSK/DUSK
python -m pytest tests/test_demo_cloudflare.py tests/test_demo_cloudflare_http.py -v
```

**TypeScript Worker tests (18 tests)**
```bash
cd cloudflare-demo
npm test
```

**Type check**
```bash
cd cloudflare-demo
npx tsc --noEmit
```

**Python lint and types**
```bash
python -m ruff check src/dusk/demo_cloudflare.py tests/test_demo_cloudflare.py tests/test_demo_cloudflare_http.py
python -m mypy src/dusk/demo_cloudflare.py --ignore-missing-imports
```

## Deployment prerequisites (Task 8 -- requires explicit approval)

1. Create a new Worker named `dusk-edge-demo` with root `cloudflare-demo/`.
2. Set `DUSK_DEMO_SHARED_SECRET` via `wrangler secret put DUSK_DEMO_SHARED_SECRET`. **Never commit a real secret.**
3. Update `DUSK_DEMO_ORIGIN` in `wrangler.jsonc` to the address of the policy service.
4. Run the Python service on a trusted host; expose via Cloudflare Tunnel if needed.
5. Do not reuse or modify the existing `dusk` Worker.
6. This step requires explicit user approval before triggering.

## Known limitations

- The Python service uses `http.server` (single-threaded). Suitable for demo only.
- `DUSK_DEMO_SHARED_SECRET` is a process-local demo key. Rotate every session; it never persists.
- `demo.rotate_demo_key` with `normal` signal increments a process-local counter; it never touches real keys.
- The Cloudflare Tunnel is not configured in this PR. The Worker can reach the Python service only when both run on the same host via `wrangler dev`.
