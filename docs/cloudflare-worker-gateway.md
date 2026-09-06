# DUSK Cloudflare Worker gateway

## Purpose

The `dusk` Cloudflare Worker is a fail-closed request boundary for DUSK action evaluation. It accepts only authenticated JSON `POST` requests to `/v1/actions/evaluate`, then forwards validated bytes to the DUSK enforcement service.

The Worker does not evaluate DUSK policy, issue permits, or execute tools. The Python DUSK service remains the enforcement authority and the only component that can authorize a consequential action.

## Local verification

```powershell
npm ci
npm run test:worker
npm run typecheck:worker
npm run deploy:worker:dry-run
```

The dry run verifies that Wrangler can package the Worker. It does not deploy it and does not prove that a DUSK origin is reachable.

## Configure production secrets

Use a principal that is authorized only for this Worker. Do not put the secret values in `wrangler.jsonc`, `.dev.vars`, source control, CI logs, or terminal recordings.

```powershell
npx wrangler secret put DUSK_ORIGIN
npx wrangler secret put DUSK_GATEWAY_TOKEN
npx wrangler deploy
```

`DUSK_ORIGIN` must be the publicly reachable HTTPS base URL of the DUSK enforcement service. `DUSK_GATEWAY_TOKEN` must be a newly generated high-entropy secret. The origin must independently validate `X-DUSK-Gateway-Token` before evaluating any request. A Worker token is an authentication boundary, not a substitute for DUSK policy, permit verification, or restricted execution.

## Request contract

```powershell
curl.exe -X POST "https://dusk.<your-subdomain>.workers.dev/v1/actions/evaluate" `
  -H "Authorization: Bearer <client-gateway-token>" `
  -H "Content-Type: application/json" `
  --data '{"action_type":"route_change","target":"sandbox"}'
```

The Worker permits only a JSON object up to 65,536 bytes. It returns a generated `X-DUSK-Request-ID` response header. Keep that identifier with DUSK audit records when investigating a decision.

## Evidence boundary

Local tests and a successful packaging dry run verify Worker behavior in an isolated runtime. A production validation also requires configured Cloudflare secrets, a reachable HTTPS DUSK origin, origin-side token validation, DUSK policy and permit checks, a restricted executor, and a retained audit receipt.
