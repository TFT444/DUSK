# Cloudflare DUSK Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy a fail-closed Cloudflare Worker named `dusk` that authenticates and proxies bounded action-evaluation requests to the Python DUSK enforcement service.

**Architecture:** A TypeScript Worker lives in `workers/dusk-gateway/` and is configured by root `wrangler.jsonc`, which lets the existing Cloudflare Workers Build discover it. The Worker has no policy authority. It authenticates requests, validates the bounded JSON contract, forwards to the HTTPS DUSK origin, and returns only the upstream result or a fail-closed error.

**Tech Stack:** Cloudflare Workers, Wrangler, TypeScript, Vitest, `@cloudflare/vitest-pool-workers`.

**Spec:** `docs/superpowers/specs/2026-09-06-cloudflare-dusk-gateway-design.md`

## Global Constraints

- Preserve the Python DUSK policy engine, permit service, and restricted executor as the only enforcement authority.
- Use `wrangler.jsonc` with `name: "dusk"`, `main: "workers/dusk-gateway/src/index.ts"`, and `compatibility_date: "2026-09-06"`.
- Enable Workers logs and traces in `wrangler.jsonc`.
- Never commit `DUSK_ORIGIN` or `DUSK_GATEWAY_TOKEN`; only document `wrangler secret put` commands.
- Permit only `POST /v1/actions/evaluate` and a JSON body no larger than 65536 bytes.
- Use Web Crypto constant-time comparison for the bearer token.
- Do not add a fallback origin or `passThroughOnException()`.
- A local passing suite and `wrangler deploy --dry-run` are deployment evidence only. A live test requires the Cloudflare secrets and an HTTPS DUSK origin.

---

## File Structure

- Create: `package.json`, root Node scripts and pinned Worker development dependencies.
- Create: `wrangler.jsonc`, Worker deployment and observability configuration.
- Create: `workers/dusk-gateway/src/index.ts`, the request boundary and upstream proxy.
- Create: `workers/dusk-gateway/test/index.spec.ts`, Workers-runtime behavior tests.
- Create: `workers/dusk-gateway/vitest.config.ts`, Workers test-pool setup.
- Modify: `.gitignore`, add only local Worker variable files.
- Create: `docs/cloudflare-worker-gateway.md`, deployment, secret, and evidence instructions.

### Task 1: Worker project configuration

**Files:**
- Create: `package.json`
- Create: `wrangler.jsonc`
- Modify: `.gitignore`

**Interfaces:**
- Produces `npm run test:worker`, `npm run typecheck:worker`, and `npm run deploy:worker:dry-run`.
- Produces global Worker bindings `DUSK_ORIGIN` and `DUSK_GATEWAY_TOKEN` through `wrangler types`.

- [ ] **Step 1: Write a failing configuration test**

Create `workers/dusk-gateway/test/config.spec.ts` that loads `../../../wrangler.jsonc` as text and asserts it contains the intended Worker name, entry point, observability settings, and no secret values.

```ts
import { expect, it } from "vitest";
import config from "../../../wrangler.jsonc?raw";

it("defines the dusk Worker with observability", () => {
  expect(config).toContain('"name": "dusk"');
  expect(config).toContain('"main": "workers/dusk-gateway/src/index.ts"');
  expect(config).toContain('"enabled": true');
  expect(config).not.toContain("DUSK_GATEWAY_TOKEN=",);
});
```

- [ ] **Step 2: Run the configuration test and verify it fails**

Run: `npm run test:worker -- workers/dusk-gateway/test/config.spec.ts`

Expected: failure because the package, test runner, and config do not exist.

- [ ] **Step 3: Add the minimal Worker package and config**

Create `package.json` with exact scripts:

```json
{
  "private": true,
  "scripts": {
    "test:worker": "vitest run --config workers/dusk-gateway/vitest.config.ts",
    "typecheck:worker": "tsc --noEmit",
    "deploy:worker:dry-run": "wrangler deploy --dry-run",
    "types:worker": "wrangler types"
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.10.20",
    "@cloudflare/workers-types": "^4.20260906.0",
    "typescript": "^5.9.2",
    "vitest": "^3.2.4",
    "wrangler": "^4.38.0"
  }
}
```

Create `wrangler.jsonc`:

```jsonc
{
  "name": "dusk",
  "main": "workers/dusk-gateway/src/index.ts",
  "compatibility_date": "2026-09-06",
  "observability": {
    "enabled": true,
    "logs": { "enabled": true, "head_sampling_rate": 1 },
    "traces": { "enabled": true, "head_sampling_rate": 1 }
  }
}
```

Append `.dev.vars*` to `.gitignore`, while retaining an optional committed `workers/dusk-gateway/.dev.vars.example` with blank values only.

- [ ] **Step 4: Install through the lockfile and run the test**

Run: `npm install --package-lock-only && npm ci && npm run test:worker -- workers/dusk-gateway/test/config.spec.ts`

Expected: PASS.

- [ ] **Step 5: Generate binding types and validate packaging**

Run: `npm run types:worker && npm run deploy:worker:dry-run`

Expected: type file generated and dry-run identifies the `dusk` Worker without a remote deployment.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json wrangler.jsonc .gitignore workers/dusk-gateway
git commit -s -m "feat(cloudflare): scaffold DUSK Worker gateway"
```

### Task 2: Fail-closed gateway handler

**Files:**
- Create: `workers/dusk-gateway/src/index.ts`
- Test: `workers/dusk-gateway/test/index.spec.ts`

**Interfaces:**
- Consumes: `Env.DUSK_ORIGIN`, `Env.DUSK_GATEWAY_TOKEN`, standard `Request`, `fetch`, and `crypto.subtle`.
- Produces: a default `ExportedHandler<Env>` with `fetch(request, env)`.

- [ ] **Step 1: Write failing tests for reject paths**

Create tests using `SELF.fetch` that assert these conditions do not invoke the mocked upstream:

```ts
it("rejects a missing bearer token", async () => {
  const response = await SELF.fetch("https://worker.test/v1/actions/evaluate", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}"
  });
  expect(response.status).toBe(401);
});

it("rejects non-POST requests", async () => {
  const response = await SELF.fetch("https://worker.test/v1/actions/evaluate", {
    headers: { authorization: "Bearer expected-token" }
  });
  expect(response.status).toBe(405);
});

it("fails closed when Worker secrets are absent", async () => {
  const response = await worker.fetch("https://worker.test/v1/actions/evaluate", {
    method: "POST",
    headers: { authorization: "Bearer expected-token", "content-type": "application/json" },
    body: "{}"
  });
  expect(response.status).toBe(503);
});
```

- [ ] **Step 2: Run the tests and verify they fail**

Run: `npm run test:worker -- workers/dusk-gateway/test/index.spec.ts`

Expected: failure because the Worker module does not exist.

- [ ] **Step 3: Implement the minimal reject path**

Implement helpers with these contracts:

```ts
const MAX_BODY_BYTES = 65_536;
async function tokenMatches(provided: string | null, expected: string): Promise<boolean>;
function jsonError(status: number, code: string, requestId: string): Response;
function requireConfiguration(env: Env): boolean;
```

The handler must use `new URL(request.url)`, accept only the specified route, check `content-length` when present, read at most 65537 bytes, parse only a JSON object, use `crypto.subtle.digest("SHA-256", ...)` plus `crypto.subtle.timingSafeEqual`, and return structured JSON errors without request-body logging.

- [ ] **Step 4: Run reject-path tests and typecheck**

Run: `npm run test:worker -- workers/dusk-gateway/test/index.spec.ts && npm run typecheck:worker`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/dusk-gateway/src/index.ts workers/dusk-gateway/test/index.spec.ts
git commit -s -m "feat(cloudflare): add fail-closed DUSK gateway"
```

### Task 3: Upstream forwarding and failure behavior

**Files:**
- Modify: `workers/dusk-gateway/src/index.ts`
- Modify: `workers/dusk-gateway/test/index.spec.ts`

**Interfaces:**
- Consumes validated JSON bytes, `DUSK_ORIGIN`, request ID, and authenticated request.
- Produces an upstream `POST ${DUSK_ORIGIN}/v1/actions/evaluate` with `X-DUSK-Gateway`, `X-DUSK-Request-ID`, and `X-DUSK-Gateway-Token` headers.

- [ ] **Step 1: Write failing forwarding tests**

Add a test that mocks `fetch` and asserts the destination, method, three safe headers, preserved JSON body, upstream status, and `X-DUSK-Request-ID` response header. Add a second test that makes upstream `fetch` throw and asserts a `502` without a fallback request.

```ts
expect(await response.json()).toEqual({ decision: "BLOCK" });
expect(response.headers.get("x-dusk-request-id")).toMatch(/^[0-9a-f-]{36}$/);
expect(mockedFetch).toHaveBeenCalledTimes(1);
```

- [ ] **Step 2: Run the forwarding tests and verify they fail**

Run: `npm run test:worker -- workers/dusk-gateway/test/index.spec.ts`

Expected: failure because validated requests are not yet forwarded.

- [ ] **Step 3: Implement forwarding**

Construct the destination with `new URL("/v1/actions/evaluate", env.DUSK_ORIGIN)`. Reject non-HTTPS origins at runtime with `503`. Use `fetch(destination, { method: "POST", headers, body: bodyBytes })`. Return `new Response(upstream.body, { status: upstream.status, headers: safeResponseHeaders })`. Keep only `content-type`, `cache-control`, and `x-dusk-request-id` response headers so an untrusted upstream cannot set browser-sensitive headers.

- [ ] **Step 4: Run Worker tests, typecheck, and package check**

Run: `npm run test:worker && npm run typecheck:worker && npm run deploy:worker:dry-run`

Expected: all commands PASS.

- [ ] **Step 5: Commit**

```bash
git add workers/dusk-gateway/src/index.ts workers/dusk-gateway/test/index.spec.ts
git commit -s -m "feat(cloudflare): proxy validated actions to DUSK"
```

### Task 4: Deployment instructions and final validation

**Files:**
- Create: `docs/cloudflare-worker-gateway.md`

**Interfaces:**
- Documents only. It does not contain live origin URLs, tokens, or credentials.

- [ ] **Step 1: Write the deployment guide**

Document the exact non-secret setup commands:

```bash
npm ci
npm run test:worker
npm run typecheck:worker
npm run deploy:worker:dry-run
npx wrangler secret put DUSK_ORIGIN
npx wrangler secret put DUSK_GATEWAY_TOKEN
npx wrangler deploy
```

State that `DUSK_ORIGIN` must be a publicly reachable HTTPS enforcement service, `DUSK_GATEWAY_TOKEN` must be a fresh high-entropy secret, and the DUSK origin must independently validate `X-DUSK-Gateway-Token` before accepting a request. Include a `curl` example using placeholder values only.

- [ ] **Step 2: Run complete local validation**

Run: `npm run test:worker && npm run typecheck:worker && npm run deploy:worker:dry-run && PYTHONPATH=src python -m pytest -q tests/test_cloudflare_gateway.py tests/test_secure_action_flow.py && git diff --check`

Expected: all commands PASS.

- [ ] **Step 3: Verify the GitHub and Cloudflare checks after push**

Push the branch and inspect the exact head SHA. Verify GitHub CI passes and Cloudflare Workers Builds reports success. Record the Worker version or build URL. Do not claim live DUSK enforcement until the secrets are configured and a real request has reached the HTTPS DUSK origin.

- [ ] **Step 4: Commit**

```bash
git add docs/cloudflare-worker-gateway.md
git commit -s -m "docs: add DUSK Worker gateway deployment guide"
```

## Self-Review

- The plan covers the Worker discovery configuration, request validation, constant-time authentication, upstream proxy, no-forward failures, observability, local runtime tests, packaging evidence, and secret-dependent live validation.
- The plan deliberately does not run the Python policy engine in the Worker, bypass DUSK, commit secrets, or claim that local tests are a production deployment.
- Interface names are consistent across all tasks: `DUSK_ORIGIN`, `DUSK_GATEWAY_TOKEN`, `POST /v1/actions/evaluate`, `X-DUSK-Gateway`, and `X-DUSK-Request-ID`.
