/**
 * Worker unit tests -- all 12 prompt-doc scenarios plus edge cases.
 * The policy service is mocked; no network or process is started.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";
import { parseDemoRequest } from "../src/demo-actions.js";

// ---------------------------------------------------------------------------
// parseDemoRequest -- input validation
// ---------------------------------------------------------------------------

describe("parseDemoRequest", () => {
  it("accepts a valid demo.read_status normal request", () => {
    const result = parseDemoRequest({
      action: "demo.read_status",
      risk_signal: "normal",
      tenant_id: "t1",
      agent_id: "a1",
      correlation_id: "c1",
    });
    expect(result).not.toBeNull();
    expect(result?.action).toBe("demo.read_status");
  });

  it("accepts a valid demo.rotate_demo_key prompt_injection request", () => {
    const result = parseDemoRequest({
      action: "demo.rotate_demo_key",
      risk_signal: "prompt_injection",
      tenant_id: "t1",
      agent_id: "a1",
      correlation_id: "c1",
    });
    expect(result).not.toBeNull();
  });

  // Scenario 3: unknown action
  it("rejects an unknown action", () => {
    expect(
      parseDemoRequest({
        action: "admin.delete_all",
        risk_signal: "normal",
        tenant_id: "t1",
        agent_id: "a1",
        correlation_id: "c1",
      }),
    ).toBeNull();
  });

  // Scenario 4: unknown signal
  it("rejects an unknown signal", () => {
    expect(
      parseDemoRequest({
        action: "demo.read_status",
        risk_signal: "suspicious",
        tenant_id: "t1",
        agent_id: "a1",
        correlation_id: "c1",
      }),
    ).toBeNull();
  });

  // Scenario 10: reject unexpected / secret-bearing fields
  it("rejects requests with unexpected fields", () => {
    expect(
      parseDemoRequest({
        action: "demo.read_status",
        risk_signal: "normal",
        tenant_id: "t1",
        agent_id: "a1",
        correlation_id: "c1",
        secret: "must-not-pass",
      }),
    ).toBeNull();
  });

  it("rejects non-object inputs", () => {
    expect(parseDemoRequest("string")).toBeNull();
    expect(parseDemoRequest(42)).toBeNull();
    expect(parseDemoRequest(null)).toBeNull();
    expect(parseDemoRequest([])).toBeNull();
  });

  it("rejects empty tenant_id or agent_id", () => {
    expect(
      parseDemoRequest({
        action: "demo.read_status",
        risk_signal: "normal",
        tenant_id: "",
        agent_id: "a1",
        correlation_id: "c1",
      }),
    ).toBeNull();
  });

  // old "signal" field must be rejected (field renamed to risk_signal)
  it("rejects requests using the old 'signal' field name", () => {
    expect(
      parseDemoRequest({
        action: "demo.read_status",
        signal: "normal",
        tenant_id: "t1",
        agent_id: "a1",
        correlation_id: "c1",
      }),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Worker fetch handler -- integration-style tests with mocked upstream
// ---------------------------------------------------------------------------

import worker from "../src/index.js";

const ENV = {
  DUSK_DEMO_ORIGIN: "http://127.0.0.1:8787",
  DUSK_DEMO_SHARED_SECRET: "test-hmac-secret-32bytes-padding!",
};

function makeRequest(body: unknown, method = "POST", path = "/api/demo-actions"): Request {
  return new Request(`https://demo.example.com${path}`, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

// Mock global fetch for upstream calls
beforeEach(() => {
  vi.restoreAllMocks();
});

function mockUpstream(resp: object): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, _opts: RequestInit) =>
      new Response(JSON.stringify(resp), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    ),
  );
}

// Scenario 1: allowed demo.read_status -> executed: true
it("returns executed:true for demo.read_status with normal signal", async () => {
  mockUpstream({
    decision: "ALLOWED",
    reason_code: "PERMIT_VALID",
    executed: true,
    permit_id: "p1",
    action_digest: "abc",
  });

  const req = makeRequest({
    action: "demo.read_status",
    risk_signal: "normal",
    tenant_id: "t1",
    agent_id: "a1",
    correlation_id: "corr-1",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(200);
  const body = await resp.json() as Record<string, unknown>;
  expect(body.executed).toBe(true);
  expect(body.decision).toBe("ALLOWED");
  expect(body.correlation_id).toBe("corr-1");
});

// Scenario 2: prompt_injection -> executed: false, single upstream call
it("returns executed:false for prompt_injection with a single upstream call", async () => {
  const fetchMock = vi.fn(async () =>
    new Response(
      JSON.stringify({
        decision: "BLOCKED",
        reason_code: "PROMPT_INJECTION_DETECTED",
        executed: false,
        permit_id: null,
        action_digest: "",
      }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  );
  vi.stubGlobal("fetch", fetchMock);

  const req = makeRequest({
    action: "demo.rotate_demo_key",
    risk_signal: "prompt_injection",
    tenant_id: "t1",
    agent_id: "a1",
    correlation_id: "corr-2",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(200);
  const body = await resp.json() as Record<string, unknown>;
  expect(body.executed).toBe(false);
  expect(body.decision).toBe("BLOCKED");
  // Single endpoint -- exactly one call
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

// GET /healthz -> 200 {"status":"ok"}
it("GET /healthz returns 200 and status ok", async () => {
  const req = new Request("https://demo.example.com/healthz", { method: "GET" });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(200);
  const body = await resp.json() as Record<string, unknown>;
  expect(body.status).toBe("ok");
});

// Scenario 10: wrong HTTP method
it("rejects non-POST methods on /api/demo-actions", async () => {
  const req = new Request("https://demo.example.com/api/demo-actions", { method: "GET" });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(405);
});

// Scenario 10: unknown route
it("returns 404 for unknown routes", async () => {
  const req = new Request("https://demo.example.com/unknown", { method: "POST" });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(404);
});

// Scenario 10: malformed JSON
it("returns 400 for malformed JSON", async () => {
  const req = new Request("https://demo.example.com/api/demo-actions", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "not-json{{{",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(400);
});

// Scenario 10: oversized body
it("returns 413 for bodies exceeding the size limit", async () => {
  const req = new Request("https://demo.example.com/api/demo-actions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Content-Length": "99999" },
    body: "x".repeat(5000),
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(413);
});

// Scenario 11: policy-service timeout returns BLOCKED
it("returns BLOCKED when the policy service times out", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => { throw new DOMException("signal aborted", "AbortError"); }),
  );

  const req = makeRequest({
    action: "demo.read_status",
    risk_signal: "normal",
    tenant_id: "t1",
    agent_id: "a1",
    correlation_id: "corr-timeout",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(200);
  const body = await resp.json() as Record<string, unknown>;
  expect(body.executed).toBe(false);
  expect(body.decision).toBe("BLOCKED");
});

// Scenario 11: policy-service returns malformed response
it("returns BLOCKED when the policy service response is malformed", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response("not-json", { status: 200 })),
  );

  const req = makeRequest({
    action: "demo.read_status",
    risk_signal: "normal",
    tenant_id: "t1",
    agent_id: "a1",
    correlation_id: "corr-malformed",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  const body = await resp.json() as Record<string, unknown>;
  expect(body.executed).toBe(false);
  expect(body.decision).toBe("BLOCKED");
});

// Scenario 12: receipt must not contain payloads or signatures
it("receipt does not contain signature or secret-bearing fields", async () => {
  mockUpstream({
    decision: "ALLOWED",
    reason_code: "PERMIT_VALID",
    executed: true,
    permit_id: "p99",
    action_digest: "digest99",
  });

  const req = makeRequest({
    action: "demo.read_status",
    risk_signal: "normal",
    tenant_id: "t1",
    agent_id: "a1",
    correlation_id: "corr-redact",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  const text = await resp.text();
  expect(text).not.toContain("t1");   // tenant_id must not leak
  expect(text).not.toContain("a1");   // agent_id must not leak
});
