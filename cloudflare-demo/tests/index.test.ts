/**
 * Worker unit tests — all 12 prompt-doc scenarios plus edge cases.
 * The policy service is mocked; no network or process is started.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";
import { parseDemoRequest } from "../src/demo-actions.js";

// ---------------------------------------------------------------------------
// parseDemoRequest — input validation
// ---------------------------------------------------------------------------

describe("parseDemoRequest", () => {
  it("accepts a valid demo.read_status normal request", () => {
    const result = parseDemoRequest({
      action: "demo.read_status",
      signal: "normal",
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
      signal: "prompt_injection",
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
        signal: "normal",
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
        signal: "suspicious",
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
        signal: "normal",
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
        signal: "normal",
        tenant_id: "",
        agent_id: "a1",
        correlation_id: "c1",
      }),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Worker fetch handler — integration-style tests with mocked upstream
// ---------------------------------------------------------------------------

import worker from "../src/index.js";

const ENV = {
  POLICY_URL: "http://127.0.0.1:8787",
  HMAC_SECRET: "test-hmac-secret-32bytes-padding!",
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

function mockUpstream(evalResp: object, execResp?: object): void {
  let call = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, _opts: RequestInit) => {
      call++;
      if (call === 1) {
        return new Response(JSON.stringify(evalResp), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify(execResp ?? {}), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
}

// Scenario 1: allowed demo.read_status → executed: true
it("returns executed:true for demo.read_status with normal signal", async () => {
  mockUpstream(
    {
      decision: "ALLOW",
      reason_code: "POLICY_ALLOWED",
      permit: {
        permit_id: "p1",
        action: "demo.read_status",
        action_digest: "abc",
        tenant_id: "t1",
        agent_id: "a1",
        issued_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 60,
        signature: "aabbcc",
      },
    },
    {
      executed: true,
      decision: "ALLOW",
      reason_code: "PERMIT_VALID",
      permit_id: "p1",
      action_digest: "abc",
    },
  );

  const req = makeRequest({
    action: "demo.read_status",
    signal: "normal",
    tenant_id: "t1",
    agent_id: "a1",
    correlation_id: "corr-1",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(200);
  const body = await resp.json() as Record<string, unknown>;
  expect(body.executed).toBe(true);
  expect(body.decision).toBe("ALLOW");
  expect(body.correlation_id).toBe("corr-1");
});

// Scenario 2: prompt_injection → executed: false, no permit call
it("returns executed:false for prompt_injection without calling executor", async () => {
  const fetchMock = vi.fn(async () =>
    new Response(
      JSON.stringify({ decision: "BLOCK", reason_code: "PROMPT_INJECTION_DETECTED" }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    ),
  );
  vi.stubGlobal("fetch", fetchMock);

  const req = makeRequest({
    action: "demo.rotate_demo_key",
    signal: "prompt_injection",
    tenant_id: "t1",
    agent_id: "a1",
    correlation_id: "corr-2",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  expect(resp.status).toBe(200);
  const body = await resp.json() as Record<string, unknown>;
  expect(body.executed).toBe(false);
  expect(body.decision).toBe("BLOCKED");
  // Must have called evaluate but NOT execute
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

// Scenario 10: wrong HTTP method
it("rejects non-POST methods", async () => {
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
  // Simulate an aborted/timed-out upstream call by rejecting immediately.
  // callUpstream catches the error and returns null, which triggers BLOCKED.
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => { throw new DOMException("signal aborted", "AbortError"); }),
  );

  const req = makeRequest({
    action: "demo.read_status",
    signal: "normal",
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
    signal: "normal",
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
  mockUpstream(
    {
      decision: "ALLOW",
      reason_code: "POLICY_ALLOWED",
      permit: {
        permit_id: "p99",
        action: "demo.read_status",
        action_digest: "digest99",
        tenant_id: "t1",
        agent_id: "a1",
        issued_at: Math.floor(Date.now() / 1000),
        expires_at: Math.floor(Date.now() / 1000) + 60,
        signature: "secret-signature-value",
      },
    },
    {
      executed: true,
      decision: "ALLOW",
      reason_code: "PERMIT_VALID",
      permit_id: "p99",
      action_digest: "digest99",
    },
  );

  const req = makeRequest({
    action: "demo.read_status",
    signal: "normal",
    tenant_id: "t1",
    agent_id: "a1",
    correlation_id: "corr-redact",
  });
  const resp = await worker.fetch(req, ENV, {} as ExecutionContext);
  const text = await resp.text();
  expect(text).not.toContain("secret-signature-value");
  expect(text).not.toContain("t1");   // tenant_id must not leak
  expect(text).not.toContain("a1");   // agent_id must not leak
});
