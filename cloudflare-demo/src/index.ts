/**
 * DUSK Cloudflare edge demo Worker.
 *
 * Transport layer only. Never the final enforcement boundary.
 * Enforcement chain:
 *   Client -> Worker -> Python policy service (/v1/demo/authorize-and-execute) -> receipt
 *
 * Security properties:
 * - Strict schema: unknown fields, methods, and routes are rejected immediately.
 * - Body size limit: enforced before parsing.
 * - HMAC-signed upstream calls with per-request timestamp and nonce.
 * - Short upstream timeout: fails closed on timeout or error.
 * - Redacted receipts: no payloads, signatures, IPs, or secrets returned.
 */

import { parseDemoRequest, signRequest } from "./demo-actions.js";
import {
  BODY_LIMIT,
  UPSTREAM_TIMEOUT_MS,
  type AuthExecResponse,
  type DemoReceipt,
} from "./contracts.js";

export interface Env {
  DUSK_DEMO_ORIGIN: string;
  DUSK_DEMO_SHARED_SECRET: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function blocked(correlationId: string, reasonCode: string, actionDigest = ""): Response {
  const receipt: DemoReceipt = {
    correlation_id: correlationId,
    decision: "BLOCKED",
    reason_code: reasonCode,
    permit_id: null,
    action_digest: actionDigest,
    executed: false,
    timestamp: new Date().toISOString(),
  };
  return Response.json(receipt, { status: 200 });
}

function jsonError(status: number, message: string): Response {
  return Response.json({ error: message }, { status });
}

async function callUpstream(
  env: Env,
  path: string,
  body: object,
): Promise<Response | null> {
  const bodyBytes = new TextEncoder().encode(JSON.stringify(body));
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomUUID();

  const sig = await signRequest(
    env.DUSK_DEMO_SHARED_SECRET,
    "POST",
    path,
    timestamp,
    nonce,
    bodyBytes,
  );

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const resp = await fetch(`${env.DUSK_DEMO_ORIGIN}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Timestamp": timestamp,
        "X-Nonce": nonce,
        "X-Hmac-Signature": sig,
      },
      body: bodyBytes,
      signal: controller.signal,
    });
    return resp;
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ---------------------------------------------------------------------------
// Fetch handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check (Worker readiness only -- does not verify Python service)
    if (url.pathname === "/healthz") {
      if (request.method !== "GET") return jsonError(405, "method not allowed");
      return Response.json({ status: "ok" }, { status: 200 });
    }

    if (url.pathname !== "/api/demo-actions") return jsonError(404, "not found");
    if (request.method !== "POST") return jsonError(405, "method not allowed");

    // Body size guard
    const contentLength = parseInt(request.headers.get("Content-Length") ?? "0", 10);
    if (contentLength > BODY_LIMIT) return jsonError(413, "body too large");

    // Parse body with size cap
    let rawText: string;
    try {
      const cloned = request.clone();
      rawText = await Promise.race([
        cloned.text(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("read timeout")), 2000),
        ),
      ]);
      if (rawText.length > BODY_LIMIT) return jsonError(413, "body too large");
    } catch {
      return jsonError(400, "could not read body");
    }

    // Parse JSON
    let rawObj: unknown;
    try {
      rawObj = JSON.parse(rawText);
    } catch {
      return jsonError(400, "invalid json");
    }

    // Validate schema
    const demoReq = parseDemoRequest(rawObj);
    if (demoReq === null) return jsonError(400, "invalid request");

    const { action, risk_signal, tenant_id, agent_id, correlation_id } = demoReq;

    // Single upstream call: policy + execution in one shot
    const upstreamBody = { action, risk_signal, tenant_id, agent_id };
    const upstreamResp = await callUpstream(
      env,
      "/v1/demo/authorize-and-execute",
      upstreamBody,
    );

    if (upstreamResp === null) {
      return blocked(correlation_id, "UPSTREAM_UNAVAILABLE");
    }

    let authExec: AuthExecResponse;
    try {
      authExec = (await upstreamResp.json()) as AuthExecResponse;
      if (typeof authExec.executed !== "boolean") throw new Error("bad shape");
      if (authExec.decision !== "ALLOWED" && authExec.decision !== "BLOCKED") {
        throw new Error("bad decision");
      }
    } catch {
      return blocked(correlation_id, "UPSTREAM_BAD_RESPONSE");
    }

    // Redacted receipt -- no payloads, signatures, IPs, or secret values
    const receipt: DemoReceipt = {
      correlation_id,
      decision: authExec.executed ? "ALLOWED" : "BLOCKED",
      reason_code: authExec.reason_code ?? "UNKNOWN",
      permit_id: authExec.executed ? (authExec.permit_id ?? null) : null,
      action_digest: authExec.action_digest ?? "",
      executed: authExec.executed,
      timestamp: new Date().toISOString(),
    };

    return Response.json(receipt, { status: 200 });
  },
};
