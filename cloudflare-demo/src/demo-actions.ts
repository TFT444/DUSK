/** Validation helpers for demo action requests. */

import {
  ALLOWED_ACTIONS,
  ALLOWED_SIGNALS,
  type DemoAction,
  type DemoRequest,
  type DemoSignal,
} from "./contracts.js";

/** Parse and validate a raw object as a DemoRequest. Returns null on any violation. */
export function parseDemoRequest(raw: unknown): DemoRequest | null {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return null;

  const obj = raw as Record<string, unknown>;

  // Reject unexpected fields
  const allowed = new Set(["action", "risk_signal", "tenant_id", "agent_id", "correlation_id"]);
  for (const key of Object.keys(obj)) {
    if (!allowed.has(key)) return null;
  }

  const { action, risk_signal, tenant_id, agent_id, correlation_id } = obj;

  if (typeof action !== "string" || !(ALLOWED_ACTIONS as readonly string[]).includes(action))
    return null;
  if (typeof risk_signal !== "string" || !(ALLOWED_SIGNALS as readonly string[]).includes(risk_signal))
    return null;
  if (typeof tenant_id !== "string" || !tenant_id) return null;
  if (typeof agent_id !== "string" || !agent_id) return null;
  if (typeof correlation_id !== "string" || !correlation_id) return null;

  return {
    action: action as DemoAction,
    risk_signal: risk_signal as DemoSignal,
    tenant_id,
    agent_id,
    correlation_id,
  };
}

/** Compute a hex HMAC-SHA-256 signature for Worker to policy service requests. */
export async function signRequest(
  secret: string,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  body: Uint8Array,
): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const prefix = enc.encode(`${method}\n${path}\n${timestamp}\n${nonce}\n`);
  const msg = new Uint8Array(prefix.length + body.length);
  msg.set(prefix);
  msg.set(body, prefix.length);
  const sigBuffer = await crypto.subtle.sign("HMAC", keyMaterial, msg);
  return Array.from(new Uint8Array(sigBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
