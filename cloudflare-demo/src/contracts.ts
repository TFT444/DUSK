/** Strict request and response types for the DUSK Cloudflare edge demo. */

export const ALLOWED_ACTIONS = ["demo.read_status", "demo.rotate_demo_key"] as const;
export const ALLOWED_SIGNALS = ["normal", "prompt_injection"] as const;

export type DemoAction = (typeof ALLOWED_ACTIONS)[number];
export type DemoSignal = (typeof ALLOWED_SIGNALS)[number];

/** Maximum request body size accepted by the Worker (bytes). */
export const BODY_LIMIT = 4096;

/** Upstream call timeout in milliseconds. */
export const UPSTREAM_TIMEOUT_MS = 5000;

/** Fields accepted from the client. Unknown fields cause rejection. */
export interface DemoRequest {
  action: DemoAction;
  risk_signal: DemoSignal;
  tenant_id: string;
  agent_id: string;
  correlation_id: string;
}

/** Redacted receipt returned to the client. Never contains payloads or secrets. */
export interface DemoReceipt {
  correlation_id: string;
  decision: "ALLOWED" | "BLOCKED";
  reason_code: string;
  permit_id: string | null;
  action_digest: string;
  executed: boolean;
  timestamp: string;
}

/** Response from POST /v1/demo/authorize-and-execute */
export interface AuthExecResponse {
  decision: "ALLOWED" | "BLOCKED";
  reason_code: string;
  executed: boolean;
  permit_id: string | null;
  action_digest: string;
}
