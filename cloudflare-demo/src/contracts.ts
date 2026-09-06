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
  signal: DemoSignal;
  tenant_id: string;
  agent_id: string;
  correlation_id: string;
}

/** Redacted receipt returned to the client. Never contains payloads or secrets. */
export interface DemoReceipt {
  correlation_id: string;
  decision: "ALLOW" | "BLOCKED";
  reason_code: string;
  permit_id: string | null;
  action_digest: string;
  executed: boolean;
  timestamp: string;
}

/** Permit issued by the Python policy service. */
export interface IssuedPermit {
  permit_id: string;
  action: string;
  action_digest: string;
  tenant_id: string;
  agent_id: string;
  issued_at: number;
  expires_at: number;
  signature: string;
}

/** Response from POST /v1/demo/evaluate */
export interface EvalResponse {
  decision: "ALLOW" | "BLOCK";
  reason_code: string;
  permit?: IssuedPermit;
}

/** Response from POST /v1/demo/execute */
export interface ExecResponse {
  executed: boolean;
  decision: string;
  reason_code: string;
  permit_id: string | null;
  action_digest: string;
}
