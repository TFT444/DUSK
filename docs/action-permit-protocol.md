# DUSK Action Permit Protocol

An Action Permit is a short-lived, signed authorization for one exact agent action. The permit is an authorization artifact, not an API credential.

## Claims

Each permit binds:

- `permit_id`, a unique identifier used for replay detection
- `tenant_id` and `agent_id`, the execution context
- `action`, the complete canonical tool action
- `policy_version`, the policy decision version that approved it
- `issued_at` and `expires_at`, UTC timestamps
- `signature`, an URL-safe Ed25519 signature over the canonical JSON claims

## Lifecycle

1. The policy evaluator approves an action.
2. A trusted issuer creates a permit with a short TTL, normally 30 seconds.
3. The restricted execution proxy verifies the signature and every binding.
4. The proxy consumes `permit_id` through a replay guard.
5. Only a successfully verified and consumed permit may reach the protected tool.

## Fail-closed rules

Verification rejects an invalid signature, unknown or malformed signature encoding, tenant or agent mismatch, action mismatch, policy-version mismatch, expired permit, permit issued in the future, non-positive TTL, or a previously consumed permit. A failed verification must not call the protected execution target.

## Key handling

Callers provide Ed25519 keys from their own secret-management system. DUSK does not write private keys to disk, logs, receipts, or source control. Key rotation and public-key distribution belong to the control plane integration. The in-memory `ReplayGuard` is a reference implementation and should be replaced with a customer-owned shared store for distributed execution.

## Scope boundary

This module proves permit integrity and action binding. It does not itself decide whether an action is safe, provide an HSM, distribute keys, or replace the policy engine. Those integrations are follow-up work in issues #232 and #189.
