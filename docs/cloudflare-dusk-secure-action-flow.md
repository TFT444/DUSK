# Cloudflare and DUSK protected-action sandbox flow

## Purpose

This sandbox flow demonstrates how Cloudflare AI Gateway and DUSK have separate responsibilities. The gateway carries a model request. DUSK controls whether a proposed consequential tool action may receive a short-lived permit and reach a restricted executor.

```text
Agent -> Cloudflare AI Gateway -> Model response -> proposed action
      -> DUSK authorization policy -> signed Action Permit
      -> restricted execution proxy -> approved sandbox tool
      -> redacted receipt
```

## Enforcement stages

DUSK evaluates policy twice:

1. `authorization`: evaluates the proposed action. Permit rules do not run because no permit exists yet.
2. `execution`: runs after proxy verification. Permit rules and action policy run before the sandbox tool executor.

The authorization stage does not invent a valid permit. The proxy provides the execution-stage permit facts only after cryptographic verification succeeds.

## Sandbox guarantees

The `SecureActionFlow` implementation proves these behaviors in automated tests:

- An allowed action is forwarded through the gateway, authorized, permitted, verified, executed, and recorded.
- A denied action does not reach the tool executor.
- Gateway failure fails closed before permit issuance or execution.
- The emergency kill switch prevents execution even after authorization.
- Existing permit tests reject expired, replayed, altered, and incorrectly signed permits.
- Receipts record a trace identifier, action digest, policy version, rule identifiers, gateway status, and execution status. They do not contain prompts, targets, tool output, credentials, or tokens.

## Boundaries

This is controlled sandbox evidence using the existing mocked HTTP gateway boundary and a caller-supplied sandbox tool. It is not live Cloudflare evidence, a production deployment, or proof that all model outputs are safe.

A production integration must add a real provider workflow, shared replay storage, managed signing-key rotation, target-specific executor restrictions, durable audit persistence, and protected evidence runs.
