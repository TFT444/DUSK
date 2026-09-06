# Live Sandbox Evidence Runner

The restricted proxy verifies signed permits before invoking a caller-supplied executor. Deployments must separately ensure tools cannot be reached outside the proxy. A future live demonstration should run with a real provider in an isolated sandbox and capture the following fields for every scenario:

- model identifier and provider
- action type and protected target
- DUSK decision and reason
- execution status, either `allowed and executed` or `blocked before execution`
- trace identifier

The `dusk.proxy_evidence` module is currently a placeholder; no evidence formatter or live runner is implemented by this PR. A future formatter must record only safe summary fields and exclude credentials, prompts containing secrets, raw tokens, and private customer data.

## Demonstration sequence

1. Show the provider and enforce mode, with credentials hidden.
2. Run one benign action and show the proxy allowing execution.
3. Run a high-risk action and show the proxy blocking it before the executor is called.
4. Activate the emergency kill switch and show that even a valid permit cannot execute.
5. Show the redacted per-scenario records and final counts.

This is sandbox evidence of pre-execution control. It is not a production certification, penetration test, or claim of universal protection.
