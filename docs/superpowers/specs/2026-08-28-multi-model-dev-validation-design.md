# Strict Multi-Model Dev Validation Design

Date: 2026-08-28

Status: Proposed for user review

Target repository: `ShieldTech-Ltd/DUSK`

Target branch flow: feature branch to `dev`, then reviewed `dev` to `main`

## Purpose

DUSK currently has one proven protected Bedrock Mantle validation route using
Kimi K2.5. This change extends that exact route to three source-controlled
models without weakening any existing security, evidence, or zero-skip gate:

| Model | Bedrock Mantle model ID |
| --- | --- |
| Kimi K2.5 | `moonshotai.kimi-k2.5` |
| GLM 5 | `zai.glm-5` |
| NVIDIA Nemotron 3 Super 120B | `nvidia.nemotron-super-3-120b` |

The three models use the same London Mantle endpoint, OpenAI Chat Completions
request shape, client-side tool calling contract, DUSK prompts, gate, Docker
services, IAM role, and evidence requirements. Kimi remains the reference
contract because it already completed the protected sandbox route
successfully.

## Scope

This work will be delivered in one branch and one pull request into `dev`.
That pull request will contain the design, implementation plan, workflow
changes, tests, and operator documentation.

In scope:

- A fixed, reviewable three-model matrix in the protected dev workflow.
- Independent execution and evidence for every model.
- A strict aggregate gate that passes only when all three model jobs pass.
- Explicit model-availability preflight against the Mantle `/models` endpoint.
- Preservation of the successful Kimi authentication and inference route.
- Tests for matrix membership, isolation, evidence, zero-skip behavior, and
  aggregate failure semantics.
- A reviewed promotion procedure that copies only the proven matrix behavior
  to the protected main workflow.

Out of scope:

- Automatic model selection, retries on a different model, or fallback.
- Bedrock Runtime models such as Claude.
- Changing DUSK verdict thresholds, prompts, gate policies, or scenario
  expectations to make a weaker model pass.
- Adding arbitrary models from environment input.
- Deploying AWS resources or changing GitHub environment values before the
  code is reviewed and merged.

## Design Principles

### Preserve the successful Kimi route

The existing Mantle client, short-term token generator, endpoint, tool schema,
required tool-call behavior, Docker Compose services, test suite, gate modes,
OIDC role, and evidence collection remain the reference implementation. The
matrix supplies a different model ID to the same route. It does not introduce
provider-specific branches for GLM or Nemotron.

If GLM or Nemotron does not satisfy the existing contract, that model job
fails. The implementation must not weaken assertions, accept an unexpected
tool, hide a missing tool call, or silently use Kimi as a fallback.

### Source-controlled allowlist

The three model IDs will be declared directly in the workflow matrix. A
dispatch input cannot add or replace a model. This prevents an unreviewed
environment-variable change from altering the validation target.

`BEDROCK_PROVIDER` remains `mantle`. Each matrix job sets
`BEDROCK_MODEL_ID` from its fixed matrix entry. The existing single
`BEDROCK_MODEL_ID` environment variable is not the authority for the matrix
and will no longer be required by the dev workflow preflight.

### No false green

Every model job must fail if any of the following occurs:

- The model is absent from the authenticated Mantle `/models` response.
- Authentication or model invocation fails.
- The model produces no tool call for a required scenario.
- The model calls an unexpected tool.
- Any protected test fails or errors.
- Any protected test is skipped.
- JUnit evidence is absent, malformed, or reports a non-zero failure, error,
  or skipped count.
- The gate did not start or its evidence is empty.
- Enforce-mode downstream isolation fails.

The aggregate gate must run with `if: always()` and fail unless the complete
matrix job result is `success`. Branch protection can then require this one
stable aggregate check in addition to the existing repository CI.

## Workflow Architecture

The existing `real-agent-dev-validation` job becomes a fixed matrix job:

```yaml
strategy:
  fail-fast: false
  matrix:
    model:
      - slug: kimi-k2-5
        id: moonshotai.kimi-k2.5
      - slug: glm-5
        id: zai.glm-5
      - slug: nemotron-3-super-120b
        id: nvidia.nemotron-super-3-120b
```

Each matrix child:

1. Enters the protected `real-agent-dev` environment.
2. Verifies the exact `dev` ref before obtaining AWS credentials.
3. Validates required environment configuration and secret presence.
4. Installs the existing hash-locked dependencies.
5. Assumes `DuskRealAgentDevMantleRole` through the existing OIDC trust.
6. Confirms AWS caller identity without printing credentials.
7. Confirms its fixed model ID appears in Mantle `/models`.
8. Starts only `dusk-gate` and `mock-prod` with Compose readiness waiting.
9. Runs the existing protected real-LLM scenarios with
   `USE_REAL_BEDROCK=true` and its matrix model ID.
10. Validates the generated JUnit counts.
11. Verifies downstream isolation in enforce mode.
12. Uploads model-specific evidence and stops containers with `if: always()`.

`fail-fast: false` ensures a failed model does not hide the results of the
other two models. Each model receives its own runner and isolated gate state,
so behavioral history and Docker logs cannot leak between models.

The aggregate job depends on the matrix job and does not obtain AWS
credentials. It reports the matrix result and fails unless all three children
succeeded.

## Model Availability Preflight

The preflight will use the same short-term token generator and OpenAI client
already locked for the successful Kimi path. It will call the authenticated
Mantle `/models` endpoint and compare only model IDs. It must never print,
return, persist, or include the bearer token in exceptions or artifacts.

The preflight receives one fixed expected model ID. It succeeds only when that
exact ID is returned. Unit tests will stub token generation and the OpenAI
client so no network or credential is required in ordinary CI.

## Evidence Contract

Each matrix child uploads an artifact named with the safe matrix slug and run
ID, for example:

```text
real-agent-dev-kimi-k2-5-evidence-<run-id>
real-agent-dev-glm-5-evidence-<run-id>
real-agent-dev-nemotron-3-super-120b-evidence-<run-id>
```

Each artifact must contain:

- `real-agent-results.xml`
- `real-agent-gate.log`, or a stage-status file when the gate was never
  created and an earlier step is already the root failure
- a non-secret manifest containing provider, model ID, model slug, Git commit,
  GitHub run ID, gate mode, and parsed test counts

The manifest is evidence metadata, not a credential store. It must not contain
AWS account credentials, bearer tokens, API keys, prompt payloads, or raw
model-derived target data.

## IAM and Security Boundaries

The validated dev Mantle IAM role already grants the endpoint-level and
project-scoped permissions required by all three models:

- `bedrock-mantle:CallWithBearerToken` restricted to `SHORT_TERM`
- `bedrock-mantle:CreateInference`
- `bedrock-mantle:GetProject`
- `bedrock-mantle:ListProjects`
- `bedrock-mantle:ListTagsForResource`

No new IAM action is required. The role remains restricted to the immutable
repository identity and `real-agent-dev` environment. The workflow remains
restricted to `refs/heads/dev`, and the GitHub environment remains restricted
to the `dev` deployment branch with required review and self-review
prevention.

The implementation must not add `bedrock:InvokeModel`, Marketplace
subscription permissions, static AWS keys, long-term Bedrock API keys, or
wildcard IAM actions.

## Testing Strategy

Test-driven implementation will cover:

- The matrix contains exactly the three approved model IDs and safe slugs.
- `fail-fast` is disabled.
- A matrix model ID, not a mutable dispatch input, reaches the test process.
- The existing Kimi endpoint, client, token, and tool-call route is unchanged.
- Model availability preflight accepts an exact match and rejects missing or
  malformed responses without leaking tokens.
- Every model uses a unique artifact and manifest path.
- JUnit verification rejects failures, errors, and skips, not only skips.
- The aggregate job fails unless the complete matrix succeeds.
- Cleanup and evidence collection still run after earlier failures.
- Dev OIDC trust, branch restriction, and IAM allowlist remain unchanged.
- The main workflow remains unchanged in this dev-validation PR.

Ordinary repository CI proves the implementation and mocked contracts. It
does not prove live model behavior. Live evidence requires the protected dev
workflow on one exact commit.

## Live Acceptance Gate

After the PR is reviewed and merged into `dev`, run the protected workflow in
enforce mode. A successful promotion candidate requires all three matrix jobs
and the aggregate job to be green on the same `dev` commit.

For each model, inspect the artifact and confirm:

- zero failed tests
- zero errors
- zero skipped tests
- all required scenarios invoked the expected tool and reached DUSK
- the gate log is present and non-empty
- enforce-mode downstream isolation passed
- the manifest identifies the expected model and exact commit

If one model fails, the complete multi-model promotion is blocked. Fix the
root cause in `dev` and rerun all three. Do not promote only the passing subset
under this design.

## Promotion to Main

Only after the strict dev gate passes will a reviewed `dev` to `main`
promotion be considered. The main workflow will receive the same fixed matrix,
evidence isolation, JUnit validation, and aggregate semantics. The separate
main Mantle role and `real-agent` environment will be deployed and configured
through the already reviewed main setup route.

The protected main workflow must then repeat the three-model enforce run with
zero failures, errors, and skips before DUSK can claim complete main
multi-model sandbox validation.

## External Compatibility Evidence

AWS documents all three selected models as available through the
`bedrock-mantle` endpoint and compatible with OpenAI Chat Completions. AWS also
documents client-side tool calling for their Mantle model cards.

- Kimi K2.5: <https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-moonshot-ai-kimi-k2-5.html>
- GLM 5: <https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-zai-glm-5.html>
- Nemotron 3 Super 120B: <https://docs.aws.amazon.com/bedrock/latest/userguide/model-card-nvidia-nemotron-super-3-120b.html>

AWS documentation establishes platform compatibility, not account-specific
access or DUSK correctness. The protected workflow preflight and live scenario
results remain the authoritative evidence for this repository.
