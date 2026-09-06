# Main Bedrock Mantle Validation Design

## Status

Approved for implementation on 28 August 2026.

## Goal

Make the protected `main` real-agent workflow reproduce the same Kimi K2.5 through Bedrock Mantle execution path that completed two successful protected runs on `dev`, while keeping AWS identities and GitHub environments isolated.

## Verified starting point

The live dev runs used commit `147d06dcda2dcf7ec413ad951d95a9427984e880` and completed with 26 tests passed, zero failures, zero errors, and zero skips in each run. Current promoted code is executable-equivalent to that commit. The main gap is configuration and workflow selection:

- `real-agent-dev` uses `eu-west-2`, `BEDROCK_PROVIDER=mantle`, `moonshotai.kimi-k2.5`, and `DuskRealAgentDevMantleRole`.
- `real-agent` uses `us-east-1`, `us.anthropic.claude-sonnet-4-6`, and `DuskRealAgentBedrockRole`.
- The existing main workflow assumes Bedrock Runtime inference profiles and does not propagate `BEDROCK_PROVIDER`.

## Security invariants

1. The dev role and dev environment remain unchanged.
2. Main receives a separate `DuskRealAgentMainMantleRole`.
3. Main OIDC trust accepts exactly the immutable ShieldTech-Ltd/DUSK identity and `environment:real-agent` subject.
4. The main role cannot be assumed from `dev`, pull requests, forks, arbitrary branches, or `real-agent-dev`.
5. The role grants only short-term Mantle bearer-token authentication and scoped project inference permissions.
6. The role grants neither `bedrock:InvokeModel` nor `bedrock:ListInferenceProfiles`.
7. No static AWS credentials, bearer tokens, or secret values enter workflow YAML, logs, documentation, or stack outputs.
8. The `real-agent` GitHub environment remains restricted to `main`, requires `ritiksah141`, and prevents self-review.
9. The workflow fails before AWS credential issuance when it is not running from `refs/heads/main`.
10. Missing configuration, no-action responses after the bounded retry, wrong tools, gate failures, and skipped protected tests remain failures.

## Architecture

### Main workflow

`.github/workflows/real-agent-sandbox.yml` will use the existing provider abstraction rather than a separate main-only client. It will set these job variables from the protected environment:

- `AWS_REGION`
- `BEDROCK_PROVIDER`
- `BEDROCK_MODEL_ID`

The preflight will require all four environment variables, including `AWS_ROLE_ARN`, plus `DUSK_GATE_API_KEY`.

The Runtime-only inference-profile discovery step will be removed because Mantle model identifiers are not Bedrock Runtime inference profiles. AWS identity verification remains. The workflow will use the same persistent-service Compose command as the proven dev workflow:

```text
docker compose -f compose.yml -f compose.ci.yml up -d --wait dusk-gate mock-prod
```

The real-LLM step will pass `USE_REAL_BEDROCK=true`. The Python client will read `BEDROCK_PROVIDER=mantle` and use the existing Mantle provider, adapter, target constraints, and one-time no-action retry.

Evidence collection will be stage-aware. If the gate container was never created, the artifact will record that status without hiding the earlier root failure. If the gate exists, its log must be non-empty. JUnit must report at least one test, zero failures, zero errors, and zero skips for a successful protected run.

### Main IAM stack

A new template at `infra/aws/bedrock-mantle-main/template.yaml` will follow the validated dev template while changing only main-specific identity values:

- Default GitHub environment: `real-agent`
- Default role: `DuskRealAgentMainMantleRole`
- Inline policy name: `BedrockMantleMainInference`
- OIDC subject: exact `environment:${GitHubEnvironment}`, validated by the setup script as `real-agent`

The allowed actions remain exactly:

- `bedrock-mantle:CallWithBearerToken`, restricted to `SHORT_TERM`
- `bedrock-mantle:CreateInference`
- `bedrock-mantle:GetProject`
- `bedrock-mantle:ListProjects`
- `bedrock-mantle:ListTagsForResource`

Project operations remain scoped to the current account, current region, and `project/*` resource.

### Setup and deployment

A new `scripts/setup-bedrock-mantle-main.ps1` will validate before changing anything:

- AWS and GitHub CLI authentication
- AWS region
- `real-agent` required reviewer includes `ritiksah141`
- self-review prevention remains enabled
- environment deployment policy allows only `main`
- required variable and secret presence
- template identity is exactly `real-agent`
- immutable GitHub organisation and repository IDs

Default execution is read-only. Deployment requires both `-Deploy` and `-Confirm`. Deployment creates or updates stack `dusk-bedrock-mantle-main`, validates the published role ARN, live OIDC trust, attached-policy absence, exact inline policy, allowed actions, resource scope, and short-term token condition. Only after those checks pass will it set `AWS_ROLE_ARN` in `real-agent`.

The script will not change `AWS_REGION`, `BEDROCK_PROVIDER`, `BEDROCK_MODEL_ID`, or `DUSK_GATE_API_KEY`, and it will not dispatch a workflow. Those three non-secret variables will be set explicitly after code promotion and role validation:

```text
AWS_REGION=eu-west-2
BEDROCK_PROVIDER=mantle
BEDROCK_MODEL_ID=moonshotai.kimi-k2.5
```

The existing `DuskRealAgentBedrockRole` will not be modified or deleted. It remains available for rollback.

## Test strategy

Tests will be written first and observed failing before implementation.

### Workflow tests

Main workflow tests will require:

- exact main branch gate before OIDC
- `real-agent` environment
- provider variable preflight and job propagation
- `USE_REAL_BEDROCK=true`
- no Runtime inference-profile discovery in the Mantle path
- persistent-service-only Compose startup with `--wait`
- stage-aware evidence collection
- zero-skip enforcement
- pinned actions and least workflow permissions
- no token generation or printing in workflow steps

### IAM tests

Main template and setup tests will require:

- separate main and dev roles
- exact immutable main OIDC subject
- exact action allowlist
- short-term bearer-token condition
- scoped project resources
- no Runtime inference permissions
- no attached policies or extra inline statements
- main-only environment deployment branch validation
- required reviewer and self-review protection validation
- deployment confirmation gate
- no automatic workflow dispatch

### Regression tests

The existing dev workflow, dev template, provider client, adapter, result contract, dependency lock, and live-test behavior must remain unchanged and continue passing their existing tests.

## Rollout sequence

1. Implement through a feature branch targeting `dev`.
2. Run focused workflow and IAM tests, full repository tests, Ruff, actionlint, zizmor, and secret scanning.
3. Review and merge the feature PR into `dev`.
4. Promote reviewed `dev` into `main` through a separate PR.
5. Run the main setup script in validation-only mode.
6. Deploy the separate main Mantle stack with explicit confirmation.
7. Set the three main environment provider variables to the proven values.
8. Re-run validation-only mode and confirm the role and environment state.
9. Dispatch the main workflow in `enforce` mode.
10. Obtain `ritiksah141` environment approval.
11. Inspect the terminal workflow state, JUnit artifact, gate log, test counts, skips, and credential-leak indicators.
12. Record the successful main run in the sandbox evidence document.

## Rollback

If the main Mantle run fails because of provider or environment configuration, do not weaken tests or IAM. Restore the previous `real-agent` variable values and `AWS_ROLE_ARN` pointing to `DuskRealAgentBedrockRole`. The new main Mantle role remains isolated and can be inspected or removed later through an explicit infrastructure change.

## Acceptance criteria

The work is complete only when:

- all code and security checks pass;
- the dev and main promotion PRs receive required approval;
- the main IAM role and GitHub environment match the design;
- a protected `main` enforce-mode run completes against Kimi K2.5;
- the downloaded JUnit report contains tests and reports zero failures, zero errors, and zero skips;
- the gate log is non-empty and contains no detected credentials or raw bearer token;
- the main run uses the promoted commit recorded in the evidence.
