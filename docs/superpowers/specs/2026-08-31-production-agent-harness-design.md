# DUSK Production Agent Harness Design

Date: 2026-08-31

Status: Proposed

Target branch: `dev`

Target baseline: `c7bcb9bf65fc1bf3c20e888489e274cfd14c0504`

## Purpose

DUSK has moved beyond a demonstration-only agent monitor. The real provider harness, protected model validation, security scenarios, evidence tooling, and Docker services should live in a production-owned root directory rather than under `examples/`.

This change creates a root-level `dusk-agent-harness/` package for authenticated Bedrock Mantle validation of these models:

- Kimi K2.5: `moonshotai.kimi-k2.5`
- GLM-5: `zai.glm-5`
- Qwen3 32B: `qwen.qwen3-32b`
- GPT OSS 120B: `openai.gpt-oss-120b`

One protected dev workflow will run either GPT qualification alone or the complete four-model matrix. The aggregate gate will fail if any required model fails, errors, skips, is cancelled, or produces invalid evidence.

## Approaches Considered

### 1. Keep the harness under `examples/`

This is the smallest change, but it continues to describe authenticated security validation as sample code. It also leaves production workflows dependent on demo-oriented paths and names.

Decision: rejected.

### 2. Copy the working harness into a new production folder

This reduces initial migration risk, but creates two implementations that can drift. Security fixes, model profiles, tests, and evidence rules could diverge between the copied trees.

Decision: rejected.

### 3. Move the working harness into one production root

Move the existing proven implementation to `dusk-agent-harness/`, update every repository reference, and remove the old `examples/agent-action-monitor/` tree in the same pull request. Preserve Git history through file moves where possible.

Decision: selected.

## Target Structure

```text
dusk-agent-harness/
  README.md
  pyproject.toml
  requirements-real-agent.in
  requirements-real-agent.txt
  .env.example
  Dockerfile
  compose.yml
  compose.ci.yml
  compose.enforce.yml
  runtime/
    bedrock_client.py
    harness.py
    run_scenario.py
    load_driver.py
  models/
    registry.py
    kimi_k2_5.py
    glm_5.py
    qwen3_32b.py
    gpt_oss_120b.py
  gate/
    src/dusk/
  scenarios/
    prompts/
    test_real_llm_gate.py
    test_result_contract.py
    test_canary_secrets.py
  evidence/
    validate_real_agent_evidence.py
  contracts/
  mock_prod/
  scripts/
  tests/
  docs/
```

The exact Python package layout may use import-safe names such as underscores. Public model slugs and provider model IDs remain unchanged.

## Components

### Model registry

`models/registry.py` is the single source of truth for supported models. Each entry records:

- Human-readable name
- Stable slug
- Exact Bedrock Mantle model ID
- Provider route
- Timeout and retry profile
- Token limit behavior
- Whether client correction is supported

Model-specific behavior stays isolated in model profile modules. Shared provider and gate behavior remains common.

The protected workflow must use the same fixed model set. CI contract tests will compare workflow model IDs with the registry so the two cannot silently drift.

### Runtime

The runtime sends authenticated requests through Bedrock Mantle, parses the provider response, converts tool calls into DUSK actions, and submits those actions to DUSK Gate. It must not log credentials, bearer tokens, canary values, or sensitive prompt contents.

The existing working provider behavior is migrated without changing the passing Kimi, GLM, Qwen, or GPT request profiles.

### Security scenarios

The real LLM suite continues to test:

- A clean route-table task
- Injected public SSH exposure
- Role escalation
- Bulk customer-data export
- Restricted audit-log deletion
- MITRE ATT&CK and ATLAS mappings
- Repeat-offense scoring
- Canary-secret containment

Every required scenario must execute. A skip invalidates the run.

### Evidence

Each model writes an isolated evidence directory containing:

- Non-empty JUnit XML
- Non-empty DUSK Gate log
- Evidence manifest
- Exact provider and model ID
- Model slug
- Commit SHA
- GitHub run ID
- Gate mode
- Test totals with zero failures, errors, and skips

Artifacts remain retained for 30 days in the protected dev workflow.

### Docker services

The root harness owns the DUSK Gate and mock production services used by protected validation. The workflow starts only persistent services. One-shot test containers are not included in `docker compose up --wait`.

### Protected workflow

`.github/workflows/real-agent-sandbox-dev.yml` remains the registered dev entry point and changes its working directory to `dusk-agent-harness/`.

Dispatch choices:

- `gpt-oss-qualification`: runs only GPT OSS 120B and forces enforce mode.
- `full-matrix`: runs Kimi K2.5, GLM-5, Qwen3 32B, and GPT OSS 120B together.

The workflow keeps:

- `refs/heads/dev` guard
- Protected `real-agent-dev` environment
- OIDC credentials
- Least-privileged Mantle permissions
- Hash-locked dependency installation
- Per-model artifacts
- Cleanup on success or failure
- Strict aggregate result gate

The production main workflow is updated only for path changes. Its model behavior and environment boundary remain unchanged.

## Migration

The migration is atomic in one pull request:

1. Add contract tests that expect the production path and registry.
2. Move the current harness tree to `dusk-agent-harness/`.
3. Split `agent-demo` into `runtime/` and `models/` without changing provider behavior.
4. Move real LLM tests into `scenarios/` and preserve their assertions.
5. Update Docker build contexts and Compose paths.
6. Update dev and main workflows.
7. Update CI scripts, repository checks, documentation, and OWASP run scripts.
8. Remove all active references to `examples/agent-action-monitor/`.
9. Run the complete local CI contract and container validation.
10. Open one reviewed pull request into `dev`.
11. After merge and protected approval, run GPT qualification and then the full matrix from `dev`.

No compatibility copy remains after the pull request. Git history preserves file ancestry where Git can detect the moves.

## Failure Handling

- Missing environment values fail before AWS credential issuance.
- A non-dev ref fails before AWS credential issuance.
- Unsupported model IDs fail registry lookup.
- Provider timeouts use only the verified model profile.
- A missing tool call fails required attack scenarios.
- Missing, empty, skipped, or mismatched evidence fails validation.
- Failure, cancellation, or skip from any model fails the aggregate matrix gate.
- Docker cleanup always runs.

## Testing

### Contract tests

- Exact four-model registry
- Exact workflow model set
- GPT-only qualification selection
- Full matrix selection
- Forced enforce mode for GPT qualification
- No arbitrary model override
- Registry and workflow consistency
- Dev and main branch guards
- OIDC and protected environment boundaries
- Evidence metadata consistency

### Runtime tests

- Provider request construction
- Model-specific retry and token behavior
- Tool-call parsing
- DUSK action conversion
- Gate response contract
- Secret and token redaction

### Integration tests

- DUSK Gate health
- Mock production reachability
- Watch and enforce behavior
- Downstream isolation
- Non-empty evidence generation
- Container startup and cleanup

### Protected validation

- Two consecutive GPT OSS qualification runs in enforce mode
- One complete four-model matrix run
- Zero failures
- Zero errors
- Zero skips
- Valid JUnit, gate logs, and manifests for every model

## Security Boundaries

- No credentials or provider tokens are stored in the repository.
- GitHub OIDC issues short-lived AWS credentials only after protected environment approval.
- Model IDs are fixed in code and workflow configuration.
- IAM permissions are not widened by this migration.
- Test prompts and logs must not expose secrets.
- Evidence claims apply only to the exact tested model, commit, scenarios, region, and run.

## Acceptance Criteria

The migration is complete when:

- `dusk-agent-harness/` is the only active real-agent harness directory.
- No active workflow, CI script, Docker file, or documentation references `examples/agent-action-monitor/`.
- All four models are represented once in the central registry.
- One dev workflow can run GPT qualification or the complete matrix.
- Local contract, runtime, integration, lint, security, and container checks pass.
- Repository CI passes on the exact pull request head.
- Required approval is present and no review thread is unresolved.
- Protected GPT qualification and full-matrix evidence pass after merge.

## Claim Boundary

Passing this design proves that the named models and scenarios completed the protected DUSK harness contract for an exact commit. It does not prove universal attack coverage, production deployment, long-term reliability, or protection against every unseen multi-agent attack.
