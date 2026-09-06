# Main Bedrock Mantle Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the protected `main` real-agent workflow reproduce the successful Kimi K2.5 through Bedrock Mantle validation path with a separate least-privilege main identity.

**Architecture:** Reuse the existing provider client, adapter, real-LLM tests, and bounded retry that passed on `dev`. Add a parallel main IAM stack and setup script, then make the existing main-only workflow consume the provider variables and operational safeguards already proven in the dev-only workflow. Keep the existing Claude role unchanged for rollback.

**Tech Stack:** GitHub Actions, AWS IAM and CloudFormation, PowerShell 5.1, Python 3.11, pytest, PyYAML, Docker Compose, Bedrock Mantle OpenAI-compatible API.

**Spec:** `docs/superpowers/specs/2026-08-28-main-mantle-validation-design.md`

## Global Constraints

- Preserve `real-agent-dev`, `DuskRealAgentDevMantleRole`, and the successful dev workflow unchanged.
- Restrict the new role to the immutable ShieldTech-Ltd/DUSK identity and `environment:real-agent`.
- Allow exactly the five proven Mantle actions and no Bedrock Runtime inference actions.
- Never print, store, or return bearer tokens or secret values.
- Keep the main workflow restricted to `refs/heads/main` and the `real-agent` environment.
- Require `ritiksah141`, prevent self-review, and allow only `main` in the environment deployment policy.
- Default setup execution is read-only. AWS or GitHub writes require `-Deploy -Confirm`.
- Do not dispatch a workflow from the setup script.
- Do not modify or delete the existing Claude role.

---

### Task 1: Define the main workflow contract

**Files:**
- Modify: `tests/ci/test_real_agent_workflow.py`
- Modify: `.github/workflows/real-agent-sandbox.yml`

**Interfaces:**
- Consumes: GitHub environment variables `AWS_ROLE_ARN`, `AWS_REGION`, `BEDROCK_PROVIDER`, and `BEDROCK_MODEL_ID`; secret `DUSK_GATE_API_KEY`.
- Produces: A main-only protected workflow that runs the existing real-LLM suite through the selected provider and uploads inspectable evidence.

- [ ] **Step 1: Add failing workflow tests**

Add tests that parse `.github/workflows/real-agent-sandbox.yml` and require:

```python
def test_main_workflow_propagates_mantle_provider_configuration() -> None:
    workflow = _workflow()
    job = workflow["jobs"]["real-agent-validation"]
    assert job["env"] == {
        "AWS_REGION": "${{ vars.AWS_REGION }}",
        "BEDROCK_PROVIDER": "${{ vars.BEDROCK_PROVIDER }}",
        "BEDROCK_MODEL_ID": "${{ vars.BEDROCK_MODEL_ID }}",
    }
    text = _WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "BEDROCK_PROVIDER: ${{ vars.BEDROCK_PROVIDER }}" in text
    assert "USE_REAL_BEDROCK: \"true\"" in text


def test_main_workflow_does_not_require_runtime_inference_profile_for_mantle() -> None:
    text = _WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "list-inference-profiles" not in text
    assert "Verify Bedrock model access" not in text


def test_main_workflow_starts_only_persistent_compose_services() -> None:
    start = next(s for s in _steps() if s.get("name") == "Start gate and mock-prod via Docker Compose")
    assert (
        "docker compose -f compose.yml -f compose.ci.yml up -d --wait dusk-gate mock-prod"
        in start["run"]
    )


def test_main_workflow_log_collection_is_stage_aware() -> None:
    collect = next(s for s in _steps() if s.get("name") == "Collect gate logs as evidence")
    assert "ps -q dusk-gate" in collect["run"]
    assert "gate-not-started" in collect["run"]
```

Extend the existing preflight test to require `BEDROCK_PROVIDER`.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/ci/test_real_agent_workflow.py -q
```

Expected: the new tests fail because the main workflow does not expose `BEDROCK_PROVIDER`, still calls `list-inference-profiles`, does not use `--wait`, and lacks stage-aware collection.

- [ ] **Step 3: Implement the minimum workflow changes**

Update the job environment and preflight:

```yaml
env:
  AWS_REGION: ${{ vars.AWS_REGION }}
  BEDROCK_PROVIDER: ${{ vars.BEDROCK_PROVIDER }}
  BEDROCK_MODEL_ID: ${{ vars.BEDROCK_MODEL_ID }}
```

Remove the Runtime-only `Verify Bedrock model access` step. Keep AWS caller identity verification. Port the exact successful dev Compose command, `USE_REAL_BEDROCK=true`, and stage-aware gate-log collection. Preserve the main branch check, `real-agent` environment, evidence upload, cleanup, and enforce-mode downstream check.

- [ ] **Step 4: Run workflow tests and verify GREEN**

Run:

```powershell
python -m pytest tests/ci/test_real_agent_workflow.py tests/ci/test_real_agent_mantle.py -q
ruff check tests/ci/test_real_agent_workflow.py
actionlint .github/workflows/real-agent-sandbox.yml
```

Expected: all commands exit zero.

- [ ] **Step 5: Commit**

```powershell
git add tests/ci/test_real_agent_workflow.py .github/workflows/real-agent-sandbox.yml
git commit -s -m "ci: run main sandbox through Bedrock Mantle"
```

---

### Task 2: Add the isolated main Mantle IAM stack

**Files:**
- Create: `infra/aws/bedrock-mantle-main/template.yaml`
- Modify: `tests/ci/test_real_agent_mantle.py`

**Interfaces:**
- Consumes: immutable GitHub organisation and repository IDs, existing GitHub OIDC provider ARN, AWS account and region pseudo-parameters.
- Produces: CloudFormation output `RoleArn` for `DuskRealAgentMainMantleRole` and `OidcProviderArn`.

- [ ] **Step 1: Add failing main-template tests**

Add constants and helpers for the main template. Add tests requiring:

```python
def test_main_template_defaults_are_main_only() -> None:
    template = _main_template()
    params = template["Parameters"]
    assert params["GitHubEnvironment"]["Default"] == "real-agent"
    assert params["RoleName"]["Default"] == "DuskRealAgentMainMantleRole"


def test_main_template_uses_exact_immutable_oidc_subject() -> None:
    statement = _main_role()["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
    assert statement["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] == {
        "Fn::Sub": (
            "repo:${GitHubOrg}@${GitHubOrgId}/${GitHubRepo}@${GitHubRepoId}:"
            "environment:${GitHubEnvironment}"
        )
    }


def test_main_template_action_allowlist_is_exact() -> None:
    assert _main_actions() == {
        "bedrock-mantle:CallWithBearerToken",
        "bedrock-mantle:CreateInference",
        "bedrock-mantle:GetProject",
        "bedrock-mantle:ListProjects",
        "bedrock-mantle:ListTagsForResource",
    }


def test_main_template_has_no_runtime_or_iam_permissions() -> None:
    actions = _main_actions()
    assert "bedrock:InvokeModel" not in actions
    assert "bedrock:ListInferenceProfiles" not in actions
    assert not any(action.startswith("iam:") for action in actions)
```

Also assert `CallWithBearerToken` has `Resource: "*"` only with `SHORT_TERM`, project actions use the regional account-scoped project ARN, the main and dev role names differ, and no action is `*`.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/ci/test_real_agent_mantle.py -q
```

Expected: failures identify the missing main template.

- [ ] **Step 3: Implement the main template**

Create the template by preserving the validated dev template structure while using:

```yaml
GitHubEnvironment:
  Type: String
  Default: real-agent
RoleName:
  Type: String
  Default: DuskRealAgentMainMantleRole
```

Name the role resource `DuskMantleMainRole` and policy `BedrockMantleMainInference`. Keep the exact action set, conditions, and resource scope from the dev template.

- [ ] **Step 4: Run template tests and verify GREEN**

Run:

```powershell
python -m pytest tests/ci/test_real_agent_mantle.py -q
ruff check tests/ci/test_real_agent_mantle.py
```

Expected: all commands exit zero.

- [ ] **Step 5: Commit**

```powershell
git add infra/aws/bedrock-mantle-main/template.yaml tests/ci/test_real_agent_mantle.py
git commit -s -m "feat: add main Mantle OIDC role"
```

---

### Task 3: Add fail-closed main setup and validation

**Files:**
- Create: `scripts/setup-bedrock-mantle-main.ps1`
- Modify: `tests/ci/test_real_agent_mantle.py`

**Interfaces:**
- Consumes: AWS CLI identity, GitHub CLI identity, main template, `real-agent` environment metadata, optional existing OIDC provider ARN.
- Produces: validated CloudFormation stack `dusk-bedrock-mantle-main` and environment variable `AWS_ROLE_ARN` only in explicit deployment mode.

- [ ] **Step 1: Add failing setup-script tests**

Add tests requiring the main script to contain and enforce:

```python
def test_main_setup_defaults_to_read_only_and_main_identity() -> None:
    script = _MAIN_SETUP_PATH.read_text(encoding="utf-8")
    assert '[string]$StackName = "dusk-bedrock-mantle-main"' in script
    assert '[string]$GitHubEnvironment = "real-agent"' in script
    assert '$RoleName = "DuskRealAgentMainMantleRole"' in script
    assert "if (-not $Deploy)" in script
    assert "if (-not $Confirm)" in script


def test_main_setup_requires_main_only_environment_protection() -> None:
    script = _MAIN_SETUP_PATH.read_text(encoding="utf-8")
    assert '"ritiksah141" -notin $reviewerLogins' in script
    assert "prevent_self_review" in script
    assert '$allowedPatterns[0] -eq "main"' in script
    assert "Only 'main' must be allowed" in script


def test_main_setup_validates_exact_live_permissions() -> None:
    script = _MAIN_SETUP_PATH.read_text(encoding="utf-8")
    assert "list-attached-role-policies" in script
    assert "$policyNames.Count -ne 1" in script
    assert "$policy.PolicyDocument.Statement.Count -ne 2" in script
    assert "Unexpected action" in script
    assert "SHORT_TERM" in script


def test_main_setup_never_dispatches_workflow_or_changes_provider_variables() -> None:
    script = _MAIN_SETUP_PATH.read_text(encoding="utf-8")
    assert "gh workflow run" not in script
    assert 'gh variable set "AWS_ROLE_ARN"' in script
    assert 'gh variable set "AWS_REGION"' not in script
    assert 'gh variable set "BEDROCK_PROVIDER"' not in script
    assert 'gh variable set "BEDROCK_MODEL_ID"' not in script
```

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
python -m pytest tests/ci/test_real_agent_mantle.py -q
```

Expected: failures identify the missing main setup script.

- [ ] **Step 3: Implement the setup script**

Adapt the validated dev script with exact main substitutions. Add an explicit check that the required-reviewer rule has `prevent_self_review` enabled. Require custom deployment branch policies with exactly one `main` pattern. Resolve immutable GitHub IDs through `gh api`. In deployment mode, validate the stack output and live trust before setting only `AWS_ROLE_ARN`.

- [ ] **Step 4: Run PowerShell syntax and focused tests**

Run:

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
  (Resolve-Path scripts/setup-bedrock-mantle-main.ps1),
  [ref]$null,
  [ref]$errors
) | Out-Null
if ($errors.Count -gt 0) { $errors | Format-List; exit 1 }
python -m pytest tests/ci/test_real_agent_mantle.py -q
ruff check tests/ci/test_real_agent_mantle.py
```

Expected: no syntax errors and all tests pass.

- [ ] **Step 5: Run validation-only mode against live configuration**

Run with the authenticated AWS profile and region:

```powershell
$env:AWS_PROFILE = "dusk-deployer"
$env:AWS_REGION = "eu-west-2"
$env:AWS_DEFAULT_REGION = "eu-west-2"
scripts/setup-bedrock-mantle-main.ps1
```

Expected before provider-variable migration: protection and branch-policy checks pass, missing or old provider variables are reported without secret values, no AWS or GitHub changes occur, and the script exits successfully after validation.

- [ ] **Step 6: Commit**

```powershell
git add scripts/setup-bedrock-mantle-main.ps1 tests/ci/test_real_agent_mantle.py
git commit -s -m "feat: validate main Mantle deployment"
```

---

### Task 4: Complete repository verification and open the dev PR

**Files:**
- Verify all modified files.
- Update: `CHANGELOG.md` only if the repository policy requires an unreleased workflow entry.

**Interfaces:**
- Consumes: completed workflow, template, setup script, and tests.
- Produces: a reviewable feature branch targeting `dev` with no external deployment side effects.

- [ ] **Step 1: Run focused verification**

```powershell
python -m pytest tests/ci/test_real_agent_workflow.py tests/ci/test_real_agent_mantle.py tests/test_actions_mantle.py -q
python -m pytest examples/agent-action-monitor/agent-demo/test_bedrock_client.py examples/agent-action-monitor/tests/test_result_contract.py examples/agent-action-monitor/tests/test_actions_mantle.py -q
```

- [ ] **Step 2: Run the full repository suite**

Use a dedicated worktree virtual environment:

```powershell
.venv\Scripts\python.exe -m pytest --cov=src/dusk --cov-report=term-missing --cov-fail-under=70
```

Record passes, failures, skips, coverage, and any proven Windows-only checkout condition separately.

- [ ] **Step 3: Run static and security checks**

```powershell
ruff check .
actionlint
zizmor .github/workflows/real-agent-sandbox.yml
git diff --check origin/dev...HEAD
```

Scan the diff for AWS access keys, private keys, GitHub tokens, and bearer-token literals without printing matched secret values.

- [ ] **Step 4: Verify attribution and branch scope**

Require Tanvir Farhad as author and committer, a `Signed-off-by` trailer on each non-merge commit, a clean worktree, and no changes outside the planned files.

- [ ] **Step 5: Push and open a PR into dev**

```powershell
git push -u origin feat/main-mantle-validation
gh pr create --repo ShieldTech-Ltd/DUSK --base dev --head feat/main-mantle-validation
```

The PR body must distinguish automated tests, previous live dev evidence, and the still-pending main deployment evidence. It must state that no IAM or environment mutation has occurred yet.

---

### Task 5: Promote, deploy, and prove the main run

**Files:**
- Update after successful run: `docs/real-agent-sandbox-live-validation-2026-08-27.md`

**Interfaces:**
- Consumes: merged dev implementation, reviewed dev to main promotion, authenticated AWS deployer, protected GitHub environment.
- Produces: main-only Mantle role, migrated main environment variables, and inspectable protected main-run evidence.

- [ ] **Step 1: Wait for dev PR approval and green CI**

Do not merge autonomously. Require all checks, no unresolved threads, and the configured reviewer approval.

- [ ] **Step 2: Promote reviewed dev to main**

Open or update a separate `dev` to `main` PR. Re-run the complete merge-readiness audit. Do not deploy until the workflow code is merged into `main`.

- [ ] **Step 3: Validate and deploy the main role**

```powershell
$oidcArn = "arn:aws:iam::040982755487:oidc-provider/" +
  "token.actions.githubusercontent.com"
scripts/setup-bedrock-mantle-main.ps1 `
  -Deploy `
  -Confirm `
  -ExistingOidcProviderArn $oidcArn
```

Require the script to confirm the exact role ARN, trust subject, action set, resource scope, and absence of attached policies before it sets `AWS_ROLE_ARN`.

- [ ] **Step 4: Set the proven main provider variables**

```powershell
gh variable set AWS_REGION --repo ShieldTech-Ltd/DUSK --env real-agent --body eu-west-2
gh variable set BEDROCK_PROVIDER --repo ShieldTech-Ltd/DUSK --env real-agent --body mantle
gh variable set BEDROCK_MODEL_ID --repo ShieldTech-Ltd/DUSK --env real-agent --body moonshotai.kimi-k2.5
```

Re-query variables and environment policy. Never read or print the secret value.

- [ ] **Step 5: Dispatch the protected main enforce run**

```powershell
gh workflow run real-agent-sandbox.yml `
  --repo ShieldTech-Ltd/DUSK `
  --ref main `
  -f gate_mode=enforce
```

Obtain `ritiksah141` approval and monitor the run to completion.

- [ ] **Step 6: Inspect evidence before declaring success**

Download the artifact into a fresh temporary directory. Parse JUnit and require tests greater than zero, failures zero, errors zero, and skips zero. Require a non-empty gate log. Count potential Authorization, bearer-token, AWS access-key, private-key, and GitHub-token patterns without printing sensitive lines.

- [ ] **Step 7: Record main evidence through a new reviewed PR**

Update the sandbox report with the main run ID, main commit SHA, test counts, durations, log size, and leak-scan counts. Submit the documentation through `dev` and promote it normally.
