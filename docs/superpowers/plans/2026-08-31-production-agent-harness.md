# DUSK Production Agent Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the authenticated DUSK real-agent harness from `examples/agent-action-monitor/` to a production-owned root directory, centralize all four model profiles, and run them through one protected workflow.

**Architecture:** Preserve the proven provider and gate behavior while moving the harness atomically to `dusk-agent-harness/`. Add a typed model registry as the single source of truth, update all Docker, CI, workflow, contract, and documentation paths, then remove the old example path. The registered dev workflow keeps GPT-only qualification and the strict four-model matrix.

**Tech Stack:** Python 3.11 and 3.12, pytest, PyYAML, OpenAI-compatible Bedrock Mantle client, Docker Compose, GitHub Actions, AWS OIDC, Ruff, actionlint, zizmor

**Spec:** `docs/superpowers/specs/2026-08-31-production-agent-harness-design.md`

## Global Constraints

- Target `dev` from baseline `c7bcb9bf65fc1bf3c20e888489e274cfd14c0504`.
- Keep exact model IDs: `moonshotai.kimi-k2.5`, `zai.glm-5`, `qwen.qwen3-32b`, and `openai.gpt-oss-120b`.
- Do not change verified Kimi, GLM, Qwen, or GPT request behavior during the path migration.
- Keep `real-agent-dev`, OIDC, least-privileged Mantle permissions, hash-locked dependencies, per-model evidence, cleanup, and the aggregate gate.
- A protected run is invalid if any required test fails, errors, or skips, or if JUnit, gate logs, or manifest evidence is missing or empty.
- Do not widen IAM permissions.
- Do not store or print credentials, bearer tokens, canary secrets, or private prompt data.
- Use sequential pytest execution for real LLM tests on Windows.
- Every commit must include a DCO `Signed-off-by` trailer.
- Do not claim protected success from local tests or ordinary CI.

---

### Task 1: Lock the Production Path Contract

**Files:**
- Modify: `tests/ci/test_real_agent_mantle.py`
- Modify: `tests/ci/test_repository_checks.py`
- Test: `tests/ci/test_real_agent_mantle.py`
- Test: `tests/ci/test_repository_checks.py`

**Interfaces:**
- Consumes: existing workflow and repository contract tests
- Produces: `_HARNESS_ROOT = Path("dusk-agent-harness")` and failing assertions that forbid active use of `examples/agent-action-monitor`

- [ ] **Step 1: Write the failing production-root tests**

Add constants and tests with this exact intent:

```python
_HARNESS_ROOT = Path("dusk-agent-harness")
_LEGACY_HARNESS_ROOT = Path("examples/agent-action-monitor")


def test_production_agent_harness_is_the_only_active_harness_root() -> None:
    assert _HARNESS_ROOT.is_dir()
    assert not _LEGACY_HARNESS_ROOT.exists()


def test_real_agent_workflows_use_the_production_harness_root() -> None:
    for path in (
        Path(".github/workflows/real-agent-sandbox-dev.yml"),
        Path(".github/workflows/real-agent-sandbox.yml"),
    ):
        text = path.read_text(encoding="utf-8")
        assert "working-directory: dusk-agent-harness" in text
        assert "examples/agent-action-monitor" not in text
```

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```powershell
$env:PYTHONPATH = "src"
python -m pytest tests/ci/test_real_agent_mantle.py tests/ci/test_repository_checks.py -q
```

Expected: failure because `dusk-agent-harness/` does not exist and workflows still use the legacy path.

- [ ] **Step 3: Commit only the failing contract tests**

```powershell
git add tests/ci/test_real_agent_mantle.py tests/ci/test_repository_checks.py
git commit -s -m "test: require production agent harness root"
```

---

### Task 2: Move the Working Harness Atomically

**Files:**
- Move: `examples/agent-action-monitor/` to `dusk-agent-harness/`
- Modify: `dusk-agent-harness/pyproject.toml`
- Modify: `dusk-agent-harness/README.md`
- Modify: `.gitignore`
- Test: `tests/ci/test_repository_checks.py`

**Interfaces:**
- Consumes: the complete existing harness directory and Task 1 path contract
- Produces: root-level `dusk-agent-harness/` with unchanged runtime, test, Docker, contract, and evidence behavior

- [ ] **Step 1: Move the tracked tree with Git**

Run:

```powershell
git mv examples/agent-action-monitor dusk-agent-harness
```

- [ ] **Step 2: Rename user-facing package descriptions**

Update `dusk-agent-harness/pyproject.toml` and `dusk-agent-harness/README.md` so titles describe the DUSK Production Agent Harness. Do not change dependency versions, entry points, or provider behavior.

- [ ] **Step 3: Update ignored runtime output paths**

Replace any ignored `examples/agent-action-monitor/ci-logs` path with:

```text
dusk-agent-harness/ci-logs/
```

- [ ] **Step 4: Run the path contract tests**

Run:

```powershell
$env:PYTHONPATH = "src"
python -m pytest tests/ci/test_repository_checks.py -q
```

Expected: production-root existence passes. Workflow path assertions still fail until Task 4.

- [ ] **Step 5: Run the moved harness unit suite**

Run:

```powershell
Push-Location dusk-agent-harness
$env:PYTHONPATH = "src;agent-demo"
python -m pytest agent-demo tests -q -n 0
Pop-Location
```

Expected: the same passing count as the pre-move baseline, with protected real-provider tests skipped only in this credential-free local suite.

- [ ] **Step 6: Commit the atomic move**

```powershell
git add -A
git commit -s -m "refactor: move agent harness to production root"
```

---

### Task 3: Create the Production Runtime Boundary and Model Registry

**Files:**
- Move: `dusk-agent-harness/agent-demo/` to `dusk-agent-harness/runtime/`
- Create: `dusk-agent-harness/models/__init__.py`
- Create: `dusk-agent-harness/models/registry.py`
- Create: `dusk-agent-harness/tests/test_model_registry.py`
- Modify: `dusk-agent-harness/runtime/bedrock_client.py`
- Modify: `dusk-agent-harness/runtime/test_bedrock_client.py`
- Modify: Docker, Compose, test, and script references returned by `rg -l "agent-demo" dusk-agent-harness`

**Interfaces:**
- Consumes: `BEDROCK_MODEL_ID` and existing provider-specific request logic
- Produces: production `runtime/`, `ModelProfile`, `MODEL_PROFILES`, and `get_model_profile(model_id: str) -> ModelProfile`

- [ ] **Step 1: Write the failing runtime and registry tests**

Create `dusk-agent-harness/tests/test_model_registry.py`:

```python
from models.registry import MODEL_PROFILES, get_model_profile


EXPECTED = {
    "moonshotai.kimi-k2.5": "kimi-k2-5",
    "zai.glm-5": "glm-5",
    "qwen.qwen3-32b": "qwen3-32b",
    "openai.gpt-oss-120b": "gpt-oss-120b",
}


def test_registry_contains_exact_supported_model_set() -> None:
    assert {profile.model_id: profile.slug for profile in MODEL_PROFILES} == EXPECTED


def test_unknown_model_fails_closed() -> None:
    try:
        get_model_profile("unknown.model")
    except ValueError as exc:
        assert "Unsupported Bedrock Mantle model" in str(exc)
    else:
        raise AssertionError("unknown model must fail closed")


def test_runtime_uses_production_name() -> None:
    from pathlib import Path

    assert Path("runtime/bedrock_client.py").is_file()
    assert not Path("agent-demo").exists()
```

- [ ] **Step 2: Run the registry tests and verify RED**

Run:

```powershell
Push-Location dusk-agent-harness
$env:PYTHONPATH = ".;src;agent-demo"
python -m pytest tests/test_model_registry.py -q
Pop-Location
```

Expected: failure because `models.registry` and the production runtime path do not exist.

- [ ] **Step 3: Move the runtime and update internal references**

Run:

```powershell
git mv dusk-agent-harness/agent-demo dusk-agent-harness/runtime
```

Update Docker, Compose, pytest, and script references returned by:

```powershell
rg -n "agent-demo" dusk-agent-harness
```

Do not rename historical text that no longer drives an active command.

- [ ] **Step 4: Implement the immutable profile type and registry**

Create `dusk-agent-harness/models/registry.py` with this public shape:

```python
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ModelProfile:
    name: str
    slug: str
    model_id: str
    provider: str = "mantle"


MODEL_PROFILES = (
    ModelProfile("Kimi K2.5", "kimi-k2-5", "moonshotai.kimi-k2.5"),
    ModelProfile("GLM-5", "glm-5", "zai.glm-5"),
    ModelProfile("Qwen3 32B", "qwen3-32b", "qwen.qwen3-32b"),
    ModelProfile("GPT OSS 120B", "gpt-oss-120b", "openai.gpt-oss-120b"),
)


def get_model_profile(model_id: str) -> ModelProfile:
    for profile in MODEL_PROFILES:
        if profile.model_id == model_id:
            return profile
    raise ValueError(f"Unsupported Bedrock Mantle model: {model_id}")
```

Export the three public symbols from `models/__init__.py`.

- [ ] **Step 5: Use the registry at the Bedrock client boundary**

In `bedrock_client.py`, resolve `BEDROCK_MODEL_ID` through `get_model_profile()` before provider-specific behavior is selected. Keep the verified timeout, retry, token, and tool-correction behavior unchanged.

- [ ] **Step 6: Extend client tests for all four profiles**

Add a parameterized test that builds the request for each exact model ID and asserts the outgoing model value is unchanged.

- [ ] **Step 7: Run registry and client tests**

Run:

```powershell
Push-Location dusk-agent-harness
$env:PYTHONPATH = ".;src;runtime"
python -m pytest tests/test_model_registry.py runtime/test_bedrock_client.py -q
Pop-Location
```

Expected: all tests pass.

- [ ] **Step 8: Commit the runtime boundary and registry**

```powershell
git add -A dusk-agent-harness
git commit -s -m "feat: create production agent runtime and model registry"
```

---

### Task 4: Connect One Workflow to the Production Harness

**Files:**
- Modify: `.github/workflows/real-agent-sandbox-dev.yml`
- Modify: `.github/workflows/real-agent-sandbox.yml`
- Modify: `tests/ci/test_real_agent_mantle.py`
- Modify: `tests/ci/test_real_agent_workflow.py`

**Interfaces:**
- Consumes: production harness path and exact `MODEL_PROFILES` values
- Produces: one registered dev workflow with `gpt-oss-qualification` and `full-matrix`

- [ ] **Step 1: Strengthen failing workflow-to-registry tests**

Add a helper that imports the registry from `dusk-agent-harness/` and compares its `(slug, model_id)` pairs with both JSON branches in `.github/workflows/real-agent-sandbox-dev.yml`.

The test must prove:

```python
qualification == [{"slug": "gpt-oss-120b", "id": "openai.gpt-oss-120b"}]
full_matrix == [
    {"slug": "kimi-k2-5", "id": "moonshotai.kimi-k2.5"},
    {"slug": "glm-5", "id": "zai.glm-5"},
    {"slug": "qwen3-32b", "id": "qwen.qwen3-32b"},
    {"slug": "gpt-oss-120b", "id": "openai.gpt-oss-120b"},
]
```

- [ ] **Step 2: Run workflow tests and verify RED**

Run:

```powershell
$env:PYTHONPATH = "src"
python -m pytest tests/ci/test_real_agent_mantle.py tests/ci/test_real_agent_workflow.py -q
```

Expected: failure because workflow working directories and artifact paths still use the legacy location.

- [ ] **Step 3: Update the dev workflow paths**

Change each job default to:

```yaml
defaults:
  run:
    working-directory: dusk-agent-harness
```

Change cache, artifact, and evidence paths from `examples/agent-action-monitor/...` to `dusk-agent-harness/...`. Keep the existing dynamic matrix expression and effective gate mode expression byte-for-byte except where tests require formatting.

- [ ] **Step 4: Update the main workflow paths only**

Change working, cache, artifact, and evidence paths to the production root. Do not change the main branch guard, environment name, provider, model selection, schedule, or evidence behavior.

- [ ] **Step 5: Run workflow contract and action validation**

Run:

```powershell
$env:PYTHONPATH = "src"
python -m pytest tests/ci/test_real_agent_mantle.py tests/ci/test_real_agent_workflow.py -q
docker run --rm -v "${PWD}:/repo" -w /repo rhysd/actionlint:1.7.8
```

Expected: tests pass and actionlint exits zero with no output.

- [ ] **Step 6: Commit workflow migration**

```powershell
git add .github/workflows/real-agent-sandbox-dev.yml .github/workflows/real-agent-sandbox.yml tests/ci/test_real_agent_mantle.py tests/ci/test_real_agent_workflow.py
git commit -s -m "ci: run real agents from production harness"
```

---

### Task 5: Update CI, Docker, Scripts, and Documentation

**Files:**
- Modify: `.github/workflows/dusk.yml`
- Modify: `scripts/ci/pr_correctness.sh`
- Modify: `scripts/ci/pr_security.sh`
- Modify: `scripts/ci/container_controls.sh`
- Modify: repository documentation returned by `rg -l "examples/agent-action-monitor"`
- Modify: `dusk-agent-harness/compose.yml`
- Modify: `dusk-agent-harness/compose.ci.yml`
- Modify: `dusk-agent-harness/compose.enforce.yml`
- Modify: `dusk-agent-harness/scripts/run_owasp_demo.sh`
- Test: `tests/ci/test_repository_checks.py`

**Interfaces:**
- Consumes: moved production tree and workflow paths
- Produces: no active repository reference to the legacy path

- [ ] **Step 1: Inventory every remaining legacy reference**

Run:

```powershell
rg -n "examples/agent-action-monitor" . -g "!docs/superpowers/specs/2026-08-31-production-agent-harness-design.md" -g "!docs/superpowers/plans/2026-08-31-production-agent-harness.md"
```

Save the file list in the terminal output. Do not bulk-replace generated evidence or unrelated archived text.

- [ ] **Step 2: Update active CI and script paths**

For every active command, change the root to `dusk-agent-harness/`. Preserve command arguments, controls, image tags, hashes, and security thresholds.

- [ ] **Step 3: Update Compose build contexts and mounts**

Resolve paths relative to the new Compose file location. Run `docker compose config` for each file:

```powershell
Push-Location dusk-agent-harness
$env:DUSK_GATE_API_KEY = "config-validation-only"
$env:DUSK_ENFORCE = "true"
docker compose -f compose.yml -f compose.ci.yml config --quiet
docker compose -f compose.yml -f compose.enforce.yml config --quiet
Pop-Location
```

Expected: both commands exit zero without starting containers.

- [ ] **Step 4: Update documentation terminology**

Use “DUSK Production Agent Harness” and “real LLM validation.” Remove “demo” from user-facing descriptions when the file describes the authenticated harness. Keep historical release notes accurate.

- [ ] **Step 5: Prove no active legacy references remain**

Run the same `rg` command from Step 1. Expected: only the approved spec and implementation plan mention the old path as migration history.

- [ ] **Step 6: Run repository and CI tests**

Run:

```powershell
$env:PYTHONPATH = "src"
python -m pytest tests/ci -q
```

Expected: all tests pass.

- [ ] **Step 7: Commit CI, Docker, script, and documentation updates**

```powershell
git add -A
git commit -s -m "chore: complete production harness path migration"
```

---

### Task 6: Verify the Exact Branch Before Review

**Files:**
- Verify only: all changed files

**Interfaces:**
- Consumes: completed migration branch
- Produces: local verification evidence and a reviewable exact commit SHA

- [ ] **Step 1: Run formatting and static checks**

Run:

```powershell
ruff check src tests dusk-agent-harness
ruff format --check src tests dusk-agent-harness
docker run --rm -v "${PWD}:/repo" -w /repo rhysd/actionlint:1.7.8
git diff origin/dev...HEAD --check
```

Expected: every command exits zero.

- [ ] **Step 2: Run repository CI contract tests**

Run:

```powershell
$env:PYTHONPATH = "src"
python -m pytest tests/ci -q
```

Expected: zero failures.

- [ ] **Step 3: Run production harness tests sequentially**

Run:

```powershell
Push-Location dusk-agent-harness
$env:PYTHONPATH = ".;src;runtime"
python -m pytest runtime tests -q -n 0
Pop-Location
```

Expected: zero failures and errors. Credential-gated protected tests may skip locally and must be reported separately.

- [ ] **Step 4: Run Docker sandbox validation**

Run:

```powershell
Push-Location dusk-agent-harness
sh scripts/run_owasp_demo.sh --no-build watch
sh scripts/run_owasp_demo.sh --no-build enforce
Pop-Location
```

Expected: both watch and enforce scenarios pass and cleanup completes.

- [ ] **Step 5: Review the branch diff and file ancestry**

Run:

```powershell
git status --short --branch
git diff --stat origin/dev...HEAD
git diff --summary origin/dev...HEAD
git log --format="%h %s%n%b" origin/dev..HEAD
```

Expected: clean worktree, intentional moves, no unsigned commit, and no unrelated file.

- [ ] **Step 6: Request independent code review**

Provide the reviewer with the spec path, plan path, base SHA, head SHA, test output, and the exact acceptance criteria. Fix every Critical or Important finding before proceeding.

- [ ] **Step 7: Re-run affected tests after review fixes**

Run the Task 6 commands that cover every modified file. Expected: all applicable checks pass again.

---

### Task 7: Push, Review, Merge, and Run Protected Evidence

**Files:**
- External state: GitHub branch, pull request, protected environment, Actions evidence

**Interfaces:**
- Consumes: reviewed local branch and explicit user authorization for push and PR creation
- Produces: reviewed PR into `dev`, then protected qualification and matrix evidence after merge

- [ ] **Step 1: Push and create one PR into `dev`**

Run only after authorization:

```powershell
git push -u origin feat/production-agent-harness
gh pr create --repo ShieldTech-Ltd/DUSK --base dev --head feat/production-agent-harness
```

The PR body must state local pass counts, credential-gated skips, actionlint result, container result, migration scope, and claim boundary.

- [ ] **Step 2: Verify exact PR head and all checks**

Run:

```powershell
$prNumber = gh pr list --repo ShieldTech-Ltd/DUSK --head feat/production-agent-harness --json number --jq '.[0].number'
gh pr view $prNumber --repo ShieldTech-Ltd/DUSK --json headRefOid,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,reviews,reviewRequests
```

Expected: head SHA matches the reviewed local head, every required check passes, mergeability is clean, and approval is present.

- [ ] **Step 3: Verify no unresolved review thread**

Use the GitHub GraphQL `reviewThreads` query and require every non-outdated thread to be resolved.

- [ ] **Step 4: Merge only after explicit authorization**

Use the repository’s normal merge method. Re-fetch `origin/dev` and prove it contains the PR merge commit.

- [ ] **Step 5: Run GPT OSS protected qualification twice**

Dispatch from `dev` with:

```powershell
gh workflow run real-agent-sandbox-dev.yml --repo ShieldTech-Ltd/DUSK --ref dev -f run_target=gpt-oss-qualification -f gate_mode=enforce
```

For each run, obtain protected environment approval and require zero failures, errors, and skips plus non-empty JUnit, gate log, and manifest.

- [ ] **Step 6: Run the complete four-model matrix**

Dispatch from `dev` with:

```powershell
gh workflow run real-agent-sandbox-dev.yml --repo ShieldTech-Ltd/DUSK --ref dev -f run_target=full-matrix -f gate_mode=enforce
```

Require Kimi, GLM, Qwen, GPT OSS, and the aggregate matrix gate all to pass.

- [ ] **Step 7: Report the evidence boundary**

Report exact commit, branch, run URLs, model IDs, test totals, evidence artifacts, and blockers. State that the result proves only the tested models and scenarios for the exact commit and protected environment.
