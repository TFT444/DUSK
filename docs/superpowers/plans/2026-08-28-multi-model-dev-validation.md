# Strict Multi-Model Dev Validation Implementation Plan

> Correction, 2026-08-29: The model-listing preflight described below was removed
> after protected run 33217903459 showed that it requires broader IAM permission
> than inference. The current workflow qualifies every matrix model through its
> authenticated real inference scenarios and keeps the inference role least privileged.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run Kimi K2.5, GLM 5, and NVIDIA Nemotron 3 Super 120B independently through the protected DUSK dev sandbox and fail the aggregate gate unless all three complete with zero failures, errors, and skips.

**Architecture:** Preserve the successful Kimi Mantle client and protected workflow route. Add a fixed source-controlled GitHub Actions matrix, an authenticated model-availability boundary, per-model evidence validation and manifests, and a stable aggregate job. No fallback or provider-specific weakening is allowed.

**Tech Stack:** GitHub Actions YAML, Python 3.11, pytest, OpenAI Python SDK, AWS Bedrock Mantle, GitHub OIDC, Docker Compose, PowerShell validation.

**Spec:** `docs/superpowers/specs/2026-08-28-multi-model-dev-validation-design.md`

## Global Constraints

- Deliver design, plan, code, tests, and documentation in one branch and one feature PR into `dev`.
- The exact model allowlist is `moonshotai.kimi-k2.5`, `zai.glm-5`, and `nvidia.nemotron-super-3-120b`.
- Preserve the existing Kimi short-term token, Mantle endpoint, Chat Completions, required tool-call, prompt, gate, and Docker route.
- Do not add fallback, mutable model dispatch input, Bedrock Runtime permissions, Marketplace permissions, static AWS keys, or long-term API keys.
- Keep `strategy.fail-fast: false` and execute every model even when one fails.
- A valid model result has more than zero tests and exactly zero failures, errors, and skips.
- Preserve the dev-only OIDC subject, `dev` branch restriction, required reviewer, self-review prevention, and exact five-action IAM allowlist.
- Do not change the main workflow in this feature PR.
- Use signed-off commits authored only by Tanvir Farhad.

---

### Task 1: Add an authenticated Mantle model-availability boundary

**Files:**
- Modify: `examples/agent-action-monitor/agent-demo/bedrock_client.py`
- Modify: `examples/agent-action-monitor/agent-demo/test_bedrock_client.py`

**Interfaces:**
- Consumes: `region: str`, `model_id: str`, short-term token from `provide_token(region)`, and the OpenAI-compatible Mantle `/models` response.
- Produces: `list_mantle_model_ids(region: str) -> set[str]` and `require_mantle_model_available(region: str, model_id: str) -> None`.

- [ ] **Step 1: Write failing availability tests**

Add tests using complete OpenAI-shaped model fixtures. Stub only token generation and the external OpenAI client:

```python
def test_list_mantle_model_ids_returns_only_non_empty_ids(monkeypatch):
    capture = _install_mantle_modules(
        monkeypatch,
        model_entries=[
            SimpleNamespace(id="moonshotai.kimi-k2.5"),
            SimpleNamespace(id="zai.glm-5"),
            SimpleNamespace(id=""),
        ],
    )

    assert list_mantle_model_ids("eu-west-2") == {
        "moonshotai.kimi-k2.5",
        "zai.glm-5",
    }
    assert capture["base_url"] == "https://bedrock-mantle.eu-west-2.api.aws/v1"


def test_require_mantle_model_available_rejects_missing_model(monkeypatch):
    _install_mantle_modules(
        monkeypatch,
        model_entries=[SimpleNamespace(id="moonshotai.kimi-k2.5")],
    )

    with pytest.raises(RuntimeError, match="zai.glm-5"):
        require_mantle_model_available("eu-west-2", "zai.glm-5")
```

Also test an empty token and a malformed `models.list()` response. Assert that the token value is absent from exception text and object representations.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
Push-Location examples/agent-action-monitor
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest agent-demo/test_bedrock_client.py -q
Pop-Location
```

Expected: collection or import fails because `list_mantle_model_ids` and `require_mantle_model_available` do not exist.

- [ ] **Step 3: Implement the minimal availability functions**

Add:

```python
def list_mantle_model_ids(region: str) -> set[str]:
    from aws_bedrock_token_generator import provide_token
    from openai import OpenAI

    token = provide_token(region)
    if not token:
        raise RuntimeError("Bedrock token generator returned an empty token")
    client = OpenAI(
        base_url=f"https://bedrock-mantle.{region}.api.aws/v1",
        api_key=token,
    )
    response = client.models.list()
    entries = getattr(response, "data", None)
    if not isinstance(entries, list):
        raise RuntimeError("Mantle models response did not contain a data list")
    return {
        model_id
        for entry in entries
        if isinstance((model_id := getattr(entry, "id", None)), str) and model_id
    }


def require_mantle_model_available(region: str, model_id: str) -> None:
    if model_id not in list_mantle_model_ids(region):
        raise RuntimeError(f"Mantle model is not available in {region}: {model_id}")
```

Do not log the token or wrapped client. Preserve `build_mantle_client` and `propose_tool_call` behavior.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run the Task 1 test command. Expected: all `agent-demo/test_bedrock_client.py` tests pass.

- [ ] **Step 5: Commit Task 1**

```powershell
git add examples/agent-action-monitor/agent-demo/bedrock_client.py `
  examples/agent-action-monitor/agent-demo/test_bedrock_client.py
git commit -s -m "feat(bedrock): verify Mantle model availability"
```

---

### Task 2: Add executable evidence validation and per-model manifests

**Files:**
- Create: `examples/agent-action-monitor/scripts/validate_real_agent_evidence.py`
- Create: `examples/agent-action-monitor/tests/test_validate_real_agent_evidence.py`

**Interfaces:**
- Consumes: a pytest JUnit XML path plus explicit provider, model ID, model slug, commit SHA, run ID, and gate mode strings.
- Produces: `parse_junit_counts(path: Path) -> dict[str, int]`, `validate_counts(counts: Mapping[str, int]) -> None`, and a UTF-8 JSON manifest written only after valid counts are confirmed.

- [ ] **Step 1: Write failing evidence behavior tests**

Use temporary real XML files with literal counts:

```python
@pytest.mark.parametrize(
    ("attributes", "message"),
    [
        ('tests="0" failures="0" errors="0" skipped="0"', "zero tests"),
        ('tests="16" failures="1" errors="0" skipped="0"', "failures"),
        ('tests="16" failures="0" errors="1" skipped="0"', "errors"),
        ('tests="16" failures="0" errors="0" skipped="1"', "skipped"),
    ],
)
def test_invalid_junit_counts_are_rejected(tmp_path, attributes, message):
    junit = tmp_path / "results.xml"
    junit.write_text(f"<testsuites><testsuite {attributes}/></testsuites>", encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        validate_counts(parse_junit_counts(junit))


def test_manifest_contains_model_identity_and_valid_counts(tmp_path):
    junit = tmp_path / "results.xml"
    manifest = tmp_path / "manifest.json"
    junit.write_text(
        '<testsuites><testsuite tests="16" failures="0" errors="0" skipped="0"/></testsuites>',
        encoding="utf-8",
    )

    write_validated_manifest(
        junit_path=junit,
        output_path=manifest,
        provider="mantle",
        model_id="zai.glm-5",
        model_slug="glm-5",
        commit_sha="abc123",
        run_id="42",
        gate_mode="enforce",
    )

    assert json.loads(manifest.read_text(encoding="utf-8")) == {
        "provider": "mantle",
        "model_id": "zai.glm-5",
        "model_slug": "glm-5",
        "commit_sha": "abc123",
        "run_id": "42",
        "gate_mode": "enforce",
        "tests": 16,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }
```

Also test missing XML, malformed XML, and multiple suites whose counts must be summed. The manifest test must assert that no field name contains `token`, `secret`, `authorization`, or `api_key`.

- [ ] **Step 2: Run the tests and verify RED**

Run:

```powershell
Push-Location examples/agent-action-monitor
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest tests/test_validate_real_agent_evidence.py -q
Pop-Location
```

Expected: import fails because the evidence module does not exist.

- [ ] **Step 3: Implement the evidence validator and CLI**

Use `xml.etree.ElementTree` to parse the local pytest-generated XML. Sum leaf `testsuite` counts, reject negative or non-integer attributes, require `tests > 0`, and require failures, errors, and skipped to equal zero. Write JSON using `json.dumps(manifest, indent=2, sort_keys=True) + "\n"`.

The CLI must require:

```text
--junit --output --provider --model-id --model-slug --commit-sha --run-id --gate-mode
```

It must exit non-zero on invalid evidence and must not accept credential arguments.

- [ ] **Step 4: Run focused tests and verify GREEN**

Run the Task 2 test command. Expected: all evidence tests pass.

- [ ] **Step 5: Commit Task 2**

```powershell
git add examples/agent-action-monitor/scripts/validate_real_agent_evidence.py `
  examples/agent-action-monitor/tests/test_validate_real_agent_evidence.py
git commit -s -m "feat(evidence): validate per-model sandbox results"
```

---

### Task 3: Convert the protected dev workflow to the strict matrix

**Files:**
- Modify: `.github/workflows/real-agent-sandbox-dev.yml`
- Modify: `tests/ci/test_real_agent_mantle.py`

**Interfaces:**
- Consumes: fixed matrix entries, `vars.AWS_REGION`, `vars.BEDROCK_PROVIDER`, `vars.AWS_ROLE_ARN`, and `secrets.DUSK_GATE_API_KEY`.
- Produces: three isolated model jobs, three uniquely named evidence artifacts, and one `real-agent-dev-matrix-gate` aggregate job.

- [ ] **Step 1: Write failing workflow behavior tests**

Add parsed-YAML tests that require exactly these literal matrix entries:

```python
EXPECTED_MODELS = [
    {"slug": "kimi-k2-5", "id": "moonshotai.kimi-k2.5"},
    {"slug": "glm-5", "id": "zai.glm-5"},
    {"slug": "nemotron-3-super-120b", "id": "nvidia.nemotron-super-3-120b"},
]


def test_dev_workflow_runs_the_exact_approved_model_matrix():
    job = _dev_workflow()["jobs"]["real-agent-dev-validation"]
    assert job["strategy"] == {"fail-fast": False, "matrix": {"model": EXPECTED_MODELS}}
    assert job["env"]["BEDROCK_MODEL_ID"] == "${{ matrix.model.id }}"


def test_dev_workflow_has_strict_aggregate_gate():
    gate = _dev_workflow()["jobs"]["real-agent-dev-matrix-gate"]
    assert gate["needs"] == "real-agent-dev-validation"
    assert gate["if"] == "always()"
    assert "needs.real-agent-dev-validation.result" in gate["steps"][0]["run"]
    assert "exit 1" in gate["steps"][0]["run"]
```

Add behavior assertions that:

- `BEDROCK_MODEL_ID` is absent from dispatch inputs and environment preflight requirements.
- The availability step calls `require_mantle_model_available` with matrix model ID.
- Artifact names contain `${{ matrix.model.slug }}` and `${{ github.run_id }}`.
- The evidence validator receives the exact matrix ID and slug.
- No step contains a fallback model or rewrites a failed model to Kimi.
- The main workflow file remains unchanged relative to the task base SHA.

- [ ] **Step 2: Run tests and verify RED**

Run:

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest tests/ci/test_real_agent_mantle.py -q
```

Expected: new tests fail because the dev workflow still has one environment-provided model and no aggregate job.

- [ ] **Step 3: Implement the fixed matrix**

Add the exact matrix under `real-agent-dev-validation`, set the job name to include `${{ matrix.model.slug }}`, set `BEDROCK_MODEL_ID: ${{ matrix.model.id }}`, and remove `BEDROCK_MODEL_ID` from the preflight value list.

Add a post-OIDC availability step:

```yaml
- name: Verify selected Mantle model availability
  env:
    MATRIX_MODEL_ID: ${{ matrix.model.id }}
  run: |
    python -c "import os; from bedrock_client import require_mantle_model_available; require_mantle_model_available(os.environ['AWS_REGION'], os.environ['MATRIX_MODEL_ID'])"
```

Pass matrix ID and slug to the evidence validator after pytest. Use unique per-model `ci-logs/<slug>/` directories and artifacts. Preserve `USE_REAL_BEDROCK=true`, `--wait`, zero-skip semantics, stage-aware logs, enforce-mode isolation, and always-run cleanup.

Add:

```yaml
real-agent-dev-matrix-gate:
  name: Real-agent dev matrix gate
  if: always()
  needs: real-agent-dev-validation
  runs-on: ubuntu-latest
  permissions:
    contents: read
  steps:
    - name: Require every approved model to pass
      env:
        MATRIX_RESULT: ${{ needs.real-agent-dev-validation.result }}
      run: |
        if [ "$MATRIX_RESULT" != "success" ]; then
          echo "ERROR: at least one approved real-agent model failed"
          exit 1
        fi
        echo "All approved real-agent models passed"
```

- [ ] **Step 4: Run workflow tests and verify GREEN**

Run:

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest tests/ci/test_real_agent_mantle.py tests/ci/test_real_agent_workflow.py -q
ruff check tests/ci/test_real_agent_mantle.py
actionlint .github/workflows/real-agent-sandbox-dev.yml
zizmor .github/workflows/real-agent-sandbox-dev.yml
```

Expected: all tests and validators exit zero, with only existing documented zizmor suppressions.

- [ ] **Step 5: Commit Task 3**

```powershell
git add .github/workflows/real-agent-sandbox-dev.yml tests/ci/test_real_agent_mantle.py
git commit -s -m "ci(bedrock): validate strict three-model dev matrix"
```

---

### Task 4: Update operator documentation

**Files:**
- Modify: `docs/real-agent-sandbox-requirements.md`
- Modify: `examples/agent-action-monitor/README.md`

**Interfaces:**
- Consumes: the source-controlled model allowlist and existing protected environment.
- Produces: accurate operator instructions explaining that no obsolete single-model variable controls the matrix.

- [ ] **Step 1: Update operator documentation**

Document the three exact models, strict all-pass rule, model-specific artifacts, protected approval, and zero-failure/error/skip acceptance criteria. State that the workflow allowlist is authoritative and that the legacy `BEDROCK_MODEL_ID` environment variable does not select matrix models.

State that setup scripts remain read-only by default, do not control the source-managed matrix, and must not dispatch the workflow.

- [ ] **Step 2: Run documentation validation**

Run:

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest tests/ci/test_real_agent_mantle.py -q
python -c "from pathlib import Path; files=[Path('docs/real-agent-sandbox-requirements.md'),Path('examples/agent-action-monitor/README.md')]; bad=[(str(p),c) for p in files for c in (chr(0x2014),chr(0x2013),'TODO','TBD','PLACEHOLDER') if c in p.read_text(encoding='utf-8')]; print(bad); raise SystemExit(bool(bad))"
```

Expected: tests pass and the scan prints no matches.

- [ ] **Step 3: Commit Task 4**

```powershell
git add docs/real-agent-sandbox-requirements.md `
  examples/agent-action-monitor/README.md
git commit -s -m "docs(bedrock): document strict model promotion gate"
```

---

### Task 5: Complete local verification and prepare the single PR

**Files:**
- Verify every changed file.
- Do not modify AWS or GitHub environment state.

**Interfaces:**
- Consumes: Tasks 1 through 4.
- Produces: one reviewed feature branch and one PR targeting `dev`.

- [ ] **Step 1: Run focused verification**

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest tests/ci/test_real_agent_mantle.py tests/ci/test_real_agent_workflow.py -q
Push-Location examples/agent-action-monitor
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest agent-demo/test_bedrock_client.py `
  tests/test_validate_real_agent_evidence.py `
  tests/real_llm/test_result_contract.py `
  tests/test_actions_mantle.py -q
Pop-Location
```

- [ ] **Step 2: Run full repository verification**

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest -q
Push-Location examples/agent-action-monitor
$env:PYTHONPATH = (Resolve-Path src).Path
python -m pytest -q
Pop-Location
ruff check .
ruff format --check .
actionlint .github/workflows/real-agent-sandbox-dev.yml
zizmor .github/workflows/real-agent-sandbox-dev.yml
git diff --check origin/dev...HEAD
```

Report passed, failed, skipped, baseline-only, and unavailable checks separately. Ordinary local real-LLM skips are not live evidence.

- [ ] **Step 3: Audit the exact diff and attribution**

Verify:

```powershell
git diff --name-status origin/dev...HEAD
git diff --exit-code origin/dev -- `
  infra/aws/bedrock-mantle-dev/template.yaml `
  infra/aws/bedrock-mantle-main/template.yaml `
  .github/workflows/real-agent-sandbox.yml
git log --format="%H %an <%ae>%n%B" origin/dev..HEAD
git status --short --branch
```

Expected: IAM and main workflow are unchanged, commits contain Tanvir attribution and sign-off only, and the worktree is clean.

- [ ] **Step 4: Push and open one PR into dev**

Push `feat/multi-model-dev-validation` and open one non-draft PR targeting `dev`. The PR body must distinguish local mocked evidence from the pending protected live run.

- [ ] **Step 5: Monitor and inspect all PR checks**

Wait for all required checks. Do not call the PR merge-ready while any check is failed, queued, missing, or unverified. Obtain required review before merge.

---

### Task 6: Execute and inspect the protected three-model dev run

**Files:**
- No repository edits unless a live failure is reproduced by a failing automated test first.

**Interfaces:**
- Consumes: the merged exact `dev` commit, `real-agent-dev` protection, OIDC role, London region, and DUSK gate secret.
- Produces: inspectable live evidence for every model on one commit.

- [ ] **Step 1: Verify protected environment without mutation**

Confirm required reviewer, self-review prevention, dev-only branch policy, `AWS_REGION=eu-west-2`, `BEDROCK_PROVIDER=mantle`, role ARN presence, and DUSK gate secret presence. Do not print secret values.

- [ ] **Step 2: Dispatch enforce mode on the exact dev commit**

```powershell
gh workflow run 343813382 `
  --repo ShieldTech-Ltd/DUSK `
  --ref dev `
  -f gate_mode=enforce
```

Obtain approval from a permitted reviewer who did not trigger the run.

- [ ] **Step 3: Monitor every matrix job and aggregate gate**

Require Kimi, GLM, Nemotron, and `Real-agent dev matrix gate` to complete successfully. A queued job is not green.

- [ ] **Step 4: Download and inspect all three artifacts**

For every model, confirm the JUnit and manifest both report more than zero tests and exactly zero failures, errors, and skips. Confirm the model ID and commit SHA match the dispatched run. Confirm the gate log is non-empty and enforce-mode isolation passed.

- [ ] **Step 5: Issue the final verdict**

Return `MERGE READY FOR DEV TO MAIN PROMOTION` only if all three protected model jobs, the aggregate gate, repository CI, required approval, and artifact inspection are complete. Otherwise return `NEEDS WORK` with the exact failing model, step, error, and evidence path.
