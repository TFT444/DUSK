"""CI tests for the Bedrock Mantle dev-validation workflow, IAM, and adapter."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

_DEV_WORKFLOW_PATH = Path(".github/workflows/real-agent-sandbox-dev.yml")
_PROD_WORKFLOW_PATH = Path(".github/workflows/real-agent-sandbox.yml")
_DEV_TEMPLATE_PATH = Path("infra/aws/bedrock-mantle-dev/template.yaml")
_MAIN_TEMPLATE_PATH = Path("infra/aws/bedrock-mantle-main/template.yaml")
_PROD_TEMPLATE_PATH = Path("infra/aws/bedrock-real-agent/template.yaml")
_DEV_SETUP_PATH = Path("scripts/setup-bedrock-mantle-dev.ps1")
_MAIN_SETUP_PATH = Path("scripts/setup-bedrock-mantle-main.ps1")
_HARNESS_ROOT = Path("dusk-agent-harness")
_LOCK_FILE_PATH = _HARNESS_ROOT / "requirements-real-agent.txt"
_EVIDENCE_VALIDATOR_PATH = _HARNESS_ROOT / "scripts/validate_real_agent_evidence.py"
_CONFIGURE_AWS_SHA = "e6de054238d6b7531b4efff3b6587d9aade6a06c"

_DEV_JOB = "real-agent-dev-validation"
_MATRIX_GATE_JOB = "real-agent-dev-matrix-gate"
EXPECTED_MODELS = [
    {"slug": "kimi-k2-5", "id": "moonshotai.kimi-k2.5"},
    {"slug": "glm-5", "id": "zai.glm-5"},
    {"slug": "qwen3-32b", "id": "qwen.qwen3-32b"},
    {"slug": "gpt-oss-120b", "id": "openai.gpt-oss-120b"},
]


def _dev_workflow() -> dict:
    return yaml.safe_load(_DEV_WORKFLOW_PATH.read_text(encoding="utf-8"))


def _prod_workflow() -> dict:
    return yaml.safe_load(_PROD_WORKFLOW_PATH.read_text(encoding="utf-8"))


def _dev_template() -> dict:
    return yaml.safe_load(_DEV_TEMPLATE_PATH.read_text(encoding="utf-8"))


def _dev_role() -> dict:
    t = _dev_template()
    return t["Resources"]["DuskMantleDevRole"]


def _main_template() -> dict:
    return yaml.safe_load(_MAIN_TEMPLATE_PATH.read_text(encoding="utf-8"))


def _main_role() -> dict:
    return _main_template()["Resources"]["DuskMantleMainRole"]


def _main_actions() -> set[str]:
    statements = _main_role()["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    return {
        action
        for statement in statements
        for action in (
            [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
        )
    }


def _dev_steps() -> list[dict]:
    return _dev_workflow()["jobs"][_DEV_JOB]["steps"]


def _registered_model_pairs() -> list[tuple[str, str]]:
    harness_path = str(_HARNESS_ROOT.resolve())
    sys.path.insert(0, harness_path)
    try:
        from models.registry import MODEL_PROFILES
    finally:
        sys.path.pop(0)

    return [(profile.slug, profile.model_id) for profile in MODEL_PROFILES]


def _dev_workflow_matrix_branches() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    model_expression = _dev_workflow()["jobs"][_DEV_JOB]["strategy"]["matrix"]["model"]
    qualification_json, full_matrix_json = model_expression.split("&& '", 1)[1].split("' || '", 1)
    return json.loads(qualification_json), json.loads(full_matrix_json.removesuffix("') }}"))


def test_gpt_oss_qualification_is_integrated_into_the_registered_dev_workflow() -> None:
    assert not Path(".github/workflows/real-agent-gpt-oss-qualification-dev.yml").exists()
    workflow = _dev_workflow()
    on = workflow[True] if True in workflow else workflow["on"]
    inputs = on["workflow_dispatch"]["inputs"]
    target = inputs["run_target"]

    assert target["type"] == "choice"
    assert target["options"] == ["gpt-oss-qualification", "full-matrix"]
    assert target["default"] == "gpt-oss-qualification"


def test_dev_workflow_contains_the_complete_four_model_set() -> None:
    qualification, full_matrix = _dev_workflow_matrix_branches()
    registered_pairs = _registered_model_pairs()

    assert qualification == [{"slug": "gpt-oss-120b", "id": "openai.gpt-oss-120b"}]
    assert full_matrix == [
        {"slug": "kimi-k2-5", "id": "moonshotai.kimi-k2.5"},
        {"slug": "glm-5", "id": "zai.glm-5"},
        {"slug": "qwen3-32b", "id": "qwen.qwen3-32b"},
        {"slug": "gpt-oss-120b", "id": "openai.gpt-oss-120b"},
    ]
    assert [(model["slug"], model["id"]) for model in qualification] == [registered_pairs[-1]]
    assert [(model["slug"], model["id"]) for model in full_matrix] == registered_pairs


def test_dev_workflow_uses_production_harness_paths() -> None:
    job = _dev_workflow()["jobs"][_DEV_JOB]
    setup_python = next(
        step for step in job["steps"] if step.get("uses", "").startswith("actions/setup-python@")
    )
    upload = next(
        step for step in job["steps"] if step.get("uses", "").startswith("actions/upload-artifact@")
    )

    assert job["defaults"]["run"]["working-directory"] == "dusk-agent-harness"
    assert setup_python["with"]["cache-dependency-path"].strip() == (
        "dusk-agent-harness/requirements-real-agent.txt"
    )
    assert upload["with"]["path"] == "dusk-agent-harness/ci-logs/${{ matrix.model.slug }}/"
    legacy_root = "/".join(("examples", "agent-action-monitor"))
    assert legacy_root not in _DEV_WORKFLOW_PATH.read_text(encoding="utf-8")


def test_gpt_oss_qualification_forces_enforce_mode() -> None:
    job = _dev_workflow()["jobs"][_DEV_JOB]
    assert job["env"]["EFFECTIVE_GATE_MODE"] == (
        "${{ github.event.inputs.run_target == 'gpt-oss-qualification' "
        "&& 'enforce' || github.event.inputs.gate_mode }}"
    )
    for step in job["steps"]:
        if "DUSK_ENFORCE" in step.get("env", {}):
            assert step["env"]["DUSK_ENFORCE"] == (
                "${{ env.EFFECTIVE_GATE_MODE == 'enforce' && 'true' || 'false' }}"
            )


# --- Dev workflow structure ------------------------------------------------


def test_dev_workflow_is_dev_only() -> None:
    steps = _dev_steps()
    ref_check = next((s for s in steps if "refs/heads/dev" in s.get("run", "")), None)
    assert ref_check is not None, "Dev workflow must gate on refs/heads/dev"
    assert "exit 1" in ref_check["run"]
    text = _DEV_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "refs/heads/main" not in text, "Dev workflow must not gate on main"


def test_dev_workflow_uses_separate_environment() -> None:
    w = _dev_workflow()
    job = w["jobs"][_DEV_JOB]
    assert job["environment"] == "real-agent-dev"
    assert job["environment"] != "real-agent"


def test_dev_workflow_names_the_job_and_does_not_persist_checkout_credentials() -> None:
    job = _dev_workflow()["jobs"][_DEV_JOB]
    assert "${{ matrix.model.slug }}" in job["name"]
    checkout = next(s for s in job["steps"] if s.get("uses", "").startswith("actions/checkout@"))
    assert checkout["with"]["persist-credentials"] is False


def test_dev_workflow_has_separate_concurrency_group() -> None:
    dev = _dev_workflow()
    prod = _prod_workflow()
    assert "concurrency" in dev
    dev_group = dev["concurrency"]["group"]
    prod_group = prod["concurrency"]["group"]
    assert dev_group != prod_group
    assert "mantle-dev" in dev_group
    assert dev["concurrency"].get("cancel-in-progress") is False


def test_dev_workflow_is_dispatch_only() -> None:
    w = _dev_workflow()
    on = w[True] if True in w else w["on"]
    assert "workflow_dispatch" in on
    assert "schedule" not in on, "Dev validation must be dispatch-only, no schedule"


def test_dev_workflow_requires_bedrock_provider_env_var() -> None:
    w = _dev_workflow()
    job = w["jobs"][_DEV_JOB]
    preflight = next((s for s in job["steps"] if "preflight" in s.get("name", "").lower()), None)
    assert preflight is not None
    run_script = preflight.get("run", "")
    for var in (
        "AWS_ROLE_ARN",
        "AWS_REGION",
        "BEDROCK_PROVIDER",
        "DUSK_GATE_API_KEY",
    ):
        assert var in run_script, f"Preflight must check {var}"
    assert "BEDROCK_MODEL_ID" not in run_script
    assert "exit 1" in run_script


def test_dev_workflow_runs_the_exact_approved_model_matrix() -> None:
    job = _dev_workflow()["jobs"][_DEV_JOB]
    assert job["strategy"]["fail-fast"] is False
    model_expression = job["strategy"]["matrix"]["model"]
    qualification_json = json.dumps([EXPECTED_MODELS[-1]], separators=(",", ":"))
    full_matrix_json = json.dumps(EXPECTED_MODELS, separators=(",", ":"))
    assert model_expression == (
        "${{ fromJSON(github.event.inputs.run_target == 'gpt-oss-qualification' "
        + f"&& '{qualification_json}' || '{full_matrix_json}') "
        + "}}"
    )
    assert job["env"]["BEDROCK_MODEL_ID"] == "${{ matrix.model.id }}"


def test_dev_workflow_has_strict_aggregate_gate() -> None:
    gate = _dev_workflow()["jobs"][_MATRIX_GATE_JOB]
    assert gate["needs"] == _DEV_JOB
    assert gate["if"] == "always()"
    script = gate["steps"][0]["run"]
    assert "needs.real-agent-dev-validation.result" in script
    assert "exit 1" in script


def test_dev_workflow_matrix_gate_has_bounded_runtime() -> None:
    gate = _dev_workflow()["jobs"][_MATRIX_GATE_JOB]
    assert gate["timeout-minutes"] == 5


def test_dev_workflow_uses_real_inference_to_qualify_each_matrix_model() -> None:
    steps = _dev_steps()
    assert not any(step.get("name") == "Verify Mantle model availability" for step in steps)

    test_step = next(step for step in steps if step.get("name") == "Run real-LLM gate tests")
    assert test_step["env"]["USE_REAL_BEDROCK"] == "true"
    assert _dev_workflow()["jobs"][_DEV_JOB]["env"]["BEDROCK_MODEL_ID"] == (
        "${{ matrix.model.id }}"
    )


def test_dev_workflow_writes_isolated_per_model_evidence() -> None:
    steps = _dev_steps()
    upload = next(s for s in steps if s.get("uses", "").startswith("actions/upload-artifact@"))
    assert "${{ matrix.model.slug }}" in upload["with"]["name"]
    assert "${{ github.run_id }}" in upload["with"]["name"]
    assert "${{ matrix.model.slug }}" in upload["with"]["path"]

    validate = next(s for s in steps if s.get("name") == "Validate model evidence")
    assert validate["env"]["MATRIX_MODEL_ID"] == "${{ matrix.model.id }}"
    assert validate["env"]["MATRIX_MODEL_SLUG"] == "${{ matrix.model.slug }}"
    assert '--model-id "$MATRIX_MODEL_ID"' in validate["run"]
    assert '--model-slug "$MATRIX_MODEL_SLUG"' in validate["run"]


def test_dev_workflow_has_no_model_fallback_or_dispatch_override() -> None:
    workflow = _dev_workflow()
    on = workflow[True] if True in workflow else workflow["on"]
    inputs = on["workflow_dispatch"].get("inputs", {})
    assert "model" not in inputs
    assert "model_id" not in inputs

    text = _DEV_WORKFLOW_PATH.read_text(encoding="utf-8").lower()
    assert "fallback" not in text
    assert "continue-on-error" not in text


def test_dev_workflow_explicitly_enables_protected_real_model_tests() -> None:
    test_step = next(s for s in _dev_steps() if s.get("name") == "Run real-LLM gate tests")
    assert test_step["env"]["USE_REAL_BEDROCK"] == "true"


def test_dev_workflow_exposes_the_harness_root_to_real_model_tests() -> None:
    test_step = next(s for s in _dev_steps() if s.get("name") == "Run real-LLM gate tests")
    assert test_step["env"]["PYTHONPATH"] == ".:src:runtime"


def test_dev_workflow_starts_only_persistent_compose_services() -> None:
    start_step = next(
        s for s in _dev_steps() if s.get("name") == "Start gate and mock-prod via Docker Compose"
    )
    compose_up_lines = [
        line.strip()
        for line in start_step["run"].splitlines()
        if "docker compose" in line and " up " in f" {line} "
    ]

    assert compose_up_lines == [
        "docker compose -f compose.yml -f compose.ci.yml up -d --wait dusk-gate mock-prod"
    ], (
        "The real-agent workflow must start only persistent services. Starting the one-shot "
        "runtime service makes `docker compose up --wait` return exit code 1 after the "
        "container exits successfully."
    )


def test_prod_workflow_remains_main_only() -> None:
    """Regression: the prod workflow must still gate on main, not dev."""
    text = _PROD_WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "refs/heads/main" in text
    assert "refs/heads/dev" not in text


# --- Main Mantle IAM -------------------------------------------------------


def test_main_template_defaults_are_main_only() -> None:
    params = _main_template()["Parameters"]
    assert params["GitHubEnvironment"]["Default"] == "real-agent"
    assert params["RoleName"]["Default"] == "DuskRealAgentMainMantleRole"
    assert params["RoleName"]["Default"] != _dev_template()["Parameters"]["RoleName"]["Default"]


def test_main_template_uses_exact_immutable_oidc_subject() -> None:
    statement = _main_role()["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
    assert statement["Condition"]["StringEquals"] == {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": {
            "Fn::Sub": (
                "repo:${GitHubOrg}@${GitHubOrgId}/${GitHubRepo}@${GitHubRepoId}:"
                "environment:${GitHubEnvironment}"
            )
        },
    }


def test_main_template_action_allowlist_is_exact() -> None:
    assert _main_actions() == {
        "bedrock-mantle:CallWithBearerToken",
        "bedrock-mantle:CreateInference",
        "bedrock-mantle:GetProject",
        "bedrock-mantle:ListProjects",
        "bedrock-mantle:ListTagsForResource",
    }


def test_main_template_scopes_mantle_permissions() -> None:
    statements = _main_role()["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    token_statement = next(
        statement
        for statement in statements
        if statement["Action"] == "bedrock-mantle:CallWithBearerToken"
    )
    assert token_statement["Resource"] == "*"
    assert token_statement["Condition"]["StringEquals"] == {
        "bedrock-mantle:bearerTokenType": "SHORT_TERM"
    }

    project_statement = next(
        statement for statement in statements if isinstance(statement["Action"], list)
    )
    assert project_statement["Resource"] == {
        "Fn::Sub": (
            "arn:${AWS::Partition}:bedrock-mantle:${AWS::Region}:${AWS::AccountId}:project/*"
        )
    }


def test_main_template_has_no_runtime_iam_or_wildcard_actions() -> None:
    actions = _main_actions()
    assert "*" not in actions
    assert "bedrock:InvokeModel" not in actions
    assert "bedrock:ListInferenceProfiles" not in actions
    assert not any(action.startswith("iam:") for action in actions)


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


def test_main_setup_never_dispatches_or_changes_provider_variables() -> None:
    script = _MAIN_SETUP_PATH.read_text(encoding="utf-8")
    assert "gh workflow run" not in script
    assert 'gh variable set "AWS_ROLE_ARN"' in script
    assert 'gh variable set "AWS_REGION"' not in script
    assert 'gh variable set "BEDROCK_PROVIDER"' not in script
    assert 'gh variable set "BEDROCK_MODEL_ID"' not in script


# --- Dev IAM ---------------------------------------------------------------


def test_dev_template_oidc_subject_is_exact_no_wildcard() -> None:
    role = _dev_role()
    trust = role["Properties"]["AssumeRolePolicyDocument"]
    statement = trust["Statement"][0]
    condition = statement["Condition"]["StringEquals"]
    sub = condition["token.actions.githubusercontent.com:sub"]
    sub_value = str(sub)
    assert "*" not in sub_value
    assert "real-agent-dev" in sub_value or "GitHubEnvironment" in sub_value


def test_dev_template_oidc_trust_has_one_exact_statement() -> None:
    trust = _dev_role()["Properties"]["AssumeRolePolicyDocument"]
    assert len(trust["Statement"]) == 1
    statement = trust["Statement"][0]
    assert statement["Effect"] == "Allow"
    assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
    assert statement["Principal"]["Federated"] == {
        "Fn::If": [
            "CreateOidcProvider",
            {"Fn::GetAtt": ["GitHubOidcProvider", "Arn"]},
            {"Ref": "ExistingOidcProviderArn"},
        ]
    }
    assert statement["Condition"]["StringEquals"] == {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": {
            "Fn::Sub": (
                "repo:${GitHubOrg}@${GitHubOrgId}/${GitHubRepo}@${GitHubRepoId}:"
                "environment:${GitHubEnvironment}"
            )
        },
    }


def test_dev_template_requires_immutable_github_owner_and_repo_ids() -> None:
    parameters = _dev_template()["Parameters"]
    assert parameters["GitHubOrgId"]["AllowedPattern"] == "^[0-9]+$"
    assert parameters["GitHubRepoId"]["AllowedPattern"] == "^[0-9]+$"
    template_text = _DEV_TEMPLATE_PATH.read_text(encoding="utf-8")
    assert "repo:${GitHubOrg}/${GitHubRepo}:environment:" not in template_text


def test_dev_template_has_no_wildcard_actions() -> None:
    role = _dev_role()
    for policy in role["Properties"]["Policies"]:
        for stmt in policy["PolicyDocument"]["Statement"]:
            actions = stmt["Action"]
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                assert action != "*", f"Wildcard action found: {action}"
                assert not action.startswith("iam:")


def test_dev_template_allows_only_short_term_mantle_bearer_tokens() -> None:
    role = _dev_role()
    statements = []
    for policy in role["Properties"]["Policies"]:
        statements.extend(policy["PolicyDocument"]["Statement"])

    mantle_statement = next(
        stmt for stmt in statements if stmt["Action"] == "bedrock-mantle:CallWithBearerToken"
    )
    assert mantle_statement["Resource"] == "*"
    assert mantle_statement["Condition"] == {
        "StringEquals": {"bedrock-mantle:bearerTokenType": "SHORT_TERM"}
    }

    actions = {
        action
        for stmt in statements
        for action in ([stmt["Action"]] if isinstance(stmt["Action"], str) else stmt["Action"])
    }
    assert "bedrock:GetFoundationModelToken" not in actions


def test_dev_template_grants_scoped_mantle_inference_permissions() -> None:
    role = _dev_role()
    statements = [
        stmt
        for policy in role["Properties"]["Policies"]
        for stmt in policy["PolicyDocument"]["Statement"]
    ]
    inference_statement = next(
        stmt for stmt in statements if "bedrock-mantle:CreateInference" in stmt["Action"]
    )
    assert set(inference_statement["Action"]) == {
        "bedrock-mantle:CreateInference",
        "bedrock-mantle:GetProject",
        "bedrock-mantle:ListProjects",
        "bedrock-mantle:ListTagsForResource",
    }
    assert inference_statement["Resource"] == {
        "Fn::Sub": (
            "arn:${AWS::Partition}:bedrock-mantle:${AWS::Region}:${AWS::AccountId}:project/*"
        )
    }


def test_dev_template_action_allowlist_is_exact() -> None:
    actions = {
        action
        for policy in _dev_role()["Properties"]["Policies"]
        for statement in policy["PolicyDocument"]["Statement"]
        for action in (
            [statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"]
        )
    }
    assert actions == {
        "bedrock-mantle:CallWithBearerToken",
        "bedrock-mantle:CreateInference",
        "bedrock-mantle:GetProject",
        "bedrock-mantle:ListProjects",
        "bedrock-mantle:ListTagsForResource",
    }


def test_dev_setup_rejects_extra_effective_role_permissions() -> None:
    script = _DEV_SETUP_PATH.read_text(encoding="utf-8")
    assert "list-attached-role-policies" in script
    assert "$policyNames.Count -ne 1" in script
    assert "$policy.PolicyDocument.Statement.Count -ne 2" in script
    assert "Unexpected action" in script


def test_dev_setup_validates_the_published_role_arn_and_live_trust() -> None:
    script = _DEV_SETUP_PATH.read_text(encoding="utf-8")
    assert "$roleArn -ne $expectedRoleArn" in script
    assert "aws iam get-role --role-name $RoleName" in script
    assert "sts:AssumeRoleWithWebIdentity" in script
    assert "token.actions.githubusercontent.com:aud" in script
    assert "token.actions.githubusercontent.com:sub" in script
    assert "gh api orgs/ShieldTech-Ltd --jq .id" in script
    assert "gh api repos/ShieldTech-Ltd/DUSK --jq .id" in script
    assert "GitHubOrgId=$githubOrgId" in script
    assert "GitHubRepoId=$githubRepoId" in script
    assert (
        "repo:ShieldTech-Ltd@${githubOrgId}/DUSK@${githubRepoId}:environment:real-agent-dev"
        in script
    )


def test_dev_template_has_no_invoke_model() -> None:
    """Mantle uses a bearer token via the OpenAI client, not boto3 InvokeModel."""
    role = _dev_role()
    actions = set()
    for policy in role["Properties"]["Policies"]:
        for stmt in policy["PolicyDocument"]["Statement"]:
            a = stmt["Action"]
            actions.update([a] if isinstance(a, str) else a)
    assert "bedrock:InvokeModel" not in actions
    assert "bedrock:ListInferenceProfiles" not in actions


def test_dev_template_separate_from_prod_template() -> None:
    assert _DEV_TEMPLATE_PATH.exists()
    assert _PROD_TEMPLATE_PATH.exists()
    assert _DEV_TEMPLATE_PATH != _PROD_TEMPLATE_PATH
    dev = _dev_template()
    # Dev role name must differ from prod role name.
    assert dev["Resources"]["DuskMantleDevRole"]["Properties"]["RoleName"]["Ref"] == "RoleName"
    assert dev["Parameters"]["RoleName"]["Default"] == "DuskRealAgentDevMantleRole"


# --- MantleAdapter ---------------------------------------------------------


def _function_call(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "call_abc123",
        "name": "update_firewall_rule",
        "arguments_json": json.dumps({"target": "fw-x", "before": None, "after": {"port": 22}}),
    }
    base.update(overrides)
    return base


def test_mantle_adapter_parses_valid_function_call() -> None:
    from dusk.actions.adapters.mantle import MantleAdapter

    action = MantleAdapter().parse_function_call(
        _function_call(),
        agent_id="agent-x",
        timestamp=datetime(2026, 7, 10, tzinfo=UTC),
    )
    assert action.source == "mantle"
    assert action.target == "fw-x"
    assert action.action_type == "firewall_rule_change"


def test_mantle_adapter_raises_on_malformed_json() -> None:
    from dusk.actions.adapters.base import AdapterError
    from dusk.actions.adapters.mantle import MantleAdapter

    with pytest.raises(AdapterError):
        MantleAdapter().parse_function_call(
            _function_call(arguments_json="{bad json"),
            agent_id="agent-x",
            timestamp=datetime(2026, 7, 10, tzinfo=UTC),
        )


def test_mantle_adapter_raises_on_missing_target() -> None:
    from dusk.actions.adapters.base import AdapterError
    from dusk.actions.adapters.mantle import MantleAdapter

    with pytest.raises(AdapterError):
        MantleAdapter().parse_function_call(
            _function_call(arguments_json=json.dumps({"after": {}})),
            agent_id="agent-x",
            timestamp=datetime(2026, 7, 10, tzinfo=UTC),
        )


def test_mantle_adapter_raises_on_unexpected_tool() -> None:
    from dusk.actions.adapters.base import AdapterError
    from dusk.actions.adapters.mantle import MantleAdapter

    with pytest.raises(AdapterError):
        MantleAdapter().parse_function_call(
            _function_call(
                name="rm_rf_root",
                arguments_json=json.dumps({"target": "x"}),
            ),
            agent_id="agent-x",
            timestamp=datetime(2026, 7, 10, tzinfo=UTC),
        )


def test_mantle_adapter_no_auth_header_in_error_messages() -> None:
    from dusk.actions.adapters.base import AdapterError
    from dusk.actions.adapters.mantle import MantleAdapter

    try:
        MantleAdapter().parse_function_call(
            _function_call(arguments_json="{bad"),
            agent_id="agent-x",
            timestamp=datetime(2026, 7, 10, tzinfo=UTC),
        )
    except AdapterError as exc:
        message = str(exc).lower()
        assert "authorization" not in message
        assert "bearer" not in message


# --- Dependencies ----------------------------------------------------------


def test_requirements_lock_file_contains_openai_with_hash() -> None:
    text = _LOCK_FILE_PATH.read_text(encoding="utf-8")
    assert "openai==" in text
    # The openai entry must carry at least one sha256 hash.
    lines = text.splitlines()
    idx = next(i for i, ln in enumerate(lines) if ln.startswith("openai=="))
    window = "\n".join(lines[idx : idx + 6])
    assert "--hash=sha256:" in window


def test_requirements_lock_file_contains_aws_bedrock_token_generator() -> None:
    text = _LOCK_FILE_PATH.read_text(encoding="utf-8")
    assert "aws-bedrock-token-generator==" in text
    lines = text.splitlines()
    idx = next(i for i, ln in enumerate(lines) if ln.startswith("aws-bedrock-token-generator=="))
    window = "\n".join(lines[idx : idx + 6])
    assert "--hash=sha256:" in window


# --- Evidence --------------------------------------------------------------


def test_dev_workflow_evidence_upload_runs_always() -> None:
    w = _dev_workflow()
    job = w["jobs"][_DEV_JOB]
    upload = next(
        (s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact")),
        None,
    )
    assert upload is not None
    assert upload.get("if") == "always()"
    assert upload["with"]["retention-days"] == 30


def test_dev_workflow_stop_containers_runs_always() -> None:
    w = _dev_workflow()
    job = w["jobs"][_DEV_JOB]
    stop = next((s for s in job["steps"] if "stop" in s.get("name", "").lower()), None)
    assert stop is not None
    assert stop.get("if") == "always()"
    assert stop["env"]["DUSK_GATE_API_KEY"] == "${{ secrets.DUSK_GATE_API_KEY }}"


def test_dev_workflow_fails_if_real_llm_tests_skipped() -> None:
    validate = next(s for s in _dev_steps() if s.get("name") == "Validate model evidence")
    assert "validate_real_agent_evidence.py" in validate["run"]
    validator = _EVIDENCE_VALIDATOR_PATH.read_text(encoding="utf-8")
    assert '("failures", "errors", "skipped")' in validator
    assert "raise ValueError" in validator


def test_dev_workflow_log_collection_is_stage_aware() -> None:
    collect = next(s for s in _dev_steps() if s.get("name") == "Collect gate logs as evidence")
    script = collect["run"]
    assert "docker compose" in script
    assert "ps -q dusk-gate" in script
    assert "gate-not-started" in script
    assert 'if [ ! -s "$EVIDENCE_DIR/real-agent-gate.log" ]' in script


def test_dev_workflow_never_generates_or_prints_bearer_token() -> None:
    """The workflow must not mint or surface a bearer token in any step.

    The token is minted inside the Python client only. The workflow may
    mention 'bearer' in an explanatory comment, but it must never invoke the
    token generator, the token-minting CLI, or echo a token value.
    """
    steps = _dev_steps()
    for step in steps:
        run_script = step.get("run", "").lower()
        assert "provide_token" not in run_script
        assert "get-foundation-model-token" not in run_script
        # No step should echo/print a variable named like a token.
        assert "echo $token" not in run_script
        assert 'echo "$token' not in run_script
