"""Infrastructure tests for Bedrock OIDC CloudFormation template and setup scripts."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_TEMPLATE_PATH = Path("infra/aws/bedrock-real-agent/template.yaml")
_SETUP_SCRIPT_PATH = Path("scripts/setup-bedrock-oidc.ps1")
_WORKFLOW_PATH = Path(".github/workflows/real-agent-sandbox.yml")


def _template() -> dict:
    return yaml.safe_load(_TEMPLATE_PATH.read_text(encoding="utf-8"))


def _workflow() -> dict:
    return yaml.safe_load(_WORKFLOW_PATH.read_text(encoding="utf-8"))


def test_cloudformation_template_is_valid_yaml() -> None:
    t = _template()
    assert "AWSTemplateFormatVersion" in t
    assert "Resources" in t
    assert "Parameters" in t
    assert "Outputs" in t


def test_oidc_subject_restricted_to_real_agent_environment() -> None:
    t = _template()
    role = t["Resources"]["DuskBedrockRole"]
    trust = role["Properties"]["AssumeRolePolicyDocument"]
    statement = trust["Statement"][0]
    condition = statement["Condition"]["StringEquals"]
    sub_raw = condition["token.actions.githubusercontent.com:sub"]
    sub_value = str(sub_raw)
    assert "environment" in sub_value or "GitHubEnvironment" in sub_value
    assert "*" not in sub_value


def test_oidc_audience_is_sts() -> None:
    t = _template()
    role = t["Resources"]["DuskBedrockRole"]
    trust = role["Properties"]["AssumeRolePolicyDocument"]
    statement = trust["Statement"][0]
    condition = statement["Condition"]["StringEquals"]
    aud_value = condition["token.actions.githubusercontent.com:aud"]
    assert aud_value == "sts.amazonaws.com"


def test_iam_policy_does_not_grant_admin_access() -> None:
    t = _template()
    role = t["Resources"]["DuskBedrockRole"]
    policies = role["Properties"]["Policies"]
    for policy in policies:
        doc = policy["PolicyDocument"]
        for stmt in doc["Statement"]:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                assert action != "*", f"Wildcard action found: {action}"
                assert not action.startswith("iam:"), f"IAM action found: {action}"
                assert action in {
                    "bedrock:GetFoundationModel",
                    "bedrock:ListInferenceProfiles",
                    "bedrock:InvokeModel",
                }, f"Unexpected action: {action}"
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            for r in resources:
                if r == "*":
                    assert actions == ["bedrock:ListInferenceProfiles"], (
                        "Wildcard resources are permitted only for the AWS list action"
                    )


def test_template_contains_no_static_credentials() -> None:
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    assert "AWS_ACCESS_KEY_ID" not in text
    assert "AWS_SECRET_ACCESS_KEY" not in text
    assert "AWS_SESSION_TOKEN" not in text
    # Double-colon (::foundation-model) is the correct format; single-colon
    # with 12 digits would be a hardcoded account ID.
    account_pattern = re.compile(r"(?<!:):(\d{12}):")
    assert not account_pattern.search(text), "Hardcoded account ID found in template"


def test_trust_policy_subject_has_no_wildcard() -> None:
    t = _template()
    role = t["Resources"]["DuskBedrockRole"]
    trust = role["Properties"]["AssumeRolePolicyDocument"]
    statement = trust["Statement"][0]
    sub_condition = str(statement["Condition"]["StringEquals"])
    assert "*" not in sub_condition


def test_trust_policy_excludes_pull_requests_and_refs() -> None:
    t = _template()
    role = t["Resources"]["DuskBedrockRole"]
    trust = role["Properties"]["AssumeRolePolicyDocument"]
    statement = trust["Statement"][0]
    sub_value = str(statement["Condition"]["StringEquals"])
    assert "pull_request" not in sub_value
    assert ":ref:" not in sub_value
    assert ":branch:" not in sub_value


def test_model_resource_uses_region_reference_and_no_account_id() -> None:
    t = _template()
    role = t["Resources"]["DuskBedrockRole"]
    policy_doc = role["Properties"]["Policies"][0]["PolicyDocument"]
    invoke_statement = next(
        statement
        for statement in policy_doc["Statement"]
        if "bedrock:InvokeModel"
        in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
    )
    resource_raw = invoke_statement["Resource"]
    resource = str(resource_raw)
    assert resource != "*", "Resource must not be a wildcard"
    assert "inference-profile" in resource, "Inference profile ARN is required"
    assert "AWS::AccountId" in resource, "Inference profile ARN must include account ID"
    # No literal 12-digit account IDs
    account_pattern = re.compile(r"(?<!:):(\d{12}):")
    assert not account_pattern.search(resource), "Hardcoded account ID in resource ARN"


def test_conditional_oidc_provider_creation() -> None:
    t = _template()
    conditions = t.get("Conditions", {})
    assert "CreateOidcProvider" in conditions, "CreateOidcProvider condition missing"
    resources = t["Resources"]
    if "GitHubOidcProvider" in resources:
        provider = resources["GitHubOidcProvider"]
        assert provider.get("Condition") == "CreateOidcProvider"


def test_outputs_include_role_arn_and_oidc_provider_arn() -> None:
    t = _template()
    outputs = t.get("Outputs", {})
    assert "RoleArn" in outputs
    assert "OidcProviderArn" in outputs
    assert "ModelResource" in outputs


def test_setup_script_does_not_print_secrets() -> None:
    text = _SETUP_SCRIPT_PATH.read_text(encoding="utf-8")
    forbidden_patterns = [
        r"Write-Host.*DUSK_GATE_API_KEY",
        r"Write-Output.*DUSK_GATE_API_KEY",
        r"echo.*DUSK_GATE_API_KEY",
        r"Write-Host.*AWS_SECRET_ACCESS_KEY",
        r"Write-Host.*AWS_SESSION_TOKEN",
    ]
    for pattern in forbidden_patterns:
        assert not re.search(pattern, text), f"Secret printing pattern found: {pattern}"


def test_setup_script_does_not_dispatch_workflow() -> None:
    text = _SETUP_SCRIPT_PATH.read_text(encoding="utf-8")
    assert "gh workflow run" not in text
    assert "workflow dispatch" not in text.lower()
    assert "Invoke-RestMethod" not in text or "dispatches" not in text.lower()


def test_setup_script_validates_deployment_branch_policy_restricts_to_main() -> None:
    """Setup script must verify the real-agent environment is restricted to main only.

    custom_branch_policies:true with no branch filter allows any branch to
    deploy, which defeats the OIDC trust's environment restriction.  The
    script must detect this and fail rather than silently pass.
    """
    text = _SETUP_SCRIPT_PATH.read_text(encoding="utf-8")
    assert "deployment_branch_policy" in text, (
        "Setup script must check the environment's deployment_branch_policy"
    )
    assert "protected_branches" in text or "custom_branch_policies" in text, (
        "Setup script must verify the deployment branch policy type"
    )
    assert "main" in text.lower(), "Setup script must verify deployments are restricted to main"


def test_setup_script_passes_deploy_parameter_overrides_as_key_value_pairs() -> None:
    text = _SETUP_SCRIPT_PATH.read_text(encoding="utf-8")
    assert '"BedrockModelId=$modelId"' in text
    assert "ParameterKey=BedrockModelId,ParameterValue=$modelId" not in text


def test_workflow_has_concurrency_group() -> None:
    w = _workflow()
    assert "concurrency" in w, "Workflow is missing a top-level concurrency group"
    assert "group" in w["concurrency"]
    assert w["concurrency"].get("cancel-in-progress") is False


def test_workflow_preflight_checks_all_required_variables() -> None:
    w = _workflow()
    job = w["jobs"]["real-agent-validation"]
    preflight_step = next(
        (s for s in job["steps"] if "preflight" in s.get("name", "").lower()),
        None,
    )
    assert preflight_step is not None, "No preflight step found in real-agent-validation job"
    run_script = preflight_step.get("run", "")
    assert "AWS_ROLE_ARN" in run_script
    assert "AWS_REGION" in run_script
    assert "BEDROCK_MODEL_ID" in run_script
    assert "DUSK_GATE_API_KEY" in run_script
    assert "exit 1" in run_script


def test_cleanup_step_runs_always() -> None:
    w = _workflow()
    job = w["jobs"]["real-agent-validation"]
    cleanup_step = next(
        (
            s
            for s in job["steps"]
            if "stop" in s.get("name", "").lower()
            or (
                "docker compose" in s.get("run", "")
                and "down" in s.get("run", "")
                and "remove-orphans" in s.get("run", "")
            )
        ),
        None,
    )
    assert cleanup_step is not None, "No cleanup/stop containers step found"
    assert cleanup_step.get("if") == "always()"


def test_cleanup_step_receives_compose_required_gate_key() -> None:
    w = _workflow()
    cleanup_step = next(
        step
        for step in w["jobs"]["real-agent-validation"]["steps"]
        if "stop" in step.get("name", "").lower()
    )
    assert cleanup_step["env"]["DUSK_GATE_API_KEY"] == "${{ secrets.DUSK_GATE_API_KEY }}"


def test_evidence_upload_runs_always_with_30_day_retention() -> None:
    w = _workflow()
    job = w["jobs"]["real-agent-validation"]
    upload_step = next(
        (s for s in job["steps"] if s.get("uses", "").startswith("actions/upload-artifact")),
        None,
    )
    assert upload_step is not None, "No upload-artifact step found"
    assert upload_step.get("if") == "always()"
    assert upload_step["with"]["retention-days"] == 30


def test_workflow_has_caller_identity_step() -> None:
    w = _workflow()
    job = w["jobs"]["real-agent-validation"]
    identity_step = next(
        (
            s
            for s in job["steps"]
            if "identity" in s.get("name", "").lower() or "get-caller-identity" in s.get("run", "")
        ),
        None,
    )
    assert identity_step is not None, (
        "No caller identity verification step found. "
        "Add a step that runs 'aws sts get-caller-identity' after OIDC auth."
    )


def test_mantle_workflow_does_not_use_runtime_only_model_discovery() -> None:
    text = _WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "list-inference-profiles" not in text


def test_workflow_does_not_add_aws_calls_beyond_caller_identity() -> None:
    workflow_text = _WORKFLOW_PATH.read_text(encoding="utf-8")
    assert workflow_text.count("aws ") == 1
    assert "aws sts get-caller-identity" in workflow_text


def test_list_inference_profiles_uses_wildcard_resource_only() -> None:
    """ListInferenceProfiles has no resource type in AWS service authorization."""
    t = _template()
    statements = t["Resources"]["DuskBedrockRole"]["Properties"]["Policies"][0]["PolicyDocument"][
        "Statement"
    ]

    list_statement = next(
        statement
        for statement in statements
        if "bedrock:ListInferenceProfiles"
        in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
    )
    assert list_statement["Resource"] == "*"
    assert list_statement["Action"] == "bedrock:ListInferenceProfiles"

    invoke_statement = next(
        statement
        for statement in statements
        if "bedrock:InvokeModel"
        in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
    )
    assert invoke_statement["Resource"] != "*"


def test_invoke_model_allows_profile_and_underlying_foundation_model() -> None:
    t = _template()
    statements = t["Resources"]["DuskBedrockRole"]["Properties"]["Policies"][0]["PolicyDocument"][
        "Statement"
    ]
    invoke_statement = next(
        statement for statement in statements if statement["Action"] == "bedrock:InvokeModel"
    )
    resources = [str(resource) for resource in invoke_statement["Resource"]]

    assert any("inference-profile/${BedrockModelId}" in resource for resource in resources)
    expected_foundation_resources = {
        f"arn:aws:bedrock:{region}::foundation-model/${{BedrockFoundationModelId}}"
        for region in ("us-east-1", "us-east-2", "us-west-2")
    }
    assert expected_foundation_resources <= {
        resource["Fn::Sub"]
        for resource in invoke_statement["Resource"]
        if isinstance(resource, dict) and "Fn::Sub" in resource
    }
    assert t["Parameters"]["BedrockFoundationModelId"]["Default"] == ("anthropic.claude-sonnet-4-6")
