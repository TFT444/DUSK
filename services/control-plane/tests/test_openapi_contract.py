"""Committed OpenAPI artifact parity test."""

from __future__ import annotations

import json
from pathlib import Path

from dusk_control_plane.openapi import render_openapi


def test_committed_openapi_matches_application() -> None:
    contract = Path(__file__).resolve().parents[1] / "contracts" / "openapi.json"
    assert contract.read_text(encoding="utf-8") == render_openapi()


def test_v2_evaluation_contract_is_authenticated_and_has_no_tenant_input() -> None:
    schema = json.loads(render_openapi())
    operation = schema["paths"]["/v2/evaluations"]["post"]
    assert operation["security"] == [{"HTTPBearer": []}]
    request_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    request_name = request_ref.rsplit("/", 1)[1]
    request_schema = schema["components"]["schemas"][request_name]
    assert "tenant_id" not in request_schema["properties"]
    assert "principal_id" not in request_schema["properties"]
    response_ref = operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
    response_name = response_ref.rsplit("/", 1)[1]
    response_fields = schema["components"]["schemas"][response_name]["properties"]
    assert {
        "policy_decision",
        "policy_pack_version",
        "matched_rules",
        "evidence_degraded",
        "reason_codes",
    } <= set(response_fields)


def test_decision_read_contract_is_authenticated_bounded_and_tenant_free() -> None:
    schema = json.loads(render_openapi())
    list_operation = schema["paths"]["/v2/decisions"]["get"]
    detail_operation = schema["paths"]["/v2/decisions/{trace_id}"]["get"]
    assert list_operation["security"] == [{"HTTPBearer": []}]
    assert detail_operation["security"] == [{"HTTPBearer": []}]
    parameters = {value["name"]: value for value in list_operation["parameters"]}
    assert set(parameters) == {
        "limit",
        "cursor",
        "created_from",
        "created_to",
        "verdict",
        "policy_decision",
        "response_status",
        "evidence_degraded",
        "agent_id",
        "action_type",
        "search",
    }
    assert parameters["limit"]["schema"]["maximum"] == 100
    assert parameters["cursor"]["schema"]["anyOf"][0]["maxLength"] == 2048
    assert "tenant_id" not in parameters
    assert "principal_id" not in parameters
    detail_response = detail_operation["responses"]["200"]["content"]["application/json"]
    detail_name = detail_response["schema"]["$ref"].rsplit("/", 1)[1]
    detail_fields = schema["components"]["schemas"][detail_name]["properties"]
    assert {
        "action",
        "input_digest",
        "policy_matches",
        "evidence_state",
        "pipeline_timings",
        "audit",
        "similar_decisions",
        "detail_available",
    } <= set(detail_fields)


def test_dashboard_and_agent_contract_is_authenticated_bounded_and_tenant_free() -> None:
    schema = json.loads(render_openapi())
    paths = schema["paths"]
    for path in (
        "/v2/dashboard/summary",
        "/v2/dashboard/decision-volume",
        "/v2/dashboard/action-breakdown",
        "/v2/agents/risk",
        "/v2/agents/{agent_id}",
    ):
        operation = paths[path]["get"]
        assert operation["security"] == [{"HTTPBearer": []}]
        parameters = {parameter["name"]: parameter for parameter in operation["parameters"]}
        assert "tenant_id" not in parameters
        assert "principal_id" not in parameters
    risk_parameters = {
        parameter["name"]: parameter for parameter in paths["/v2/agents/risk"]["get"]["parameters"]
    }
    assert set(risk_parameters) == {"window", "limit", "cursor", "minimum_risk_score"}
    assert risk_parameters["limit"]["schema"]["maximum"] == 100
    assert risk_parameters["cursor"]["schema"]["anyOf"][0]["maxLength"] == 2048

    response = paths["/v2/dashboard/summary"]["get"]["responses"]["200"]
    model_name = response["content"]["application/json"]["schema"]["$ref"].rsplit("/", 1)[1]
    fields = schema["components"]["schemas"][model_name]["properties"]
    assert {"window_start", "window_end", "comparison_start", "timezone", "freshness"} <= set(
        fields
    )
