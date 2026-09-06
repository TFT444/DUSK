"""Golden parity tests for the frozen Flask ``/v1/gate`` boundary."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask.testing import FlaskClient

from dusk import api
from dusk.config import reset_config

EXAMPLE_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = EXAMPLE_ROOT / "tests" / "fixtures" / "actions_normal.json"
GOLDEN_PATH = EXAMPLE_ROOT / "contracts" / "v1-gate-golden.json"
TRACE_IDS = tuple(f"{number:032x}" for number in range(1, 5))
FROZEN_HEADERS = ("Content-Type", "WWW-Authenticate")
FROZEN_NOW = datetime(2024, 1, 15, 12, 0, tzinfo=UTC)


class _UUIDValue:
    def __init__(self, value: str) -> None:
        self.hex = value


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz: object = None) -> datetime:
        return FROZEN_NOW if tz is not None else FROZEN_NOW.replace(tzinfo=None)


@pytest.fixture(scope="module")
def golden() -> dict[str, Any]:
    with GOLDEN_PATH.open(encoding="utf-8") as handle:
        value = json.load(handle)
    assert isinstance(value, dict)
    return value


@pytest.fixture(autouse=True)
def _isolated_gate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", str(BASELINE_PATH))
    monkeypatch.setenv("DUSK_GATE_BASELINE_SOURCE", "generic")
    monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", "true")
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(tmp_path / "offenses.json"))
    for name in (
        "DUSK_ENFORCE",
        "DUSK_GATE_API_KEY",
        "DUSK_SIE_ENDPOINT",
        "SIE_API_KEY",
        "DUSK_N8N_ALERT_URL",
        "DUSK_N8N_REPORT_URL",
        "DUSK_N8N_DECISION_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()
    api.app.config["TESTING"] = True
    yield
    gate = api._gate_engine
    if gate is not None and gate.offense_memory is not None:
        gate.offense_memory.close()
    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()


@pytest.fixture
def client() -> FlaskClient:
    with api.app.test_client() as test_client:
        return test_client


def _action_payload(
    *, agent_id: str = "netops-agent", target: str = "fw-corp-https"
) -> dict[str, Any]:
    return {
        "agent_id": agent_id,
        "timestamp": "2023-11-14T22:20:00+00:00",
        "action_type": "firewall_rule_change",
        "target": target,
        "change": {"before": None, "after": {"port": 443}},
        "source": "generic",
        "raw_ref": "evt-test-1",
    }


def _refused_payload() -> dict[str, Any]:
    payload = _action_payload(agent_id="ghost-agent", target="fw-restricted")
    payload["change"] = {"before": None, "after": None}
    return payload


def _snapshot(response: Any) -> dict[str, Any]:  # noqa: ANN401
    headers = {name: response.headers[name] for name in FROZEN_HEADERS if name in response.headers}
    snapshot: dict[str, Any] = {"status": response.status_code, "headers": headers}
    if response.is_json:
        body = response.get_json()
        snapshot["body"] = json.loads(
            json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        )
    else:
        snapshot["body_text"] = response.get_data(as_text=True)
    return snapshot


def _assert_golden(response: Any, name: str, golden: dict[str, Any]) -> None:  # noqa: ANN401
    assert _snapshot(response) == golden["responses"][name]


def _reset_runtime() -> None:
    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()


@pytest.mark.parametrize(
    ("name", "mutation"),
    (
        ("missing_timestamp", lambda payload: {"agent_id": payload["agent_id"]}),
        ("empty_agent_id", lambda payload: {**payload, "agent_id": " "}),
        ("empty_target", lambda payload: {**payload, "target": ""}),
        ("naive_timestamp", lambda payload: {**payload, "timestamp": "2023-11-14T22:20:00"}),
        ("unknown_action_type", lambda payload: {**payload, "action_type": "delete_everything"}),
        ("change_not_object", lambda payload: {**payload, "change": []}),
        ("missing_source", lambda payload: {k: v for k, v in payload.items() if k != "source"}),
    ),
)
def test_validation_failures_match_golden(
    client: FlaskClient,
    golden: dict[str, Any],
    name: str,
    mutation: Any,  # noqa: ANN401
) -> None:
    _assert_golden(client.post("/v1/gate", json=mutation(_action_payload())), name, golden)


def test_non_object_request_failures_match_golden(
    client: FlaskClient, golden: dict[str, Any]
) -> None:
    invalid = client.post("/v1/gate", data="not json", content_type="application/json")
    _assert_golden(invalid, "invalid_json", golden)
    _reset_runtime()
    _assert_golden(client.post("/v1/gate", json=["not", "an", "object"]), "non_object_json", golden)


@pytest.mark.parametrize(
    ("case", "payload", "enforce"),
    (
        ("allow", _action_payload(), False),
        ("watch_refusal", _refused_payload(), False),
        ("enforce_refusal", _refused_payload(), True),
    ),
)
def test_verdict_responses_match_golden(
    client: FlaskClient,
    golden: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    payload: dict[str, Any],
    enforce: bool,
) -> None:
    if enforce:
        monkeypatch.setenv("DUSK_ENFORCE", "true")
        _reset_runtime()
    with patch("dusk.actions.verdict.uuid.uuid4", return_value=_UUIDValue(TRACE_IDS[0])):
        response = client.post("/v1/gate", json=payload)
    _assert_golden(response, case, golden)


def test_authentication_paths_match_golden(
    client: FlaskClient, golden: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DUSK_GATE_ALLOW_ANONYMOUS")
    _assert_golden(client.post("/v1/gate", json=_action_payload()), "anonymous_denied", golden)
    monkeypatch.setenv("DUSK_GATE_API_KEY", "golden-secret")
    for case, authorization in (
        ("wrong_bearer_scheme", "Basic golden-secret"),
        ("wrong_bearer_token", "Bearer wrong-secret"),
    ):
        _assert_golden(
            client.post(
                "/v1/gate", json=_action_payload(), headers={"Authorization": authorization}
            ),
            case,
            golden,
        )
    with patch("dusk.actions.verdict.uuid.uuid4", return_value=_UUIDValue(TRACE_IDS[0])):
        accepted = client.post(
            "/v1/gate",
            json=_action_payload(),
            headers={"Authorization": "Bearer golden-secret"},
        )
    _assert_golden(accepted, "allow", golden)


def test_framework_failure_paths_match_golden(client: FlaskClient, golden: dict[str, Any]) -> None:
    _assert_golden(client.get("/v1/gate"), "method_not_allowed", golden)
    oversized = client.post(
        "/v1/gate", data="x" * (2 * 1024 * 1024), content_type="application/json"
    )
    _assert_golden(oversized, "oversized_body", golden)


def test_health_paths_match_golden(
    client: FlaskClient,
    golden: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _assert_golden(client.get("/health"), "health_ok", golden)
    monkeypatch.delenv("DUSK_GATE_BASELINE_PATH")
    _reset_runtime()
    _assert_golden(client.get("/health"), "health_without_baseline", golden)
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", "/does/not/exist.json")
    _reset_runtime()
    _assert_golden(client.get("/health"), "health_baseline_degraded", golden)

    blocker = tmp_path / "not-a-directory"
    blocker.write_text("blocking file", encoding="utf-8")
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", str(BASELINE_PATH))
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(blocker / "offenses.json"))
    _reset_runtime()
    with patch("dusk.actions.verdict.uuid.uuid4", return_value=_UUIDValue(TRACE_IDS[0])):
        client.post("/v1/gate", json=_refused_payload())
    api._get_gate_engine().offense_memory.flush()
    _assert_golden(client.get("/health"), "health_offense_memory_degraded", golden)


@pytest.mark.parametrize(
    ("case", "payload", "enforce"),
    (
        ("allow", _action_payload(), False),
        ("watch_refusal", _refused_payload(), False),
        ("enforce_refusal", _refused_payload(), True),
    ),
)
def test_public_side_effects_match_golden(
    client: FlaskClient,
    golden: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    payload: dict[str, Any],
    enforce: bool,
) -> None:
    if enforce:
        monkeypatch.setenv("DUSK_ENFORCE", "true")
        _reset_runtime()
    with (
        patch("dusk.actions.verdict.uuid.uuid4", return_value=_UUIDValue(TRACE_IDS[0])),
        patch("dusk.trace.n8n_client.fire_decision") as decision,
        patch("dusk.trace.n8n_client.fire_report") as report,
        patch("dusk.trace.n8n_client.fire_alert") as alert,
    ):
        response = client.post("/v1/gate", json=payload)

    body = response.get_json()
    calls = sorted(
        name
        for name, mock in (("alert", alert), ("decision", decision), ("report", report))
        if mock.call_count
    )
    engine = api._get_gate_engine()
    actual = {
        "webhooks": calls,
        "offense_records": len(engine.offense_memory.offenses_for(payload["agent_id"])),
        "decision_records": len(api._decision_history),
    }
    assert actual == golden["side_effects"][case]
    webhook_payload = {
        **body,
        "agent_id": payload["agent_id"],
        "action_type": payload["action_type"],
        "target": payload["target"],
    }
    decision.assert_called_once_with(webhook_payload)
    report.assert_called_once_with(webhook_payload)
    if case == "allow":
        alert.assert_not_called()
    else:
        alert.assert_called_once_with(webhook_payload)


@pytest.mark.parametrize(
    ("case", "unauthorized"),
    (("invalid_request", False), ("unauthorized_request", True)),
)
def test_rejected_requests_have_no_side_effects(
    client: FlaskClient,
    golden: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    unauthorized: bool,
) -> None:
    if unauthorized:
        monkeypatch.delenv("DUSK_GATE_ALLOW_ANONYMOUS")
    payload = _action_payload() if unauthorized else {"agent_id": "netops-agent"}
    with (
        patch("dusk.trace.n8n_client.fire_decision") as decision,
        patch("dusk.trace.n8n_client.fire_report") as report,
        patch("dusk.trace.n8n_client.fire_alert") as alert,
    ):
        client.post("/v1/gate", json=payload)
    engine = api._gate_engine
    offense_count = (
        len(engine.offense_memory.offenses_for("netops-agent")) if engine is not None else 0
    )
    assert {
        "webhooks": [],
        "offense_records": offense_count,
        "decision_records": len(api._decision_history),
    } == golden["side_effects"][case]
    decision.assert_not_called()
    report.assert_not_called()
    alert.assert_not_called()


def test_similar_decision_references_match_golden(
    client: FlaskClient, golden: dict[str, Any]
) -> None:
    values = iter(_UUIDValue(value) for value in TRACE_IDS)
    with patch("dusk.actions.verdict.uuid.uuid4", side_effect=lambda: next(values)):
        client.post("/v1/gate", json=_action_payload())
        client.post("/v1/gate", json=_action_payload())
        third = client.post("/v1/gate", json=_action_payload())
    _assert_golden(third, "similar_decision_third_response", golden)


def test_repeat_offense_persistence_and_scoring_match_golden(
    client: FlaskClient, golden: dict[str, Any]
) -> None:
    values = iter(_UUIDValue(value) for value in TRACE_IDS)
    with (
        patch("dusk.actions.verdict.uuid.uuid4", side_effect=lambda: next(values)),
        patch("dusk.actions.offense_memory.datetime", _FrozenDateTime),
        patch("dusk.actions.analyse.datetime", _FrozenDateTime),
    ):
        first = client.post("/v1/gate", json=_refused_payload())
        _assert_golden(first, "watch_refusal", golden)
        api._get_gate_engine().offense_memory.flush()
        api.reset_gate_engine()
        after_restart = client.post("/v1/gate", json=_refused_payload())
    _assert_golden(after_restart, "repeat_refusal_after_restart", golden)


def test_sie_unavailability_preserves_deterministic_golden(
    client: FlaskClient, golden: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DUSK_SIE_ENDPOINT", "https://unavailable.invalid")
    _reset_runtime()
    with (
        patch("dusk.trace.vector._sie_client", return_value=None),
        patch("dusk.actions.verdict.uuid.uuid4", return_value=_UUIDValue(TRACE_IDS[0])),
    ):
        response = client.post("/v1/gate", json=_action_payload())
    _assert_golden(response, "allow", golden)


def _mock_response(payload: dict[str, Any]) -> MagicMock:
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


@pytest.mark.parametrize("verdict", ("ALLOW", "WOULD-BLOCK", "BLOCK"))
def test_downstream_execution_boundary_matches_golden(
    golden: dict[str, Any], monkeypatch: pytest.MonkeyPatch, verdict: str
) -> None:
    monkeypatch.syspath_prepend(str(EXAMPLE_ROOT / "runtime"))
    sys.modules.pop("harness", None)
    import harness

    gate = _mock_response(
        {
            "trace_id": TRACE_IDS[0],
            "verdict": verdict,
            "score": 0.85 if verdict != "ALLOW" else 0.0,
            "blast": "high" if verdict != "ALLOW" else "medium",
            "reasons": ["golden refusal"] if verdict != "ALLOW" else [],
        }
    )
    responses = [gate]
    if verdict != "BLOCK":
        responses.append(_mock_response({"status": "applied"}))
    with patch("harness.requests.post", side_effect=responses) as post:
        result = harness.run_scenario("golden-agent", "clean")
    calls = ["gate"] + (["downstream"] if post.call_count == 2 else [])
    assert calls == golden["downstream_execution"][verdict]
    assert result["applied"] is (verdict != "BLOCK")
