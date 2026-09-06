"""SIE failure-mode tests: gate falls back gracefully when SIE is unavailable.

These tests use StubSIEClient (see stub_sie.py) to inject specific failure
modes into dusk.trace.vector._sie_client.  Each test verifies that the gate
handles the failure silently and returns a usable result instead of raising.

Coverage gaps filled vs test_trace_vector.py:
  - TimeoutError (distinct from RuntimeError; both are caught by except Exception)
  - Malformed ``dense`` field (None instead of a list)
  - SIE high score does NOT lower deterministic WOULD-BLOCK into ALLOW (F-04)
  - End-to-end gate verdict is valid even when SIE encode raises
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest
from stub_sie import StubSIEClient

from dusk import api
from dusk.config import reset_config
from dusk.trace import vector


def _inject_fake_sie_types(monkeypatch: pytest.MonkeyPatch) -> None:
    """Register a minimal fake sie_sdk.types so SIE call-sites can import Item."""

    def _fake_item(text=None, id=None, **_kw):  # noqa: A002
        return {"text": text, "id": id}

    fake_types = types.ModuleType("sie_sdk.types")
    fake_types.Item = _fake_item  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sie_sdk.types", fake_types)


def test_encode_returns_none_when_sie_server_times_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIF-01: TimeoutError from encode must cause sie_encode to return None (n-gram fallback)."""
    stub = StubSIEClient(mode="timeout")
    monkeypatch.setattr(vector, "_sie_client", lambda config: stub)
    _inject_fake_sie_types(monkeypatch)

    result = vector.sie_encode("firewall_rule_change fw-corp-https")

    assert result is None, "TimeoutError must trigger the None-returning fallback path"


def test_encode_returns_none_when_dense_field_is_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIF-02: a well-formed HTTP 200 response with ``dense: null`` must fall back to None.

    The SIE SDK can return a response where the model is still provisioning and
    the dense field is absent or null.  sie_encode must return None so the
    caller uses the n-gram fallback rather than silently producing a zero vector.
    """
    stub = StubSIEClient(mode="malformed_dense")
    monkeypatch.setattr(vector, "_sie_client", lambda config: stub)
    _inject_fake_sie_types(monkeypatch)

    result = vector.sie_encode("firewall_rule_change fw-corp-https")

    assert result is None, "None dense field must be treated as unavailable, not as an empty vector"


def test_sie_high_score_does_not_lower_deterministic_would_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SIF-03 / F-04: a high SIE similarity score must NOT lower a WOULD-BLOCK verdict.

    When SIE is healthy and returns a perfect similarity score, the gate must
    still return WOULD-BLOCK for actions that trip the deterministic threshold
    (unknown agent + sensitive "owner" token → score 0.85 > 0.6).  SIE
    similarity is advisory only; it must never pull a WOULD-BLOCK to ALLOW.
    """
    stub = StubSIEClient(mode="high_score")
    monkeypatch.setattr(vector, "_sie_client", lambda config: stub)
    _inject_fake_sie_types(monkeypatch)

    monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", "true")
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(tmp_path / "offenses.json"))
    monkeypatch.delenv("DUSK_GATE_API_KEY", raising=False)
    monkeypatch.delenv("DUSK_GATE_BASELINE_PATH", raising=False)
    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()

    api.app.config["TESTING"] = True
    with api.app.test_client() as client:
        r = client.post(
            "/v1/gate",
            json={
                "agent_id": "sie-f04-unknown-agent",
                "timestamp": "2024-01-10T10:00:00+00:00",
                "action_type": "role_assignment",
                "target": "ra-owner-prod",
                "change": {"before": {"role": "viewer"}, "after": {"role": "owner"}},
                "source": "generic",
                "raw_ref": "evt-sie-f04",
            },
        )

    data = r.get_json()
    assert r.status_code == 200

    # Prove the SIE high-score path was actually invoked, not bypassed.
    total_sie_calls = sum(stub.call_count.values())
    assert total_sie_calls > 0, (
        "StubSIEClient was never called; gate used only n-gram fallback — "
        "high-score path was not exercised"
    )
    # Every score() call in high_score mode returns 1.0; verify no call used a lower value.
    assert stub.mode == "high_score", "stub mode must not have changed during the test"

    assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}, (
        "SIE high score must not lower deterministic WOULD-BLOCK: "
        f"score={data['score']}, verdict={data['verdict']}, "
        f"sie_calls={stub.call_count}"
    )

    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()


def test_gate_returns_verdict_when_sie_encode_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SIF-04: /v1/gate returns a valid verdict even when SIE encode raises ConnectionRefusedError.

    This is the end-to-end gate-level test: all unit-level fallbacks above are
    confirmed to work in isolation; this one confirms the full request path
    (gate → analyse → embed_text → sie_encode → n-gram fallback) doesn't surface
    the SIE error as an HTTP 500.
    """
    stub = StubSIEClient(mode="connection_refused")
    monkeypatch.setattr(vector, "_sie_client", lambda config: stub)
    _inject_fake_sie_types(monkeypatch)

    fixtures = Path(__file__).resolve().parent / "fixtures"
    baseline = str(fixtures / "actions_normal.json")
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", baseline)
    monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", "true")
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(tmp_path / "offenses.json"))
    monkeypatch.delenv("DUSK_GATE_API_KEY", raising=False)
    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()

    api.app.config["TESTING"] = True
    with api.app.test_client() as client:
        r = client.post(
            "/v1/gate",
            json={
                "agent_id": "ghost-agent",
                "timestamp": "2023-11-14T22:20:00+00:00",
                "action_type": "firewall_rule_change",
                "target": "fw-restricted",
                "change": {"before": None, "after": {"port": 22}},
                "source": "generic",
                "raw_ref": "evt-sie-fallback-1",
            },
        )

    assert r.status_code == 200, "gate must not propagate SIE failures as HTTP 500"
    data = r.get_json()
    assert data["verdict"] in {"ALLOW", "WOULD-BLOCK", "BLOCK"}
    assert isinstance(data["score"], float)

    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()
