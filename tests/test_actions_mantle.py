"""Tests for the Mantle (OpenAI-format) tool-call adapter."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from dusk.actions.adapters.base import AdapterError
from dusk.actions.adapters.mantle import MantleAdapter


def _function_call(**overrides: object) -> dict[str, object]:
    """Build a sample OpenAI-format function call proposing a firewall change."""
    base: dict[str, object] = {
        "id": "call_abc123",
        "name": "update_firewall_rule",
        "arguments_json": json.dumps(
            {
                "target": "fw-corp-restricted-segment",
                "before": None,
                "after": {"port": 22, "cidr": "0.0.0.0/0"},
            }
        ),
    }
    base.update(overrides)
    return base


def test_firewall_function_name_maps_to_firewall_rule_change() -> None:
    action = MantleAdapter().parse_function_call(
        _function_call(),
        agent_id="ops-agent-1",
        timestamp=datetime(2026, 7, 10, tzinfo=UTC),
    )
    assert action.action_type == "firewall_rule_change"
    assert action.agent_id == "ops-agent-1"
    assert action.target == "fw-corp-restricted-segment"
    assert action.source == "mantle"
    assert action.raw_ref == "call_abc123"
    assert action.change["after"] == {"port": 22, "cidr": "0.0.0.0/0"}
    assert action.timestamp.tzinfo is not None


def test_route_function_name_maps_to_route_change() -> None:
    fc = _function_call(
        name="update_route_table",
        arguments_json=json.dumps({"target": "rt-1"}),
    )
    action = MantleAdapter().parse_function_call(
        fc, agent_id="ops-agent-1", timestamp=datetime(2026, 7, 10, tzinfo=UTC)
    )
    assert action.action_type == "route_change"


def test_mantle_adapter_parses_valid_function_call() -> None:
    fc = _function_call(
        name="assign_role",
        arguments_json=json.dumps(
            {"target": "ra-owner-self", "before": None, "after": {"role": "owner"}}
        ),
    )
    action = MantleAdapter().parse_function_call(
        fc, agent_id="agent-x", timestamp=datetime(2026, 7, 10, tzinfo=UTC)
    )
    assert action.action_type == "role_assignment"
    assert action.target == "ra-owner-self"


def test_mantle_adapter_raises_on_malformed_json() -> None:
    fc = _function_call(arguments_json="{not valid json")
    with pytest.raises(AdapterError, match="JSON"):
        MantleAdapter().parse_function_call(
            fc, agent_id="agent-x", timestamp=datetime(2026, 7, 10, tzinfo=UTC)
        )


def test_mantle_adapter_raises_on_missing_target() -> None:
    fc = _function_call(arguments_json=json.dumps({"before": None, "after": {}}))
    with pytest.raises(AdapterError, match="target"):
        MantleAdapter().parse_function_call(
            fc, agent_id="agent-x", timestamp=datetime(2026, 7, 10, tzinfo=UTC)
        )


def test_mantle_adapter_raises_on_unexpected_tool() -> None:
    fc = _function_call(
        name="get_weather",
        arguments_json=json.dumps({"target": "n/a"}),
    )
    with pytest.raises(AdapterError, match="tool"):
        MantleAdapter().parse_function_call(
            fc, agent_id="agent-x", timestamp=datetime(2026, 7, 10, tzinfo=UTC)
        )


def test_mantle_adapter_no_auth_header_in_error_messages() -> None:
    """No error path should surface a bearer token or Authorization header."""
    fc = _function_call(arguments_json="{bad")
    try:
        MantleAdapter().parse_function_call(
            fc, agent_id="agent-x", timestamp=datetime(2026, 7, 10, tzinfo=UTC)
        )
    except AdapterError as exc:
        message = str(exc).lower()
        assert "authorization" not in message
        assert "bearer" not in message


def test_parse_satisfies_source_adapter_contract() -> None:
    raw = {
        "function_call": _function_call(),
        "agent_id": "ops-agent-1",
        "timestamp": "2026-07-10T00:00:00+00:00",
    }
    action = MantleAdapter().parse(raw)
    assert action.action_type == "firewall_rule_change"
    assert action.agent_id == "ops-agent-1"


def test_parse_missing_function_call_raises() -> None:
    with pytest.raises(AdapterError, match="function_call"):
        MantleAdapter().parse({"agent_id": "a", "timestamp": "2026-07-10T00:00:00+00:00"})
