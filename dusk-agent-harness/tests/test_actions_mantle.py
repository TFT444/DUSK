"""Tests for the Mantle adapter shipped by the standalone example package."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from dusk.actions.adapters.base import AdapterError
from dusk.actions.adapters.mantle import MantleAdapter


def _function_call(**overrides: object) -> dict[str, object]:
    call: dict[str, object] = {
        "id": "call-1",
        "name": "update_firewall_rule",
        "arguments_json": json.dumps(
            {"target": "fw-1", "before": None, "after": {"cidr": "0.0.0.0/0"}}
        ),
    }
    call.update(overrides)
    return call


def test_mantle_adapter_is_available_in_example_package() -> None:
    action = MantleAdapter().parse_function_call(
        _function_call(), agent_id="agent-1", timestamp=datetime(2026, 8, 27, tzinfo=UTC)
    )
    assert action.source == "mantle"
    assert action.action_type == "firewall_rule_change"
    assert action.target == "fw-1"


def test_mantle_adapter_rejects_unapproved_tools() -> None:
    with pytest.raises(AdapterError, match="not a permitted DUSK tool"):
        MantleAdapter().parse_function_call(
            _function_call(name="run_shell"),
            agent_id="agent-1",
            timestamp=datetime(2026, 8, 27, tzinfo=UTC),
        )
