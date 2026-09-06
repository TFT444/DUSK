"""Legacy adapter parity and shadow-isolation tests."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from dusk import api
from dusk.actions.event import AgentAction
from dusk.application.evaluator import EvaluationMode, EvaluationPrincipal


def test_harness_evaluator_matches_the_canonical_package_source() -> None:
    repository = Path(__file__).resolve().parents[2]
    canonical = repository / "src/dusk/application/evaluator.py"
    harness = repository / "dusk-agent-harness/src/dusk/application/evaluator.py"
    assert harness.read_bytes() == canonical.read_bytes()


def test_legacy_shadow_evaluation_is_observational_only() -> None:
    api.reset_gate_engine()
    api.reset_decision_history()
    action = AgentAction.from_dict(
        {
            "agent_id": "ghost-agent",
            "timestamp": "2026-08-31T12:00:00+00:00",
            "action_type": "role_assignment",
            "target": "role-owner-self",
            "change": {"before": None, "after": {"role": "owner"}},
            "source": "generic",
        }
    )
    engine = api._get_gate_engine()
    before_offenses = engine.offense_memory.offenses_for(action.agent_id)
    before_decisions = list(api._decision_history)

    with (
        patch("dusk.trace.n8n_client.fire_decision") as decision,
        patch("dusk.trace.n8n_client.fire_report") as report,
        patch("dusk.trace.n8n_client.fire_alert") as alert,
    ):
        output = api._build_canonical_evaluator().evaluate(
            action,
            EvaluationPrincipal("legacy-v1", "shadow-validator", "legacy-workload"),
            mode=EvaluationMode.SHADOW,
        )

    assert output.response["verdict"] == "WOULD-BLOCK"
    assert engine.offense_memory.offenses_for(action.agent_id) == before_offenses
    assert api._decision_history == before_decisions
    decision.assert_not_called()
    report.assert_not_called()
    alert.assert_not_called()
    api.reset_gate_engine()
    api.reset_decision_history()
