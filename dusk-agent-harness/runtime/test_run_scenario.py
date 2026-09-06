"""Contract tests for the OWASP demo result validator."""

from __future__ import annotations

import pytest
from run_scenario import _result_matches_mode


@pytest.mark.parametrize(
    ("mode", "scenario", "verdict", "applied"),
    [
        ("watch", "clean", "ALLOW", True),
        ("watch", "poisoned", "WOULD-BLOCK", True),
        ("enforce", "clean", "ALLOW", True),
        ("enforce", "poisoned", "BLOCK", False),
    ],
)
def test_expected_demo_results_match(mode: str, scenario: str, verdict: str, applied: bool) -> None:
    result: dict[str, object] = {"verdict": verdict, "applied": applied}

    assert _result_matches_mode(scenario, result, mode)


@pytest.mark.parametrize(
    ("mode", "scenario", "result"),
    [
        ("watch", "clean", {"verdict": "BLOCK", "applied": False}),
        ("watch", "poisoned", {"verdict": "WOULD-BLOCK", "applied": False}),
        ("enforce", "clean", {"verdict": "ALLOW", "applied": False}),
        ("enforce", "poisoned", {"verdict": "ALLOW", "applied": True}),
    ],
)
def test_unexpected_demo_results_fail(mode: str, scenario: str, result: dict[str, object]) -> None:
    assert not _result_matches_mode(scenario, result, mode)
