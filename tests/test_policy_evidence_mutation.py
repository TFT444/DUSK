"""Direct boundary tests for fail-closed policy evidence classification."""

from __future__ import annotations

import pytest

from dusk.policies.evidence import EvidenceState, classify_evidence


def test_evidence_state_wire_values_are_stable() -> None:
    assert EvidenceState.CONFIRMED.value == "CONFIRMED"
    assert EvidenceState.UNKNOWN.value == "UNKNOWN"
    assert EvidenceState.STALE.value == "STALE"
    assert EvidenceState.CONFLICTED.value == "CONFLICTED"
    assert EvidenceState.NOT_APPLICABLE.value == "NOT_APPLICABLE"


@pytest.mark.parametrize("classification", [True, None, "false", 0, 1])
def test_only_boolean_false_marks_an_action_non_consequential(classification: object) -> None:
    consequential, _ = classify_evidence(
        {"action": {"consequential": classification, "_evidence": "CONFIRMED"}}
    )
    assert consequential is True


def test_explicit_boolean_false_is_non_consequential() -> None:
    assert classify_evidence({"action": {"consequential": False}}) == (False, False)


@pytest.mark.parametrize("state", ["UNKNOWN", "STALE", "CONFLICTED", "invalid", 1])
def test_untrusted_evidence_is_degraded_for_consequential_actions(state: object) -> None:
    assert classify_evidence(
        {
            "action": {"consequential": True, "_evidence": "CONFIRMED"},
            "permit": {"_evidence": state},
        }
    ) == (True, True)


@pytest.mark.parametrize("state", ["CONFIRMED", "NOT_APPLICABLE", EvidenceState.CONFIRMED])
def test_trusted_evidence_is_not_degraded(state: object) -> None:
    assert classify_evidence(
        {
            "action": {"consequential": True, "_evidence": "CONFIRMED"},
            "permit": {"_evidence": state},
        }
    ) == (True, False)


def test_missing_evidence_fails_closed_only_for_consequential_actions() -> None:
    assert classify_evidence({"action": {"consequential": True}}) == (True, True)
    assert classify_evidence({"action": {"consequential": False}}) == (False, False)


def test_non_mapping_action_is_not_consequential_or_degraded() -> None:
    assert classify_evidence({"action": "invalid"}) == (False, False)


def test_any_degraded_domain_degrades_the_whole_context() -> None:
    assert classify_evidence(
        {
            "action": {"consequential": False, "_evidence": "CONFIRMED"},
            "identity": {"_evidence": "UNKNOWN"},
            "scalar": "ignored",
        }
    ) == (False, True)
