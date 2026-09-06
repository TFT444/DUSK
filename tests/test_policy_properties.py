"""Property checks for fail-closed enterprise policy invariants."""

from __future__ import annotations

import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from dusk.policies import Decision, EvidenceState, PolicyPack, load_enterprise_pack


@pytest.fixture(scope="module")
def policy_pack() -> PolicyPack:
    """Load the shared policy once, outside each generated evaluation."""
    return load_enterprise_pack()


@given(st.text(alphabet=string.ascii_letters, min_size=1).map(lambda key: f"invalid_{key}"))
def test_unknown_context_domains_are_always_rejected(policy_pack: PolicyPack, key: str) -> None:
    """Arbitrary undeclared context domains cannot bypass schema validation."""
    with pytest.raises(ValueError, match="unknown context domain"):
        policy_pack.evaluate({key: {}})


@given(st.sampled_from([EvidenceState.UNKNOWN, EvidenceState.STALE, EvidenceState.CONFLICTED]))
def test_degraded_evidence_always_denies_consequential_actions(
    policy_pack: PolicyPack, state: EvidenceState
) -> None:
    """Every unsafe evidence state fails closed for a consequential action."""
    result = policy_pack.evaluate(
        {
            "action": {
                "type": "role_assignment",
                "consequential": True,
                "_evidence": state,
            }
        }
    )
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True
