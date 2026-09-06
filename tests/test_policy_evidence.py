"""Behavioral tests for evidence states, fail-closed evaluation, rule lifecycle,
context schema validation, and redacted audit evidence (issue #144).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from dusk.policies import Decision, load_enterprise_pack
from dusk.policies.engine import EvidenceState, PolicyResult, load_policy_pack

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pack(tmp_path: Path, raw: object) -> Path:
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def _enforced_rule(**overrides: object) -> dict[str, object]:
    """Minimal valid enforced rule. Provide overrides for the fields to change."""
    base: dict[str, object] = {
        "id": "DUSK-TEST-001",
        "version": "1.0.0",
        "title": "Test rule",
        "category": "test",
        "severity": "low",
        "decision": "DENY",
        "status": "enforced",
        "owner": "DUSK Security",
        "rationale": "Test rationale.",
        "frameworks": ["TEST"],
        "match": [{"field": "action.type", "operator": "equals", "value": "test.trigger"}],
        "prerequisites": [],
        "tests": ["allow", "deny"],
    }
    base.update(overrides)
    return base


def _pack_with_single_rule(**rule_overrides: object) -> dict[str, object]:
    return {
        "name": "test-pack",
        "version": "1.0.0",
        "default_decision": "ALLOW",
        "rules": [_enforced_rule(**rule_overrides)],
    }


# ---------------------------------------------------------------------------
# Group 1: EvidenceState enum
# ---------------------------------------------------------------------------


def test_evidence_state_has_all_required_values() -> None:
    assert EvidenceState.CONFIRMED.value == "CONFIRMED"
    assert EvidenceState.UNKNOWN.value == "UNKNOWN"
    assert EvidenceState.STALE.value == "STALE"
    assert EvidenceState.CONFLICTED.value == "CONFLICTED"
    assert EvidenceState.NOT_APPLICABLE.value == "NOT_APPLICABLE"


def test_evidence_state_from_valid_string() -> None:
    assert EvidenceState("CONFIRMED") is EvidenceState.CONFIRMED
    assert EvidenceState("UNKNOWN") is EvidenceState.UNKNOWN


def test_evidence_state_invalid_string_raises() -> None:
    with pytest.raises(ValueError):
        EvidenceState("MAYBE")


# ---------------------------------------------------------------------------
# Group 2: Fail-closed for consequential actions with degraded evidence
# ---------------------------------------------------------------------------


def test_unknown_evidence_fails_closed_on_consequential_action() -> None:
    """UNKNOWN evidence source on a consequential action must produce DENY."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "permit": {"valid": False, "_evidence": "UNKNOWN"},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_stale_evidence_fails_closed_on_consequential_action() -> None:
    """STALE evidence on a consequential action must produce DENY."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "identity": {"tenant_id": "tenant-a", "_evidence": "STALE"},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_conflicted_evidence_fails_closed_on_consequential_action() -> None:
    """CONFLICTED evidence on a consequential action must produce DENY."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "identity": {"tenant_id": "tenant-a", "_evidence": "CONFLICTED"},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_confirmed_evidence_does_not_trigger_fail_closed() -> None:
    """CONFIRMED evidence: fail-closed path must not fire even for consequential actions."""
    # Provide a fully valid permit so PERMIT-001 and CONSEQ-001 do not fire.
    context = {
        "action": {"type": "noop", "consequential": True, "_evidence": "CONFIRMED"},
        "permit": {"valid": True, "expired": False, "_evidence": "CONFIRMED"},
        "approval": {"valid": True, "_evidence": "CONFIRMED"},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.evidence_degraded is False
    assert result.decision is Decision.ALLOW


def test_not_applicable_evidence_does_not_trigger_fail_closed() -> None:
    """NOT_APPLICABLE evidence is a safe state and must not trigger fail-closed."""
    # Provide a valid permit so PERMIT-001 does not fire on the consequential action.
    context = {
        "action": {"type": "noop", "consequential": True, "_evidence": "CONFIRMED"},
        "permit": {"valid": True, "expired": False, "_evidence": "CONFIRMED"},
        "session": {"id": "sess-001", "_evidence": "NOT_APPLICABLE"},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.evidence_degraded is False
    assert result.decision is Decision.ALLOW


def test_missing_evidence_key_defaults_to_confirmed_for_non_consequential() -> None:
    """Absent _evidence on a non-consequential action is treated as CONFIRMED (backward compat)."""
    context = {
        "action": {"type": "filesystem.read", "consequential": False},
        "resource": {"within_approved_root": True, "classification": "internal"},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.evidence_degraded is False


def test_consequential_action_with_absent_evidence_defaults_to_unknown() -> None:
    """Absent _evidence on a consequential action defaults to UNKNOWN (strict mode).

    Callers that set action.consequential=True but omit _evidence metadata
    must not receive a false ALLOW.  The engine must treat the missing key
    as UNKNOWN and trigger the fail-closed DENY path.
    """
    context = {
        "action": {"consequential": True},  # _evidence deliberately absent
        "permit": {"valid": True, "expired": False},  # _evidence deliberately absent
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.evidence_degraded is True, (
        "Absent _evidence on a consequential evaluation must set evidence_degraded"
    )
    assert result.decision is Decision.DENY, (
        "Fail-closed must trigger DENY when evidence is absent on a consequential action"
    )


def test_missing_consequential_classification_fails_closed() -> None:
    """Omitting the action classification cannot select compatibility mode."""
    context = {
        "action": {"type": "noop"},
        "permit": {"valid": True, "expired": False},
        "approval": {"valid": True},
    }

    result = load_enterprise_pack().evaluate(context)

    assert result.evidence_degraded is True
    assert result.decision is Decision.DENY


def test_untrusted_consequential_classification_fails_closed() -> None:
    """Non-boolean classification values are untrusted and must fail closed."""
    context = {
        "action": {"type": "noop", "consequential": "unknown"},
        "permit": {"valid": True, "expired": False},
        "approval": {"valid": True},
    }

    result = load_enterprise_pack().evaluate(context)

    assert result.evidence_degraded is True
    assert result.decision is Decision.DENY


def test_non_consequential_action_with_unknown_evidence_is_not_failed_closed() -> None:
    """Fail-closed only triggers for consequential actions, not routine ones.

    A non-consequential read with an UNKNOWN permit should flag degraded
    evidence but must NOT force DENY via the fail-closed path.  Normal rule
    matching still applies; this context is designed to avoid triggering any
    enforced rules so the ALLOW default is observable.
    """
    context = {
        # non-consequential filesystem read with a confirmed, in-root resource
        "action": {"type": "filesystem.read", "consequential": False, "_evidence": "CONFIRMED"},
        "resource": {
            "within_approved_root": True,
            "classification": "internal",
            "_evidence": "CONFIRMED",
        },
        # permit domain exists but evidence is UNKNOWN
        "permit": {"valid": True, "expired": False, "_evidence": "UNKNOWN"},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.evidence_degraded is True, "UNKNOWN permit evidence must set evidence_degraded"
    # Not consequential: fail-closed path must not fire
    assert result.decision is Decision.ALLOW, (
        "Non-consequential action must not be force-denied by degraded evidence alone"
    )


def test_bypass_permit_with_unknown_evidence_is_denied() -> None:
    """Security bypass attempt: attacker provides favourable permit values but
    evidence source is UNKNOWN.  The engine must deny regardless of values."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "permit": {
            "valid": True,
            "expired": False,
            "replayed": False,
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY, (
        "UNKNOWN evidence must force DENY on a consequential action "
        "regardless of permit field values"
    )
    assert result.evidence_degraded is True


def test_evidence_degraded_flag_appears_in_result_dict() -> None:
    context = {
        "action": {"consequential": True},
        "permit": {"valid": False, "_evidence": "UNKNOWN"},
    }
    d = load_enterprise_pack().evaluate(context).to_dict()
    assert "evidence_degraded" in d
    assert d["evidence_degraded"] is True


def test_evidence_degraded_false_appears_in_result_dict_when_clean() -> None:
    context = {"action": {"type": "filesystem.read", "consequential": False}}
    d = load_enterprise_pack().evaluate(context).to_dict()
    assert d["evidence_degraded"] is False


# ---------------------------------------------------------------------------
# Group 3: Rule lifecycle states
# ---------------------------------------------------------------------------


def test_proposed_rule_accepted_with_empty_match_prerequisites_tests(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(
        status="proposed",
        match=[],
        prerequisites=[],
        tests=[],
    )
    pack = load_policy_pack(_write_pack(tmp_path, raw))
    assert pack.rules[0].status == "proposed"


def test_proposed_rule_does_not_fire_at_runtime(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="proposed", match=[], prerequisites=[], tests=[])
    pack = load_policy_pack(_write_pack(tmp_path, raw))
    result = pack.evaluate({"action": {"type": "test.trigger", "consequential": False}})
    assert all(r.id != "DUSK-TEST-001" for r in result.matched_rules)
    assert result.decision is Decision.ALLOW


def test_implemented_rule_requires_conditions(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="implemented", match=[], prerequisites=[], tests=[])
    with pytest.raises(ValueError, match="implemented"):
        load_policy_pack(_write_pack(tmp_path, raw))


def test_implemented_rule_does_not_require_tests(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="implemented", tests=[], prerequisites=[])
    pack = load_policy_pack(_write_pack(tmp_path, raw))
    assert pack.rules[0].status == "implemented"


def test_implemented_rule_does_not_fire_at_runtime(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="implemented", tests=[], prerequisites=[])
    pack = load_policy_pack(_write_pack(tmp_path, raw))
    result = pack.evaluate({"action": {"type": "test.trigger", "consequential": False}})
    assert all(r.id != "DUSK-TEST-001" for r in result.matched_rules)
    assert result.decision is Decision.ALLOW


def test_validated_rule_requires_conditions_and_tests(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="validated", tests=[], prerequisites=[])
    with pytest.raises(ValueError, match="validated"):
        load_policy_pack(_write_pack(tmp_path, raw))


def test_validated_rule_accepted_with_conditions_and_tests(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="validated", prerequisites=[])
    pack = load_policy_pack(_write_pack(tmp_path, raw))
    assert pack.rules[0].status == "validated"


def test_validated_rule_does_not_fire_at_runtime(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="validated", prerequisites=[])
    pack = load_policy_pack(_write_pack(tmp_path, raw))
    result = pack.evaluate({"action": {"type": "test.trigger", "consequential": False}})
    assert all(r.id != "DUSK-TEST-001" for r in result.matched_rules)
    assert result.decision is Decision.ALLOW


def test_planned_rule_still_requires_prerequisites(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="planned", match=[], tests=[], prerequisites=[])
    with pytest.raises(ValueError, match="planned"):
        load_policy_pack(_write_pack(tmp_path, raw))


def test_invalid_lifecycle_status_is_rejected(tmp_path: Path) -> None:
    raw = _pack_with_single_rule(status="retired")
    with pytest.raises(ValueError, match="status"):
        load_policy_pack(_write_pack(tmp_path, raw))


def test_only_enforced_rules_affect_runtime_decision(tmp_path: Path) -> None:
    """All non-enforced lifecycle states must not alter the pack decision."""
    rules = [
        _enforced_rule(id="DUSK-TEST-001", status="proposed", match=[], prerequisites=[], tests=[]),
        _enforced_rule(id="DUSK-TEST-002", status="implemented", tests=[], prerequisites=[]),
        _enforced_rule(id="DUSK-TEST-003", status="validated", prerequisites=[]),
        _enforced_rule(
            id="DUSK-TEST-004",
            status="planned",
            match=[],
            tests=[],
            prerequisites=["some prereq"],
        ),
    ]
    raw: dict[str, object] = {
        "name": "test-pack",
        "version": "1.0.0",
        "default_decision": "ALLOW",
        "rules": rules,
    }
    pack = load_policy_pack(_write_pack(tmp_path, raw))
    result = pack.evaluate({"action": {"type": "test.trigger", "consequential": False}})
    assert result.decision is Decision.ALLOW
    assert result.matched_rules == ()


# ---------------------------------------------------------------------------
# Group 4: Context schema validation
# ---------------------------------------------------------------------------


def test_unknown_context_domain_raises_validation_error() -> None:
    with pytest.raises(ValueError, match="unknown context domain"):
        load_enterprise_pack().evaluate({"sneaky_key": {"val": True}})


def test_all_approved_domains_are_accepted() -> None:
    context = {
        "action": {"type": "noop"},
        "identity": {"agent_id": "a"},
        "tenant": {"id": "t"},
        "session": {"id": "s"},
        "objective": {"id": "o"},
        "delegation": {"chain": []},
        "tool": {"trusted": True},
        "resource": {"within_approved_root": True},
        "data": {"contains_secret": False},
        "destination": {"external": False},
        "permit": {"valid": True},
        "approval": {"valid": True},
        "execution": {"via_broker": True},
    }
    result = load_enterprise_pack().evaluate(context)
    assert isinstance(result, PolicyResult)


def test_empty_context_is_accepted() -> None:
    result = load_enterprise_pack().evaluate({})
    assert result.decision is Decision.ALLOW


# ---------------------------------------------------------------------------
# Group 5: Redacted audit evidence
# ---------------------------------------------------------------------------


def test_audit_dict_never_contains_context_values() -> None:
    """Decision evidence output must not include context field values."""
    context = {
        "identity": {"agent_id": "super-secret-agent-id"},
        "permit": {"expired": True},
    }
    d = load_enterprise_pack().evaluate(context).to_dict()
    output = str(d)
    assert "super-secret-agent-id" not in output


def test_audit_dict_contains_required_metadata_fields() -> None:
    d = load_enterprise_pack().evaluate({"permit": {"expired": True}}).to_dict()
    assert "decision" in d
    assert "policy_version" in d
    assert "evidence_degraded" in d
    assert "matched_rules" in d


def test_matched_rule_audit_entry_has_no_context_values() -> None:
    context = {
        "action": {
            "type": "iam.role.assign",
            "target_identity": "sensitive-service-account",
            "role": "owner",
        },
        "identity": {"agent_id": "sensitive-service-account"},
    }
    d = load_enterprise_pack().evaluate(context).to_dict()
    output = str(d)
    assert "sensitive-service-account" not in output


def test_audit_never_exposes_credential_shaped_values() -> None:
    """Even if a caller accidentally puts token-shaped data in context, audit
    output must not echo it back."""
    context = {
        "permit": {"expired": True},
        "identity": {"agent_id": "sk-1234-should-not-appear"},
    }
    d = load_enterprise_pack().evaluate(context).to_dict()
    assert "sk-1234-should-not-appear" not in str(d)


def test_evidence_degraded_in_audit_is_boolean_not_context_value() -> None:
    context = {
        "action": {"consequential": True},
        "permit": {"value": "must-not-leak", "_evidence": "UNKNOWN"},
    }
    d = load_enterprise_pack().evaluate(context).to_dict()
    assert "must-not-leak" not in str(d)
    assert isinstance(d["evidence_degraded"], bool)
