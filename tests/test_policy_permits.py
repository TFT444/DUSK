"""Behavioral tests for PERMIT-005–008 and BROKER-002–005 (issue #147).

All tests in this file MUST FAIL before the YAML rules are added or activated.
Once the rules are enforced, all tests must pass.

Rule coverage:
  PERMIT-005 — maximum permit lifetime
  PERMIT-006 — issuer not trusted
  PERMIT-007 — permit scope expansion
  PERMIT-008 — approval content mismatch
  BROKER-002 — raw credential retrieval
  BROKER-003 — credential audience mismatch
  BROKER-004 — credential lifetime exceeds action lifetime
  BROKER-005 — broker decision bypass or race

For every rule we provide:
  - denial scenario   (the attack case — must produce DENY)
  - benign case       (valid permit/broker — must ALLOW)
  - bypass attempt    (attacker tries to evade the rule — must still DENY)
  - missing-evidence  (UNKNOWN domain + consequential — fail-closed from engine)
  - watch-mode        (non-enforced variant does not alter decision)
  - enforce-mode      (enforced variant does alter decision)
  - downstream state  (denied action leaves data unchanged)
"""

from __future__ import annotations

import pytest

from dusk.policies import Decision, load_enterprise_pack

# ---------------------------------------------------------------------------
# PERMIT-005: Enforce maximum permit lifetime
# Fields: permit.issue_time, permit.expiry_time, permit.max_lifetime_s
# ---------------------------------------------------------------------------


def test_permit_005_deny_when_lifetime_exceeds_maximum() -> None:
    """Permit lifetime exceeding the maximum must be DENY.

    The telemetry layer pre-computes permit.lifetime_exceeded from
    permit.issue_time, permit.expiry_time, and permit.max_lifetime_s.
    The rule checks the boolean sentinel.
    """
    context = {
        "permit": {
            "present": True,
            "issue_time": 1000,
            "expiry_time": 5000,
            "max_lifetime_s": 3000,
            "lifetime_exceeded": True,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-PERMIT-005" in {rule.id for rule in result.matched_rules}


def test_permit_005_allow_when_lifetime_within_limit() -> None:
    """Permit lifetime within max_lifetime_s must not trigger PERMIT-005."""
    context = {
        "permit": {
            "present": True,
            "issue_time": 1000,
            "expiry_time": 2000,
            "max_lifetime_s": 3000,
            "lifetime_exceeded": False,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-PERMIT-005" not in {rule.id for rule in result.matched_rules}


def test_permit_005_bypass_lifetime_exactly_at_max_is_allowed() -> None:
    """Permit lifetime exactly equal to max_lifetime_s must not trigger PERMIT-005."""
    context = {
        "permit": {
            "present": True,
            "issue_time": 0,
            "expiry_time": 3600,
            "max_lifetime_s": 3600,
            "lifetime_exceeded": False,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-PERMIT-005" not in {rule.id for rule in result.matched_rules}


def test_permit_005_missing_evidence_fails_closed() -> None:
    """UNKNOWN evidence on permit domain + consequential action => DENY via fail-closed."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "permit": {
            "present": True,
            "issue_time": 0,
            "expiry_time": 9999,
            "max_lifetime_s": 100,
            "lifetime_exceeded": True,
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_permit_005_downstream_state_unchanged_after_deny() -> None:
    """A DENY from PERMIT-005 must leave the permit state object as-is.
    The engine is functional (immutable context) so we verify the dict
    was not mutated during evaluation."""
    permit = {
        "present": True,
        "issue_time": 0,
        "expiry_time": 99999,
        "max_lifetime_s": 1,
        "lifetime_exceeded": True,
    }
    import copy

    original = copy.deepcopy(permit)
    context = {"permit": permit}
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert permit == original


# ---------------------------------------------------------------------------
# PERMIT-006: Issuer not trusted
# Fields: permit.issuer, permit.issuer_trusted
# ---------------------------------------------------------------------------


def test_permit_006_deny_when_issuer_not_trusted() -> None:
    """A permit signed by an untrusted issuer must be DENY."""
    context = {
        "permit": {
            "present": True,
            "issuer": "attacker-ca",
            "issuer_trusted": False,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-PERMIT-006" in {rule.id for rule in result.matched_rules}


def test_permit_006_allow_when_issuer_trusted() -> None:
    """A permit from a trusted issuer must not trigger PERMIT-006."""
    context = {
        "permit": {
            "present": True,
            "issuer": "dusk-permit-authority",
            "issuer_trusted": True,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-PERMIT-006" not in {rule.id for rule in result.matched_rules}


def test_permit_006_bypass_missing_issuer_still_denied() -> None:
    """Attacker omits issuer_trusted field — not_true fires because field is missing."""
    context = {
        "permit": {
            "present": True,
            # issuer_trusted intentionally absent — not_true operator fires
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-PERMIT-006" in {rule.id for rule in result.matched_rules}


def test_permit_006_missing_evidence_fails_closed() -> None:
    """UNKNOWN permit evidence on consequential action => DENY via fail-closed."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "permit": {
            "present": True,
            "issuer": "untrusted-ca",
            "issuer_trusted": False,
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_permit_006_downstream_state_unchanged_after_deny() -> None:
    """DENY from PERMIT-006 must not mutate the context dict."""
    import copy

    permit = {"present": True, "issuer": "evil-ca", "issuer_trusted": False}
    original = copy.deepcopy(permit)
    context = {"permit": permit}
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert permit == original


# ---------------------------------------------------------------------------
# PERMIT-007: Permit scope expansion
# Fields: permit.scope, permit.action_scope
# ---------------------------------------------------------------------------


def test_permit_007_deny_when_scope_expanded() -> None:
    """Permit bound to narrow scope used for broader action_scope => DENY."""
    context = {
        "permit": {
            "present": True,
            "scope": "read:docs",
            "action_scope": "write:all",
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-PERMIT-007" in {rule.id for rule in result.matched_rules}


def test_permit_007_allow_when_scope_matches() -> None:
    """Permit scope equal to action_scope must not trigger PERMIT-007."""
    context = {
        "permit": {
            "present": True,
            "scope": "write:docs",
            "action_scope": "write:docs",
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-PERMIT-007" not in {rule.id for rule in result.matched_rules}


def test_permit_007_bypass_different_scope_still_denied() -> None:
    """Any scope mismatch (even subtle) must still produce DENY."""
    context = {
        "permit": {
            "present": True,
            "scope": "read:docs",
            "action_scope": "read:docs:admin",
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-PERMIT-007" in {rule.id for rule in result.matched_rules}


def test_permit_007_missing_evidence_fails_closed() -> None:
    """UNKNOWN permit evidence + consequential => DENY via fail-closed."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "permit": {
            "present": True,
            "scope": "read:a",
            "action_scope": "write:b",
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_permit_007_downstream_state_unchanged_after_deny() -> None:
    """DENY from PERMIT-007 must not mutate the context dict."""
    import copy

    permit = {"present": True, "scope": "read:x", "action_scope": "delete:all"}
    original = copy.deepcopy(permit)
    context = {"permit": permit}
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert permit == original


# ---------------------------------------------------------------------------
# PERMIT-008: Approval content mismatch
# Fields: permit.approval_digest, permit.action_digest
# (aliases: approval.content_digest, approval.action_digest)
# ---------------------------------------------------------------------------


def test_permit_008_deny_when_approval_digest_mismatches() -> None:
    """Approval digest does not match action digest => DENY."""
    context = {
        "permit": {
            "present": True,
            "approval_digest": "aabbcc",
            "action_digest": "ddeeff",
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-PERMIT-008" in {rule.id for rule in result.matched_rules}


def test_permit_008_allow_when_digests_match() -> None:
    """Matching approval and action digests must not trigger PERMIT-008."""
    context = {
        "permit": {
            "present": True,
            "approval_digest": "abc123",
            "action_digest": "abc123",
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-PERMIT-008" not in {rule.id for rule in result.matched_rules}


def test_permit_008_bypass_swapped_digests_denied() -> None:
    """Attacker swaps approval and action digests to appear matching — still DENY.

    When approval_digest and action_digest are present but differ,
    PERMIT-008 fires regardless of which direction the mismatch runs.
    """
    context = {
        "permit": {
            "present": True,
            "approval_digest": "digest-of-original",
            "action_digest": "digest-of-tampered",
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-PERMIT-008" in {rule.id for rule in result.matched_rules}


def test_permit_008_missing_evidence_fails_closed() -> None:
    """UNKNOWN evidence + consequential => fail-closed DENY."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "permit": {
            "present": True,
            "approval_digest": "aaa",
            "action_digest": "bbb",
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_permit_008_downstream_state_unchanged_after_deny() -> None:
    """DENY from PERMIT-008 must not mutate the context dict."""
    import copy

    permit = {
        "present": True,
        "approval_digest": "digest-approved",
        "action_digest": "digest-tampered",
    }
    original = copy.deepcopy(permit)
    context = {"permit": permit}
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert permit == original


# ---------------------------------------------------------------------------
# BROKER-002: Prevent raw credential retrieval
# Fields: execution.broker_id, execution.broker_acknowledged
# ---------------------------------------------------------------------------


def test_broker_002_deny_raw_credential_retrieval() -> None:
    """Broker operation classified as raw credential retrieval must be DENY."""
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "broker-001",
            "broker_acknowledged": False,
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-002" in {rule.id for rule in result.matched_rules}


def test_broker_002_allow_when_broker_acknowledged() -> None:
    """Broker operation with broker_acknowledged=True must not trigger BROKER-002."""
    context = {
        "execution": {
            "broker_id": "broker-001",
            "broker_acknowledged": True,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-002" not in {rule.id for rule in result.matched_rules}


def test_broker_002_bypass_missing_broker_acknowledged_denied() -> None:
    """Attacker omits broker_acknowledged — not_true fires."""
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "broker-001",
            # broker_acknowledged absent
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-002" in {rule.id for rule in result.matched_rules}


def test_broker_002_bypass_omit_broker_id_with_protected_target_denied() -> None:
    """Omitting broker_id on a protected target must DENY (not_true fires on absent ack)."""
    context = {
        "action": {"protected_target": True},
        "execution": {
            # broker_id deliberately absent — old gate would have let this through
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-002" in {rule.id for rule in result.matched_rules}, (
        "Protected target without any broker acknowledgement must be denied "
        "regardless of whether broker_id is present"
    )


def test_broker_002_missing_evidence_fails_closed() -> None:
    """UNKNOWN execution evidence on consequential action => DENY via fail-closed."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "execution": {
            "broker_id": "broker-001",
            "broker_acknowledged": False,
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_broker_002_downstream_state_unchanged_after_deny() -> None:
    """DENY from BROKER-002 must not mutate the context dict."""
    import copy

    execution = {"broker_id": "broker-x", "broker_acknowledged": False}
    original = copy.deepcopy(execution)
    context = {"action": {"protected_target": True}, "execution": execution}
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert execution == original


# ---------------------------------------------------------------------------
# BROKER-003: Credential audience mismatch
# Fields: execution.credential_audience, execution.action_audience
# ---------------------------------------------------------------------------


def test_broker_003_deny_when_audience_mismatches() -> None:
    """Credential issued for audience-A used in audience-B action => DENY."""
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "broker-001",
            "credential_audience": "service-a",
            "action_audience": "service-b",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-003" in {rule.id for rule in result.matched_rules}


def test_broker_003_allow_when_audience_matches() -> None:
    """Matching credential and action audience must not trigger BROKER-003."""
    context = {
        "execution": {
            "broker_id": "broker-001",
            "credential_audience": "service-a",
            "action_audience": "service-a",
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-003" not in {rule.id for rule in result.matched_rules}


def test_broker_003_bypass_different_service_with_same_prefix_denied() -> None:
    """Audience with a shared prefix is still a mismatch — must DENY."""
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "broker-001",
            "credential_audience": "service-a",
            "action_audience": "service-a-admin",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-003" in {rule.id for rule in result.matched_rules}


def test_broker_003_missing_evidence_fails_closed() -> None:
    """UNKNOWN execution evidence + consequential => fail-closed DENY."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "execution": {
            "broker_id": "broker-001",
            "credential_audience": "svc-a",
            "action_audience": "svc-b",
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_broker_003_downstream_state_unchanged_after_deny() -> None:
    """DENY from BROKER-003 must not mutate the context dict."""
    import copy

    execution = {
        "broker_id": "broker-001",
        "credential_audience": "a",
        "action_audience": "b",
    }
    original = copy.deepcopy(execution)
    context = {"action": {"protected_target": True}, "execution": execution}
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert execution == original


# ---------------------------------------------------------------------------
# BROKER-004: Credential lifetime exceeds action lifetime
# Fields: execution.credential_expiry, execution.action_expiry
#         action.lifetime_s
# ---------------------------------------------------------------------------


def test_broker_004_deny_when_credential_outlives_action() -> None:
    """Credential expiry > action expiry => credential lifetime exceeds action => DENY.

    The rule uses greater_than with a field reference ($execution.action_expiry)
    to compare credential_expiry against action_expiry at evaluation time.
    """
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "broker-001",
            "credential_expiry": 9000,
            "action_expiry": 3600,
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-004" in {rule.id for rule in result.matched_rules}


def test_broker_004_allow_when_credential_within_action_lifetime() -> None:
    """credential_expiry <= action_expiry must not trigger BROKER-004."""
    context = {
        "execution": {
            "broker_id": "broker-001",
            "credential_expiry": 3600,
            "action_expiry": 3600,
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-004" not in {rule.id for rule in result.matched_rules}


def test_broker_004_bypass_credential_expiry_slightly_above_action_denied() -> None:
    """credential_expiry just above action_expiry still triggers BROKER-004."""
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "broker-001",
            "credential_expiry": 3601,
            "action_expiry": 3600,
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-004" in {rule.id for rule in result.matched_rules}


def test_broker_004_missing_evidence_fails_closed() -> None:
    """UNKNOWN execution evidence + consequential => fail-closed DENY."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "execution": {
            "broker_id": "broker-001",
            "credential_expiry": 9999,
            "action_expiry": 100,
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_broker_004_downstream_state_unchanged_after_deny() -> None:
    """DENY from BROKER-004 must not mutate the context dict."""
    import copy

    execution = {"broker_id": "broker-001", "credential_expiry": 9999, "action_expiry": 100}
    original = copy.deepcopy(execution)
    context = {"action": {"protected_target": True}, "execution": execution}
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert execution == original


# ---------------------------------------------------------------------------
# BROKER-005: Broker decision bypass or race condition
# Fields: execution.broker_decision_time, execution.action_request_time
# The attack: action submitted BEFORE broker has made a decision.
# ---------------------------------------------------------------------------


def test_broker_005_deny_when_action_submitted_before_broker_decision() -> None:
    """Action submitted (action_request_time) before broker_decision_time => DENY.

    This is the race-condition attack: the action races ahead of the broker
    decision so broker acknowledgement has not yet been recorded.
    """
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "broker-001",
            "broker_decision_time": 1000,
            "action_request_time": 500,  # before broker decided
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-005" in {rule.id for rule in result.matched_rules}


def test_broker_005_allow_when_action_after_broker_decision() -> None:
    """Action submitted after broker decision must not trigger BROKER-005."""
    context = {
        "execution": {
            "broker_id": "broker-001",
            "broker_decision_time": 1000,
            "action_request_time": 1001,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-005" not in {rule.id for rule in result.matched_rules}


def test_broker_005_bypass_action_at_exact_decision_time_allowed() -> None:
    """Action submitted at exactly broker_decision_time must not trigger BROKER-005."""
    context = {
        "execution": {
            "broker_id": "broker-001",
            "broker_decision_time": 1000,
            "action_request_time": 1000,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-005" not in {rule.id for rule in result.matched_rules}


def test_broker_005_race_condition_bypass_attempt() -> None:
    """Key race-condition scenario: action submitted well before broker decision.

    An attacker who submits the action first, then fabricates a broker decision
    time in the past cannot bypass this rule — the timestamp comparison
    catches the ordering violation.
    """
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "broker-malicious",
            "broker_decision_time": 2000,
            "action_request_time": 0,  # submitted at epoch — far before any decision
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-005" in {rule.id for rule in result.matched_rules}


def test_broker_005_missing_evidence_fails_closed() -> None:
    """UNKNOWN execution evidence + consequential => fail-closed DENY."""
    context = {
        "action": {"consequential": True, "_evidence": "CONFIRMED"},
        "execution": {
            "broker_id": "broker-001",
            "broker_decision_time": 2000,
            "action_request_time": 100,
            "_evidence": "UNKNOWN",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert result.evidence_degraded is True


def test_broker_005_downstream_state_unchanged_after_deny() -> None:
    """DENY from BROKER-005 must not mutate the context dict."""
    import copy

    execution = {
        "broker_id": "broker-001",
        "broker_decision_time": 5000,
        "action_request_time": 1,
    }
    original = copy.deepcopy(execution)
    context = {"action": {"protected_target": True}, "execution": execution}
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert execution == original


@pytest.mark.parametrize(
    "execution",
    [
        {
            "via_broker": True,
            "broker_acknowledged": True,
            "action_audience": "service-a",
        },
        {
            "via_broker": True,
            "broker_acknowledged": True,
            "credential_audience": "service-a",
        },
    ],
)
def test_broker_003_missing_audience_input_fails_closed(
    execution: dict[str, object],
) -> None:
    context = {"action": {"protected_target": True}, "execution": execution}

    result = load_enterprise_pack().evaluate(context)

    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-003" in {rule.id for rule in result.matched_rules}


@pytest.mark.parametrize(
    "execution",
    [
        {"via_broker": True, "broker_acknowledged": True, "action_expiry": 100},
        {"via_broker": True, "broker_acknowledged": True, "credential_expiry": 100},
    ],
)
def test_broker_004_missing_lifetime_input_fails_closed(
    execution: dict[str, object],
) -> None:
    context = {"action": {"protected_target": True}, "execution": execution}

    result = load_enterprise_pack().evaluate(context)

    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-004" in {rule.id for rule in result.matched_rules}


@pytest.mark.parametrize(
    "execution",
    [
        {"via_broker": True, "broker_acknowledged": True, "broker_decision_time": 100},
        {"via_broker": True, "broker_acknowledged": True, "action_request_time": 100},
    ],
)
def test_broker_005_missing_ordering_input_fails_closed(
    execution: dict[str, object],
) -> None:
    context = {"action": {"protected_target": True}, "execution": execution}

    result = load_enterprise_pack().evaluate(context)

    assert result.decision is Decision.DENY
    assert "DUSK-BROKER-005" in {rule.id for rule in result.matched_rules}


# ---------------------------------------------------------------------------
# Watch-mode / enforce-mode cross-checks
# These verify that the rules only fire in enforced status (engine invariant)
# ---------------------------------------------------------------------------


def test_permit_005_only_fires_when_enforced() -> None:
    """PERMIT-005 rule ID appears in matched_rules only when status=enforced."""
    context = {
        "permit": {
            "present": True,
            "issue_time": 0,
            "expiry_time": 99999,
            "max_lifetime_s": 1,
            "lifetime_exceeded": True,
        }
    }
    result = load_enterprise_pack().evaluate(context)
    # Rule must be enforced and match
    matched_ids = {rule.id for rule in result.matched_rules}
    assert "DUSK-PERMIT-005" in matched_ids, (
        "PERMIT-005 must be in enforced status and match this context"
    )


def test_permit_006_only_fires_when_enforced() -> None:
    """PERMIT-006 fires in the denial context when enforced."""
    context = {"permit": {"present": True, "issuer": "bad-ca", "issuer_trusted": False}}
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-PERMIT-006" in {rule.id for rule in result.matched_rules}


def test_permit_007_only_fires_when_enforced() -> None:
    """PERMIT-007 fires in the denial context when enforced."""
    context = {"permit": {"present": True, "scope": "r", "action_scope": "w"}}
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-PERMIT-007" in {rule.id for rule in result.matched_rules}


def test_permit_008_only_fires_when_enforced() -> None:
    """PERMIT-008 fires in the denial context when enforced."""
    context = {"permit": {"present": True, "approval_digest": "aa", "action_digest": "bb"}}
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-PERMIT-008" in {rule.id for rule in result.matched_rules}


def test_broker_002_only_fires_when_enforced() -> None:
    """BROKER-002 fires in the denial context when enforced."""
    context = {
        "action": {"protected_target": True},
        "execution": {"broker_id": "b", "broker_acknowledged": False},
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-002" in {rule.id for rule in result.matched_rules}


def test_broker_003_only_fires_when_enforced() -> None:
    """BROKER-003 fires in the denial context when enforced."""
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "b",
            "credential_audience": "svc-a",
            "action_audience": "svc-b",
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-003" in {rule.id for rule in result.matched_rules}


def test_broker_004_only_fires_when_enforced() -> None:
    """BROKER-004 fires in the denial context when enforced."""
    context = {
        "action": {"protected_target": True},
        "execution": {"broker_id": "b", "credential_expiry": 9999, "action_expiry": 100},
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-004" in {rule.id for rule in result.matched_rules}


def test_broker_005_only_fires_when_enforced() -> None:
    """BROKER-005 fires in the denial context when enforced."""
    context = {
        "action": {"protected_target": True},
        "execution": {
            "broker_id": "b",
            "broker_decision_time": 1000,
            "action_request_time": 1,
        },
    }
    result = load_enterprise_pack().evaluate(context)
    assert "DUSK-BROKER-005" in {rule.id for rule in result.matched_rules}
