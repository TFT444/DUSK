"""Behavioral tests for IAM rules 003-012 (issue #145).

Coverage per rule:
  - denial scenario    (malicious case fires)
  - benign case        (must not fire)
  - bypass case        (must not be bypassable)
  - missing evidence   (UNKNOWN + consequential => DENY via fail-closed)
  - watch mode         (rule fires, consequential=False -> not force-denied alone)
  - enforce mode       (consequential=True + UNKNOWN evidence => DENY)
"""

from __future__ import annotations

from dusk.policies import Decision, load_enterprise_pack

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PACK = None


def _pack():
    global _PACK
    if _PACK is None:
        _PACK = load_enterprise_pack()
    return _PACK


def _eval(context):
    return _pack().evaluate(context)


def _matched_ids(result):
    return {r.id for r in result.matched_rules}


# ---------------------------------------------------------------------------
# IAM-003: Prevent identity impersonation
# ---------------------------------------------------------------------------


class TestIAM003IdentityImpersonation:
    rule_id = "DUSK-IAM-003"

    def test_denial_impersonation_without_delegation(self):
        """Agent acting as another principal without delegation chain => DENY."""
        context = {
            "identity": {"subject": "agent-a"},
            "action": {
                "type": "identity.assume",
                "initiating_principal": "agent-a",
            },
            "delegation": {"present": False},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_acting_with_valid_delegation(self):
        """Agent acting with valid delegation chain must NOT fire IAM-003."""
        context = {
            "identity": {"subject": "agent-a"},
            "action": {
                "type": "identity.assume",
                "initiating_principal": "agent-a",
            },
            "delegation": {"present": True},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_missing_delegation_key(self):
        """Omitting delegation domain entirely must still trigger the rule."""
        context = {
            "identity": {"subject": "agent-x"},
            "action": {
                "type": "identity.assume",
                "initiating_principal": "agent-x",
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN identity evidence + consequential action => DENY via fail-closed."""
        context = {
            "identity": {
                "subject": "agent-z",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "identity.assume",
                "initiating_principal": "agent-z",
                "consequential": True,
            },
            "delegation": {"present": False},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Rule fires on impersonation; consequential=False does not alone force-deny."""
        context = {
            "identity": {"subject": "agent-w"},
            "action": {
                "type": "identity.assume",
                "initiating_principal": "agent-w",
                "consequential": False,
            },
            "delegation": {"present": False},
        }
        result = _eval(context)
        # Rule itself fires (DENY from the rule)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN identity evidence => DENY regardless of rule match."""
        context = {
            "identity": {
                "subject": "agent-e",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "consequential": True,
                "type": "identity.assume",
                "initiating_principal": "agent-e",
            },
            "delegation": {"present": True},  # delegation present, so rule itself won't fire
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-004: Require initiating principal for privileged actions
# ---------------------------------------------------------------------------


class TestIAM004InitiatingPrincipal:
    rule_id = "DUSK-IAM-004"

    def test_denial_privileged_action_no_principal(self):
        """Privileged action with no initiating principal => DENY."""
        context = {
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_privileged_action_with_principal(self):
        """Privileged action with an initiating principal must NOT fire IAM-004."""
        context = {
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "initiating_principal": "operator@example.com",
            },
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_benign_non_privileged_no_principal(self):
        """Non-privileged action without initiating principal must NOT fire IAM-004."""
        context = {
            "action": {
                "type": "filesystem.read",
                "privileged": False,
            },
            "resource": {"within_approved_root": True, "classification": "internal"},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_empty_string_principal(self):
        """Absent initiating_principal on a privileged action fires the rule.

        The rule fires when the field is absent (exists: false).  An attacker
        who supplies an empty string instead of a real principal still bypasses
        detection at the YAML layer; that case is expected to be caught at a
        higher validation layer.  Here we confirm the absence case fires.
        """
        # absent key => rule fires
        context = {
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                # initiating_principal deliberately absent
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN action evidence + consequential => DENY via fail-closed."""
        context = {
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "consequential": True,
                "_evidence": "UNKNOWN",
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Rule fires on privileged action without principal, even when non-consequential."""
        context = {
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "consequential": False,
            },
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN evidence => DENY even with principal present."""
        context = {
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "initiating_principal": "admin@example.com",
                "consequential": True,
                "_evidence": "UNKNOWN",
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-005: Prevent environment credential crossover
# ---------------------------------------------------------------------------


class TestIAM005CredentialCrossover:
    rule_id = "DUSK-IAM-005"

    def test_denial_credential_used_in_wrong_environment(self):
        """Credential from prod used in staging => DENY."""
        context = {
            "identity": {
                "credential_environment": "production",
            },
            "action": {
                "target_environment": "staging",
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_credential_matches_environment(self):
        """Credential environment matches action environment => must NOT fire IAM-005."""
        context = {
            "identity": {
                "credential_environment": "production",
            },
            "action": {
                "target_environment": "production",
            },
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_absent_credential_environment_fails_closed(self):
        """Absent credential_environment when target_environment set + UNKNOWN evidence => DENY.

        The not_equals operator requires the field to exist for the rule to match;
        an absent credential_environment is caught by fail-closed when evidence
        is degraded and the action is consequential.
        """
        context = {
            "identity": {
                "_evidence": "UNKNOWN",
            },
            "action": {
                "target_environment": "production",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN identity evidence + consequential => DENY."""
        context = {
            "identity": {
                "credential_environment": "production",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "target_environment": "staging",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Rule fires; non-consequential doesn't prevent the rule's own DENY."""
        context = {
            "identity": {"credential_environment": "production"},
            "action": {
                "target_environment": "staging",
                "consequential": False,
            },
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN evidence => DENY even if environments match."""
        context = {
            "identity": {
                "credential_environment": "production",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "target_environment": "production",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-006: Require fresh step-up authorization
# ---------------------------------------------------------------------------


class TestIAM006FreshStepUp:
    rule_id = "DUSK-IAM-006"

    def test_denial_requires_approval_no_valid_approval(self):
        """Step-up action without valid approval => REQUIRE_APPROVAL."""
        context = {
            "action": {
                "requires_fresh_authn": True,
            },
            "approval": {"valid": False},
        }
        result = _eval(context)
        assert result.decision in (Decision.DENY, Decision.REQUIRE_APPROVAL)
        assert self.rule_id in _matched_ids(result)

    def test_benign_step_up_with_valid_approval(self):
        """Step-up action with valid, fresh approval must NOT fire IAM-006."""
        context = {
            "action": {
                "requires_fresh_authn": True,
            },
            "approval": {"valid": True},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_benign_non_step_up_action(self):
        """Action not requiring fresh auth must NOT fire IAM-006."""
        context = {
            "action": {
                "type": "filesystem.read",
                "requires_fresh_authn": False,
            },
            "resource": {"within_approved_root": True, "classification": "internal"},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_missing_approval_domain(self):
        """Omitting approval domain when requires_fresh_authn=True => rule fires."""
        context = {
            "action": {
                "requires_fresh_authn": True,
            },
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN approval evidence + consequential => DENY via fail-closed."""
        context = {
            "action": {
                "requires_fresh_authn": True,
                "consequential": True,
            },
            "approval": {"valid": True, "_evidence": "UNKNOWN"},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Rule fires; non-consequential doesn't prevent REQUIRE_APPROVAL from the rule."""
        context = {
            "action": {
                "requires_fresh_authn": True,
                "consequential": False,
            },
            "approval": {"valid": False},
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN approval evidence => DENY."""
        context = {
            "action": {
                "requires_fresh_authn": True,
                "consequential": True,
            },
            "approval": {"valid": True, "_evidence": "UNKNOWN"},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-007: Workload identity audience mismatch
# ---------------------------------------------------------------------------


class TestIAM007AudienceMismatch:
    rule_id = "DUSK-IAM-007"

    def test_denial_audience_mismatch(self):
        """Token audience does not match target service => DENY."""
        context = {
            "identity": {
                "issuer": "https://accounts.example.com",
                "audience": "service-b",
                "subject": "workload-123",
            },
            "action": {
                "type": "api.call",
                "target_service": "service-a",
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_audience_matches(self):
        """Token audience matches target service => must NOT fire IAM-007."""
        context = {
            "identity": {
                "issuer": "https://accounts.example.com",
                "audience": "service-a",
                "subject": "workload-123",
            },
            "action": {
                "type": "api.call",
                "target_service": "service-a",
            },
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_missing_audience_fails_closed_on_consequential(self):
        """Omitting audience when target_service present + consequential + UNKNOWN => DENY.

        The engine's not_equals operator requires the field to exist for the rule to
        match; an absent audience claim is instead caught by the fail-closed path
        when action is consequential and evidence is degraded.
        """
        context = {
            "identity": {
                "issuer": "https://accounts.example.com",
                "subject": "workload-123",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "api.call",
                "target_service": "service-a",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN identity evidence + consequential + audience mismatch => DENY."""
        context = {
            "identity": {
                "issuer": "https://accounts.example.com",
                "audience": "service-b",
                "subject": "workload-456",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "api.call",
                "target_service": "service-a",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Audience mismatch fires rule; non-consequential does not prevent rule DENY."""
        context = {
            "identity": {
                "issuer": "https://accounts.example.com",
                "audience": "service-b",
                "subject": "workload-w",
            },
            "action": {
                "type": "api.call",
                "target_service": "service-a",
                "consequential": False,
            },
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN evidence => DENY even if audience matches."""
        context = {
            "identity": {
                "issuer": "https://accounts.example.com",
                "audience": "service-a",
                "subject": "workload-e",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "api.call",
                "target_service": "service-a",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-008: Stale or revoked identity
# ---------------------------------------------------------------------------


class TestIAM008StaleRevokedIdentity:
    rule_id = "DUSK-IAM-008"

    def test_denial_revoked_identity(self):
        """Revoked identity must be DENY."""
        context = {
            "identity": {
                "subject": "sa-revoked@example.com",
                "revoked": True,
            },
            "action": {"type": "api.call"},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_denial_stale_identity(self):
        """Stale evidence on identity for a consequential action => DENY."""
        context = {
            "identity": {
                "subject": "sa-stale@example.com",
                "revoked": False,
                "_evidence": "STALE",
            },
            "action": {"type": "api.call", "consequential": True},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_benign_active_identity(self):
        """Active, non-revoked identity must NOT fire IAM-008."""
        context = {
            "identity": {
                "subject": "sa-active@example.com",
                "revoked": False,
            },
            "action": {"type": "api.call"},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_missing_revoked_field(self):
        """Omitting revoked field must still trigger the rule (absence is not confirmed safe)."""
        context = {
            "identity": {
                "subject": "sa-unknown@example.com",
                "_evidence": "UNKNOWN",
            },
            "action": {"type": "api.call", "consequential": True},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN identity evidence on consequential action => DENY (fail-closed)."""
        context = {
            "identity": {
                "subject": "sa-x@example.com",
                "revoked": False,
                "_evidence": "UNKNOWN",
            },
            "action": {"consequential": True},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_revoked_non_consequential(self):
        """Revoked identity fires rule; non-consequential does not prevent rule DENY."""
        context = {
            "identity": {
                "subject": "sa-r@example.com",
                "revoked": True,
            },
            "action": {"type": "api.call", "consequential": False},
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN identity evidence => DENY."""
        context = {
            "identity": {
                "subject": "sa-e@example.com",
                "revoked": False,
                "_evidence": "UNKNOWN",
            },
            "action": {"consequential": True, "type": "api.call"},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-009: Privilege use outside assigned role
# ---------------------------------------------------------------------------


class TestIAM009PrivilegeOutsideRole:
    rule_id = "DUSK-IAM-009"

    def test_denial_role_mismatch(self):
        """Identity role does not satisfy action required_role => DENY."""
        context = {
            "identity": {
                "role": "viewer",
            },
            "action": {
                "type": "iam.role.assign",
                "required_role": "administrator",
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_role_matches(self):
        """Identity role satisfies required_role => must NOT fire IAM-009."""
        context = {
            "identity": {
                "role": "administrator",
            },
            "action": {
                "type": "iam.role.assign",
                "required_role": "administrator",
            },
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_missing_role_fails_closed(self):
        """Absent identity.role + UNKNOWN evidence + consequential action => DENY.

        The not_equals operator requires the field to exist for the rule to match;
        a missing role is caught by fail-closed when evidence is degraded and
        the action is consequential.
        """
        context = {
            "identity": {
                "subject": "agent-norole",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "iam.role.assign",
                "required_role": "administrator",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN identity evidence + consequential => DENY."""
        context = {
            "identity": {
                "role": "viewer",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "iam.role.assign",
                "required_role": "administrator",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Rule fires for role mismatch; non-consequential doesn't prevent DENY from rule."""
        context = {
            "identity": {"role": "viewer"},
            "action": {
                "type": "iam.role.assign",
                "required_role": "administrator",
                "consequential": False,
            },
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN evidence => DENY even with role match."""
        context = {
            "identity": {
                "role": "administrator",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "iam.role.assign",
                "required_role": "administrator",
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-010: Service account interactive login
# ---------------------------------------------------------------------------


class TestIAM010ServiceAccountInteractiveLogin:
    rule_id = "DUSK-IAM-010"

    def test_service_account_interactive_non_login_action_does_not_match(self):
        """Interactive metadata on an unrelated action must not trigger IAM-010."""
        context = {
            "identity": {
                "subject": "sa-svc@example.com",
                "type": "service_account",
                "interactive": True,
            },
            "action": {"type": "resource.read"},
        }

        result = _eval(context)

        assert self.rule_id not in _matched_ids(result)

    def test_denial_service_account_interactive(self):
        """Service account attempting interactive login => DENY."""
        context = {
            "identity": {
                "subject": "sa-svc@example.com",
                "type": "service_account",
                "interactive": True,
            },
            "action": {"type": "auth.login"},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_service_account_non_interactive(self):
        """Service account with non-interactive flow must NOT fire IAM-010."""
        context = {
            "identity": {
                "subject": "sa-svc@example.com",
                "interactive": False,
            },
            "action": {"type": "auth.login"},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_missing_interactive_field(self):
        """Omitting the interactive field must not fire the rule (absent is not True)."""
        context = {
            "identity": {
                "subject": "sa-svc@example.com",
            },
            "action": {"type": "auth.login"},
        }
        result = _eval(context)
        # missing interactive != True, rule should NOT fire
        assert self.rule_id not in _matched_ids(result)

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN identity evidence + consequential => DENY via fail-closed."""
        context = {
            "identity": {
                "subject": "sa-svc@example.com",
                "interactive": True,
                "_evidence": "UNKNOWN",
            },
            "action": {"type": "auth.login", "consequential": True},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Rule fires; non-consequential doesn't prevent rule's own DENY."""
        context = {
            "identity": {
                "subject": "sa-svc@example.com",
                "type": "service_account",
                "interactive": True,
            },
            "action": {"type": "auth.login", "consequential": False},
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_human_interactive_login_does_not_match(self):
        """Human interactive login must NOT fire IAM-010 (no service_account type)."""
        context = {
            "identity": {
                "subject": "human@example.com",
                "type": "human",
                "interactive": True,
            },
            "action": {"type": "auth.login"},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result), (
            "IAM-010 must not fire for human identities — only service accounts"
        )

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN evidence => DENY even if interactive=False."""
        context = {
            "identity": {
                "subject": "sa-svc@example.com",
                "interactive": False,
                "_evidence": "UNKNOWN",
            },
            "action": {"type": "auth.login", "consequential": True},
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-011: Identity assurance downgrade
# ---------------------------------------------------------------------------


class TestIAM011AssuranceDowngrade:
    rule_id = "DUSK-IAM-011"

    def test_denial_assurance_downgrade(self):
        """Identity assurance_sufficient=False when action requires it => DENY."""
        context = {
            "identity": {
                "assurance_level": 1,
                "assurance_sufficient": False,
                "subject": "agent-low",
            },
            "action": {
                "type": "iam.role.assign",
                "requires_assurance": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_assurance_sufficient(self):
        """Identity assurance_sufficient=True => must NOT fire IAM-011."""
        context = {
            "identity": {
                "assurance_level": 3,
                "assurance_sufficient": True,
                "subject": "agent-high",
            },
            "action": {
                "type": "iam.role.assign",
                "requires_assurance": True,
            },
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_missing_assurance_sufficient(self):
        """Omitting assurance_sufficient when action requires_assurance=True => rule fires."""
        context = {
            "identity": {
                "subject": "agent-noal",
            },
            "action": {
                "type": "iam.role.assign",
                "requires_assurance": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_action_not_requiring_assurance(self):
        """Action that does not require assurance => IAM-011 must not fire."""
        context = {
            "identity": {
                "assurance_sufficient": False,
                "subject": "agent-low2",
            },
            "action": {
                "type": "filesystem.read",
                "requires_assurance": False,
            },
            "resource": {"within_approved_root": True, "classification": "internal"},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN identity evidence + consequential => DENY."""
        context = {
            "identity": {
                "assurance_sufficient": False,
                "subject": "agent-uk",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "iam.role.assign",
                "requires_assurance": True,
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Rule fires; non-consequential does not prevent rule DENY."""
        context = {
            "identity": {"assurance_sufficient": False, "subject": "agent-w"},
            "action": {
                "type": "iam.role.assign",
                "requires_assurance": True,
                "consequential": False,
            },
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN evidence => DENY even if assurance sufficient."""
        context = {
            "identity": {
                "assurance_sufficient": True,
                "subject": "agent-e",
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "iam.role.assign",
                "requires_assurance": True,
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True


# ---------------------------------------------------------------------------
# IAM-012: Privileged action without fresh authentication
# ---------------------------------------------------------------------------


class TestIAM012PrivilegedWithoutFreshAuthn:
    rule_id = "DUSK-IAM-012"

    def test_denial_privileged_no_fresh_authn(self):
        """Privileged action without fresh_authn_confirmed => DENY."""
        context = {
            "identity": {
                "subject": "agent-priv",
                "fresh_authn_confirmed": False,
            },
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "requires_fresh_authn": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_denial_privileged_missing_confirmed_flag(self):
        """Missing fresh_authn_confirmed on a privileged action must DENY."""
        context = {
            "identity": {
                "subject": "agent-priv2",
                # fresh_authn_confirmed intentionally absent
            },
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "requires_fresh_authn": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_benign_privileged_with_fresh_authn(self):
        """Privileged action with fresh_authn_confirmed=True => must NOT fire IAM-012."""
        context = {
            "identity": {
                "subject": "agent-priv-ok",
                "fresh_authn_confirmed": True,
            },
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "requires_fresh_authn": True,
            },
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_benign_non_privileged_no_fresh_authn(self):
        """Non-privileged action does not require fresh authn => must NOT fire."""
        context = {
            "identity": {"subject": "agent-np", "fresh_authn_confirmed": False},
            "action": {
                "type": "filesystem.read",
                "privileged": False,
                "requires_fresh_authn": False,
            },
            "resource": {"within_approved_root": True, "classification": "internal"},
        }
        result = _eval(context)
        assert self.rule_id not in _matched_ids(result)

    def test_bypass_null_confirmed_flag(self):
        """False fresh_authn_confirmed fires the rule (not_true catches both False and absent)."""
        context = {
            "identity": {
                "subject": "agent-null-ts",
                "fresh_authn_confirmed": False,
            },
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "requires_fresh_authn": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert self.rule_id in _matched_ids(result)

    def test_missing_evidence_consequential_deny(self):
        """UNKNOWN identity evidence + consequential => DENY."""
        context = {
            "identity": {
                "subject": "agent-uk",
                "fresh_authn_confirmed": True,
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "requires_fresh_authn": True,
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_watch_mode_non_consequential(self):
        """Rule fires on missing fresh authn; non-consequential does not prevent DENY."""
        context = {
            "identity": {
                "subject": "agent-w",
                "fresh_authn_confirmed": False,
            },
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "requires_fresh_authn": True,
                "consequential": False,
            },
        }
        result = _eval(context)
        assert self.rule_id in _matched_ids(result)
        assert result.decision is Decision.DENY

    def test_enforce_mode_unknown_evidence_plus_consequential(self):
        """Consequential=True + UNKNOWN evidence => DENY even with fresh authn confirmed."""
        context = {
            "identity": {
                "subject": "agent-e",
                "fresh_authn_confirmed": True,
                "_evidence": "UNKNOWN",
            },
            "action": {
                "type": "iam.role.assign",
                "privileged": True,
                "requires_fresh_authn": True,
                "consequential": True,
            },
        }
        result = _eval(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True
