"""Trusted evidence and v2 policy precedence tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from dusk.application import BehavioralDecision
from dusk.policies import Decision, load_enterprise_pack
from dusk.policies.engine import PolicyResult

from dusk_control_plane.evaluations import (
    CanonicalAction,
    EvaluationRequest,
    EvidenceEnvelope,
    PolicyEvaluationService,
)
from dusk_control_plane.identity import IdentityKind, Principal
from dusk_control_plane.policy import (
    EnforcementMode,
    EvidenceRejectedError,
    EvidenceSubmission,
    EvidenceTrust,
    PolicyActivationError,
    PolicyIntegration,
    PolicyUnavailableError,
    VerifiedEvidence,
    certification_gated_rule_ids,
    combine_decisions,
)

NOW = datetime(2026, 9, 1, 0, 0, tzinfo=UTC)


def _policy(decision: Decision, *, degraded: bool = False) -> PolicyResult:
    return PolicyResult(decision, "1.2.3", (), degraded)


@pytest.mark.parametrize(
    ("policy", "degraded", "behavioral", "mode", "expected", "reason"),
    [
        (Decision.DENY, False, "ALLOW", EnforcementMode.ENFORCE, "BLOCK", "POLICY_DENY"),
        (Decision.DENY, False, "ALLOW", EnforcementMode.WATCH, "WOULD-BLOCK", "POLICY_DENY"),
        (Decision.DENY, False, "BLOCK", EnforcementMode.ENFORCE, "BLOCK", "POLICY_DENY"),
        (
            Decision.REQUIRE_APPROVAL,
            False,
            "ALLOW",
            EnforcementMode.ENFORCE,
            "WOULD-BLOCK",
            "APPROVAL_REQUIRED",
        ),
        (
            Decision.REQUIRE_APPROVAL,
            False,
            "BLOCK",
            EnforcementMode.ENFORCE,
            "WOULD-BLOCK",
            "APPROVAL_REQUIRED",
        ),
        (Decision.ALLOW, True, "ALLOW", EnforcementMode.ENFORCE, "BLOCK", "EVIDENCE_DEGRADED"),
        (Decision.ALLOW, True, "ALLOW", EnforcementMode.WATCH, "WOULD-BLOCK", "EVIDENCE_DEGRADED"),
        (Decision.ALLOW, False, "BLOCK", EnforcementMode.ENFORCE, "BLOCK", "BEHAVIORAL_THRESHOLD"),
        (
            Decision.ALLOW,
            False,
            "WOULD-BLOCK",
            EnforcementMode.WATCH,
            "WOULD-BLOCK",
            "BEHAVIORAL_THRESHOLD",
        ),
        (Decision.ALLOW, False, "ALLOW", EnforcementMode.ENFORCE, "ALLOW", None),
    ],
)
def test_complete_precedence_table(policy, degraded, behavioral, mode, expected, reason) -> None:
    result = combine_decisions(
        behavioral_verdict=behavioral,
        policy=_policy(policy, degraded=degraded),
        consequential=True,
        mode=mode,
    )
    assert result.verdict == expected
    assert result.reason_codes == (() if reason is None else (reason,))
    assert result.policy_pack_version == "1.2.3"


@dataclass
class _Verifier:
    live_domains: frozenset[str]
    trust: EvidenceTrust = EvidenceTrust.CONFIRMED

    async def verify(self, submission, principal) -> VerifiedEvidence:
        return VerifiedEvidence(
            submission.domain, submission.source_identity, self.trust, submission.payload
        )


def _principal() -> Principal:
    return Principal("issuer", "subject", "tenant-a", IdentityKind.WORKLOAD, workload_id="agent-a")


def _integration(pack, verifier) -> PolicyIntegration:
    return PolicyIntegration(
        pack,
        verifier,
        certified_rule_ids=certification_gated_rule_ids(pack),
    )


def _submission(payload: dict[str, object], *, observed_at: datetime = NOW) -> EvidenceSubmission:
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return EvidenceSubmission(
        "action",
        "aws-cloudtrail",
        "signed-event",
        observed_at,
        f"sha256:{digest}",
        payload,
        "tenant-a",
        "test-key",
        "test-nonce-00000001",
        "a" * 86,
    )


def test_activation_rejects_missing_live_prerequisites() -> None:
    with pytest.raises(PolicyActivationError, match="unavailable live evidence"):
        PolicyIntegration(load_enterprise_pack(), _Verifier(frozenset({"action"})))


def test_cloud_rules_cannot_activate_before_live_certification() -> None:
    pack = load_enterprise_pack()
    domains = frozenset(
        condition.field.split(".", 1)[0]
        for rule in pack.rules
        if rule.status == "enforced"
        for condition in rule.conditions
    )

    with pytest.raises(PolicyActivationError, match="approved live certification"):
        PolicyIntegration(pack, _Verifier(domains))


def test_certification_cannot_name_unknown_or_ungated_rules() -> None:
    pack = load_enterprise_pack()
    domains = frozenset(
        condition.field.split(".", 1)[0]
        for rule in pack.rules
        if rule.status == "enforced"
        for condition in rule.conditions
    )

    with pytest.raises(PolicyActivationError, match="unknown or ungated"):
        PolicyIntegration(
            pack,
            _Verifier(domains),
            certified_rule_ids=certification_gated_rule_ids(pack) | {"DUSK-IAM-001"},
        )


@pytest.mark.anyio
async def test_verified_context_derives_identity_and_returns_safe_policy_metadata() -> None:
    pack = load_enterprise_pack()
    domains = frozenset(
        condition.field.split(".", 1)[0]
        for rule in pack.rules
        if rule.status == "enforced"
        for condition in rule.conditions
    )
    integration = _integration(pack, _Verifier(domains))
    action = {"type": "network.firewall.update", "cidrs": ["0.0.0.0/0"], "consequential": True}
    result = await integration.evaluate(
        principal=_principal(),
        action_context=action,
        evidence=(_submission(action),),
        behavioral_verdict="ALLOW",
        mode=EnforcementMode.ENFORCE,
        now=NOW,
    )
    assert result.verdict == "BLOCK"
    assert result.policy_decision == "DENY"
    assert result.policy_pack_version == "1.0.0"
    assert {match.id for match in result.matched_rules} >= {"DUSK-NET-001"}
    assert "0.0.0.0/0" not in repr(result.matched_rules)


@pytest.mark.anyio
async def test_stale_evidence_fails_closed_and_caller_asserted_trust_is_rejected() -> None:
    pack = load_enterprise_pack()
    domains = frozenset(
        condition.field.split(".", 1)[0]
        for rule in pack.rules
        if rule.status == "enforced"
        for condition in rule.conditions
    )
    integration = _integration(pack, _Verifier(domains))
    action = {"type": "noop", "consequential": True}
    stale = await integration.evaluate(
        principal=_principal(),
        action_context=action,
        evidence=(_submission(action, observed_at=NOW - timedelta(hours=1)),),
        behavioral_verdict="ALLOW",
        mode=EnforcementMode.ENFORCE,
        now=NOW,
    )
    assert stale.verdict == "BLOCK"
    assert stale.evidence_degraded is True
    assert stale.reason_codes == ("EVIDENCE_DEGRADED",)
    asserted = {**action, "_evidence": "CONFIRMED"}
    with pytest.raises(EvidenceRejectedError, match="reserved"):
        await integration.evaluate(
            principal=_principal(),
            action_context=asserted,
            evidence=(_submission(asserted),),
            behavioral_verdict="ALLOW",
            mode=EnforcementMode.ENFORCE,
            now=NOW,
        )


class _Behavioral:
    async def evaluate(self, action, principal) -> BehavioralDecision:
        return BehavioralDecision(
            trace_id="trace-policy-1",
            verdict="ALLOW",
            score=0.12567,
            blast_radius="high",
            reasons=("behavioral allow",),
            mitre_attack="T1562.004",
            mitre_atlas="AML.T0051",
            predicted_next="watch network changes",
            target_class="firewall",
            target_tokens=frozenset({"public"}),
        )


@dataclass
class _UnavailableVerifier(_Verifier):
    async def verify(self, submission, principal) -> VerifiedEvidence:
        raise PolicyUnavailableError


@pytest.mark.anyio
async def test_v2_response_includes_policy_evidence_and_real_stage_timings() -> None:
    pack = load_enterprise_pack()
    domains = frozenset(
        condition.field.split(".", 1)[0]
        for rule in pack.rules
        if rule.status == "enforced"
        for condition in rule.conditions
    )
    action_context = {
        "type": "network.firewall.update",
        "target": "firewall-prod",
        "consequential": True,
        "tenant_id": "tenant-a",
        "cidrs": ["0.0.0.0/0"],
    }
    request = EvaluationRequest(
        action=CanonicalAction(
            agent_id="agent-a",
            action_type="network.firewall.update",
            target="firewall-prod",
            consequential=True,
            attributes={"cidrs": ["0.0.0.0/0"]},
        ),
        evidence=(EvidenceEnvelope(**_submission(action_context).__dict__),),
        idempotency_key="request-1",
    )
    response = await PolicyEvaluationService(
        _integration(pack, _Verifier(domains)),
        _Behavioral(),
        mode=EnforcementMode.ENFORCE,
        clock=lambda: NOW,
    ).evaluate(request, _principal())

    assert response.trace_id == "trace-policy-1"
    assert response.verdict == "BLOCK"
    assert response.behavioral_score == 0.1257
    assert response.policy_decision == "DENY"
    assert response.policy_pack_version == "1.0.0"
    assert response.response_status == "DECIDED"
    assert response.pipeline_timings.behavioral_ms >= 0
    assert response.pipeline_timings.total_ms >= response.pipeline_timings.policy_ms
    assert response.similar_decision_ids == ()


@pytest.mark.anyio
async def test_policy_provider_outage_fails_closed() -> None:
    pack = load_enterprise_pack()
    domains = frozenset(
        condition.field.split(".", 1)[0]
        for rule in pack.rules
        if rule.status == "enforced"
        for condition in rule.conditions
    )
    action = {"type": "noop", "consequential": True}
    integration = _integration(pack, _UnavailableVerifier(domains))
    with pytest.raises(PolicyUnavailableError):
        await integration.evaluate(
            principal=_principal(),
            action_context=action,
            evidence=(_submission(action),),
            behavioral_verdict="ALLOW",
            mode=EnforcementMode.ENFORCE,
            now=NOW,
        )
