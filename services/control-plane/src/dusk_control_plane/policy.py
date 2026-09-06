"""Trusted policy integration and deterministic v2 decision precedence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal, Protocol

from dusk.policies import Decision, PolicyPack, PolicyResult
from dusk.policies.engine import Rule

from dusk_control_plane.identity import Principal

SERVER_DERIVED_DOMAINS = frozenset({"identity", "tenant"})
CERTIFICATION_GATED_RULE_PREFIXES = ("DUSK-CLOUD-",)


class EnforcementMode(StrEnum):
    WATCH = "watch"
    ENFORCE = "enforce"


class EvidenceTrust(StrEnum):
    CONFIRMED = "CONFIRMED"
    UNKNOWN = "UNKNOWN"
    STALE = "STALE"
    CONFLICTED = "CONFLICTED"


@dataclass(frozen=True)
class EvidenceSubmission:
    """Untrusted evidence metadata received at the API boundary."""

    domain: str
    source_identity: str
    provenance: str
    observed_at: datetime
    digest: str
    payload: Mapping[str, object]
    tenant_id: str
    key_id: str
    nonce: str
    signature: str


@dataclass(frozen=True)
class VerifiedEvidence:
    """Evidence result created only by a configured verifier adapter."""

    domain: str
    source_identity: str
    trust: EvidenceTrust
    payload: Mapping[str, object]


class EvidenceVerifier(Protocol):
    @property
    def live_domains(self) -> frozenset[str]: ...

    async def verify(
        self, submission: EvidenceSubmission, principal: Principal
    ) -> VerifiedEvidence: ...


@dataclass(frozen=True)
class SafePolicyMatch:
    id: str
    version: str
    title: str
    owner: str
    severity: str
    frameworks: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class CombinedDecision:
    verdict: Literal["ALLOW", "WOULD-BLOCK", "BLOCK"]
    reason_codes: tuple[str, ...]
    policy_decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    policy_pack_version: str
    matched_rules: tuple[SafePolicyMatch, ...]
    evidence_degraded: bool


class PolicyActivationError(ValueError):
    """A rule pack cannot be truthfully activated with current live sources."""


class EvidenceRejectedError(ValueError):
    """Submitted evidence is malformed, untrusted, or attempts boundary override."""


class PolicyUnavailableError(Exception):
    """A required policy or evidence-verification dependency is unavailable."""


@dataclass(frozen=True)
class PolicyIntegration:
    pack: PolicyPack
    verifier: EvidenceVerifier
    freshness: timedelta = timedelta(minutes=5)
    future_skew: timedelta = timedelta(seconds=30)
    certified_rule_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        required = required_evidence_domains(self.pack)
        available = self.verifier.live_domains | SERVER_DERIVED_DOMAINS
        missing = required - available
        if missing:
            raise PolicyActivationError(
                f"policy pack requires unavailable live evidence domains: {sorted(missing)}"
            )
        gated = certification_gated_rule_ids(self.pack)
        uncertified = gated - self.certified_rule_ids
        unknown = self.certified_rule_ids - gated
        if unknown:
            raise PolicyActivationError(
                f"certification references unknown or ungated rules: {sorted(unknown)}"
            )
        if uncertified:
            raise PolicyActivationError(
                f"policy rules require approved live certification: {sorted(uncertified)}"
            )

    async def evaluate(
        self,
        *,
        principal: Principal,
        action_context: Mapping[str, object],
        evidence: tuple[EvidenceSubmission, ...],
        behavioral_verdict: str,
        mode: EnforcementMode,
        now: datetime,
    ) -> CombinedDecision:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("policy clock must be timezone-aware")
        context: dict[str, object] = {
            "identity": {
                "subject": principal.subject,
                "agent_id": principal.workload_id,
                "tenant_id": principal.tenant_id,
                "_evidence": EvidenceTrust.CONFIRMED.value,
            },
            "tenant": {
                "id": principal.tenant_id,
                "_evidence": EvidenceTrust.CONFIRMED.value,
            },
        }
        seen: set[str] = set()
        for submission in evidence:
            stale = self._validate_submission(submission, now)
            if submission.domain in SERVER_DERIVED_DOMAINS or submission.domain in seen:
                raise EvidenceRejectedError("evidence domain is duplicated or server-derived")
            verified = await self.verifier.verify(submission, principal)
            if (
                verified.domain != submission.domain
                or verified.source_identity != submission.source_identity
            ):
                raise EvidenceRejectedError("evidence verifier returned mismatched identity")
            if verified.payload != submission.payload:
                raise EvidenceRejectedError("evidence verifier returned mismatched payload")
            trust = EvidenceTrust.STALE if stale else verified.trust
            context[verified.domain] = {
                **dict(verified.payload),
                "_evidence": trust.value,
            }
            seen.add(verified.domain)

        if "action" not in seen:
            raise EvidenceRejectedError("verified action evidence is required")
        raw_action = context["action"]
        if not isinstance(raw_action, Mapping):
            raise EvidenceRejectedError("verified action evidence is malformed")
        verified_action = dict(raw_action)
        verified_action.pop("_evidence", None)
        if verified_action != dict(action_context):
            raise EvidenceRejectedError("verified action evidence does not match canonical action")

        for domain in required_evidence_domains(self.pack) - set(context):
            context[domain] = {"_evidence": EvidenceTrust.UNKNOWN.value}
        result = self.pack.evaluate(context)
        consequential = action_context.get("consequential") is not False
        return combine_decisions(
            behavioral_verdict=behavioral_verdict,
            policy=result,
            consequential=consequential,
            mode=mode,
        )

    def _validate_submission(self, submission: EvidenceSubmission, now: datetime) -> bool:
        if submission.domain not in self.verifier.live_domains:
            raise EvidenceRejectedError("evidence domain or source is not allow-listed")
        if submission.observed_at.tzinfo is None or submission.observed_at.utcoffset() is None:
            raise EvidenceRejectedError("evidence timestamp must be timezone-aware")
        observed = submission.observed_at.astimezone(UTC)
        stale = observed < now.astimezone(UTC) - self.freshness
        if observed > now.astimezone(UTC) + self.future_skew:
            raise EvidenceRejectedError("evidence timestamp is in the future")
        if _has_reserved_field(submission.payload):
            raise EvidenceRejectedError("reserved evidence fields are server-controlled")
        canonical = json.dumps(
            submission.payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
        expected = hashlib.sha256(canonical).hexdigest()
        if submission.digest != f"sha256:{expected}":
            raise EvidenceRejectedError("evidence digest does not match payload")
        return stale


def required_evidence_domains(pack: PolicyPack) -> frozenset[str]:
    """Return domain roots referenced by enforced rules."""
    return frozenset(
        condition.field.split(".", 1)[0]
        for rule in pack.rules
        if rule.status == "enforced"
        for condition in rule.conditions
    )


def certification_gated_rule_ids(pack: PolicyPack) -> frozenset[str]:
    """Return active provider rules that require reviewed live certification evidence."""
    return frozenset(
        rule.id
        for rule in pack.rules
        if rule.status == "enforced"
        and any(rule.id.startswith(prefix) for prefix in CERTIFICATION_GATED_RULE_PREFIXES)
    )


def combine_decisions(
    *,
    behavioral_verdict: str,
    policy: PolicyResult,
    consequential: bool,
    mode: EnforcementMode,
) -> CombinedDecision:
    """Apply the reviewed v2 precedence without relying on enum ordering."""
    reasons: list[str] = []
    verdict: Literal["ALLOW", "WOULD-BLOCK", "BLOCK"]
    policy_decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    if policy.decision is Decision.DENY:
        policy_decision = "DENY"
    elif policy.decision is Decision.REQUIRE_APPROVAL:
        policy_decision = "REQUIRE_APPROVAL"
    else:
        policy_decision = "ALLOW"
    if policy.decision is Decision.DENY:
        verdict = "BLOCK" if mode is EnforcementMode.ENFORCE else "WOULD-BLOCK"
        reasons.append(
            "EVIDENCE_DEGRADED" if policy.evidence_degraded and consequential else "POLICY_DENY"
        )
    elif policy.decision is Decision.REQUIRE_APPROVAL:
        verdict = "WOULD-BLOCK"
        reasons.append("APPROVAL_REQUIRED")
    elif policy.evidence_degraded and consequential:
        verdict = "BLOCK" if mode is EnforcementMode.ENFORCE else "WOULD-BLOCK"
        reasons.append("EVIDENCE_DEGRADED")
    elif behavioral_verdict in {"BLOCK", "WOULD-BLOCK"}:
        verdict = "BLOCK" if behavioral_verdict == "BLOCK" else "WOULD-BLOCK"
        reasons.append("BEHAVIORAL_THRESHOLD")
    elif behavioral_verdict == "ALLOW":
        verdict = "ALLOW"
    else:
        raise ValueError("behavioral evaluator returned an unsupported verdict")

    return CombinedDecision(
        verdict=verdict,
        reason_codes=tuple(reasons),
        policy_decision=policy_decision,
        policy_pack_version=policy.policy_version,
        matched_rules=tuple(_safe_match(rule) for rule in policy.matched_rules),
        evidence_degraded=policy.evidence_degraded,
    )


def _safe_match(rule: Rule) -> SafePolicyMatch:
    return SafePolicyMatch(
        id=rule.id,
        version=rule.version,
        title=rule.title,
        owner=rule.owner,
        severity=rule.severity,
        frameworks=rule.frameworks,
        reason=rule.rationale,
    )


def _has_reserved_field(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            str(key).startswith("_") or _has_reserved_field(child) for key, child in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_has_reserved_field(child) for child in value)
    return False
