"""Authenticated v2 evaluation application service and API models."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal, Protocol

from dusk.application import BehavioralDecision
from pydantic import BaseModel, ConfigDict, Field

from dusk_control_plane.identity import Principal
from dusk_control_plane.observability import Telemetry
from dusk_control_plane.policy import (
    CombinedDecision,
    EnforcementMode,
    EvidenceSubmission,
    PolicyIntegration,
    SafePolicyMatch,
)

INSTRUMENTED_EVALUATION_STAGES = ("normalization", "behavioral", "policy")


class EvaluationUnavailableError(Exception):
    """A mandatory evaluation dependency is unavailable."""


class EvaluationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CanonicalAction(EvaluationModel):
    agent_id: str = Field(min_length=1, max_length=200)
    action_type: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=1000)
    consequential: bool
    attributes: dict[str, object] = Field(default_factory=dict)


class EvidenceEnvelope(EvaluationModel):
    domain: str = Field(pattern=r"^[a-z][a-z_]{0,31}$")
    source_identity: str = Field(min_length=1, max_length=200)
    provenance: str = Field(min_length=1, max_length=500)
    observed_at: datetime
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    payload: dict[str, object]
    tenant_id: str = Field(min_length=1, max_length=200)
    key_id: str = Field(min_length=1, max_length=200)
    nonce: str = Field(min_length=16, max_length=200)
    signature: str = Field(min_length=80, max_length=128)


class EvaluationRequest(EvaluationModel):
    action: CanonicalAction
    evidence: tuple[EvidenceEnvelope, ...] = Field(min_length=1, max_length=16)
    idempotency_key: str = Field(min_length=1, max_length=200)


class PolicyMatchResponse(EvaluationModel):
    id: str
    version: str
    title: str
    owner: str
    severity: str
    frameworks: tuple[str, ...]
    reason: str


class PipelineTimings(EvaluationModel):
    normalization_ms: float = Field(default=0, ge=0)
    baseline_ms: float | None = Field(default=None, ge=0)
    behavioral_ms: float = Field(ge=0)
    sie_ms: float | None = Field(default=None, ge=0)
    policy_ms: float = Field(ge=0)
    persistence_ms: float | None = Field(default=None, ge=0)
    audit_ms: float | None = Field(default=None, ge=0)
    total_ms: float = Field(ge=0)


class EvaluationResponse(EvaluationModel):
    trace_id: str
    verdict: Literal["ALLOW", "WOULD-BLOCK", "BLOCK"]
    behavioral_score: float = Field(ge=0, le=1)
    blast_radius: str
    reasons: tuple[str, ...]
    reason_codes: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    mitre_atlas: tuple[str, ...]
    predicted_next: str
    policy_decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    policy_pack_version: str
    matched_rules: tuple[PolicyMatchResponse, ...]
    evidence_degraded: bool
    response_status: Literal["DECIDED", "DELIVERY_PENDING"]
    pipeline_timings: PipelineTimings
    similar_decision_ids: tuple[str, ...]


class BehavioralEvaluator(Protocol):
    async def evaluate(
        self, action: CanonicalAction, principal: Principal
    ) -> BehavioralDecision: ...


class EvaluationService(Protocol):
    async def evaluate(
        self, request: EvaluationRequest, principal: Principal
    ) -> EvaluationResponse: ...


class PolicyEvaluationService:
    """Combine a trusted behavioral decision with verified policy evidence."""

    def __init__(
        self,
        policy: PolicyIntegration,
        behavioral: BehavioralEvaluator,
        *,
        mode: EnforcementMode,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        telemetry: Telemetry | None = None,
    ) -> None:
        self._policy = policy
        self._behavioral = behavioral
        self._mode = mode
        self._clock = clock
        self._telemetry = telemetry

    def with_telemetry(self, telemetry: Telemetry) -> PolicyEvaluationService:
        return PolicyEvaluationService(
            self._policy,
            self._behavioral,
            mode=self._mode,
            clock=self._clock,
            telemetry=telemetry,
        )

    async def evaluate(
        self, request: EvaluationRequest, principal: Principal
    ) -> EvaluationResponse:
        started = time.perf_counter()
        if self._telemetry is None:
            action_context, submissions = self._normalize(request, principal)
        else:
            with self._telemetry.stage("normalization"):
                action_context, submissions = self._normalize(request, principal)
        after_normalization = time.perf_counter()
        if self._telemetry is None:
            behavioral = await self._behavioral.evaluate(request.action, principal)
        else:
            with self._telemetry.stage("behavioral"):
                behavioral = await self._behavioral.evaluate(request.action, principal)
        after_behavioral = time.perf_counter()
        if self._telemetry is None:
            combined = await self._evaluate_policy(
                principal, action_context, submissions, behavioral.verdict
            )
        else:
            with self._telemetry.stage("policy", decision_trace_id=behavioral.trace_id):
                combined = await self._evaluate_policy(
                    principal, action_context, submissions, behavioral.verdict
                )
        finished = time.perf_counter()
        return EvaluationResponse(
            trace_id=behavioral.trace_id,
            verdict=combined.verdict,
            behavioral_score=round(behavioral.score, 4),
            blast_radius=behavioral.blast_radius,
            reasons=behavioral.reasons,
            reason_codes=combined.reason_codes,
            mitre_attack=(behavioral.mitre_attack,) if behavioral.mitre_attack else (),
            mitre_atlas=(behavioral.mitre_atlas,) if behavioral.mitre_atlas else (),
            predicted_next=behavioral.predicted_next,
            policy_decision=combined.policy_decision,
            policy_pack_version=combined.policy_pack_version,
            matched_rules=tuple(_match(value) for value in combined.matched_rules),
            evidence_degraded=combined.evidence_degraded,
            response_status="DECIDED",
            pipeline_timings=PipelineTimings(
                normalization_ms=(after_normalization - started) * 1000,
                behavioral_ms=(after_behavioral - after_normalization) * 1000,
                policy_ms=(finished - after_behavioral) * 1000,
                total_ms=(finished - started) * 1000,
            ),
            similar_decision_ids=(),
        )

    @staticmethod
    def _normalize(
        request: EvaluationRequest, principal: Principal
    ) -> tuple[dict[str, object], tuple[EvidenceSubmission, ...]]:
        return (
            {
                "type": request.action.action_type,
                "target": request.action.target,
                "consequential": request.action.consequential,
                "tenant_id": principal.tenant_id,
                **request.action.attributes,
            },
            tuple(
                EvidenceSubmission(
                    domain=value.domain,
                    source_identity=value.source_identity,
                    provenance=value.provenance,
                    observed_at=value.observed_at,
                    digest=value.digest,
                    payload=value.payload,
                    tenant_id=value.tenant_id,
                    key_id=value.key_id,
                    nonce=value.nonce,
                    signature=value.signature,
                )
                for value in request.evidence
            ),
        )

    async def _evaluate_policy(
        self,
        principal: Principal,
        action_context: dict[str, object],
        submissions: tuple[EvidenceSubmission, ...],
        behavioral_verdict: str,
    ) -> CombinedDecision:
        return await self._policy.evaluate(
            principal=principal,
            action_context=action_context,
            evidence=submissions,
            behavioral_verdict=behavioral_verdict,
            mode=self._mode,
            now=self._clock(),
        )


def _match(value: SafePolicyMatch) -> PolicyMatchResponse:
    return PolicyMatchResponse(**value.__dict__)
