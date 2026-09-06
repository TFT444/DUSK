"""Framework-neutral orchestration for DUSK action evaluations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable


class EvaluationMode(StrEnum):
    """Whether an evaluation may commit externally observable effects."""

    ACTIVE = "active"
    SHADOW = "shadow"


@dataclass(frozen=True)
class EvaluationPrincipal:
    """Trusted identity context supplied by an authentication adapter."""

    tenant_id: str
    principal_id: str
    identity_kind: str


@dataclass(frozen=True)
class ExtractedEntity:
    """Provider-neutral semantic entity."""

    text: str
    label: str
    score: float


@dataclass(frozen=True)
class BehavioralDecision:
    """Side-effect-free behavioral result returned to the orchestrator."""

    trace_id: str
    verdict: str
    score: float
    blast_radius: str
    reasons: tuple[str, ...]
    mitre_attack: str
    mitre_atlas: str
    predicted_next: str
    target_class: str
    target_tokens: frozenset[str]

    @property
    def refused(self) -> bool:
        return self.verdict != "ALLOW"


@dataclass(frozen=True)
class PolicyDecision:
    """Policy result; passthrough adapters retain the behavioral verdict."""

    verdict: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class OffenseWrite:
    """Minimal refused-action state written after a committed evaluation."""

    trace_id: str
    agent_id: str
    action_type: str
    target_class: str
    tokens: frozenset[str]
    verdict: str
    occurred_at: datetime


@dataclass(frozen=True)
class DecisionWrite:
    """Canonical decision evidence supplied to a persistence adapter."""

    trace_id: str
    principal: EvaluationPrincipal
    agent_id: str
    action_type: str
    target: str
    action_text: str
    verdict: str
    score: float
    blast_radius: str
    reasons: tuple[str, ...]
    mitre_attack: str
    mitre_atlas: str
    predicted_next: str
    similar_decision_ids: tuple[str, ...]
    occurred_at: datetime


@dataclass(frozen=True)
class DeliveryIntent:
    """A requested delivery, not evidence that downstream execution occurred."""

    kind: str
    payload: dict[str, object]


@dataclass(frozen=True)
class EvaluationOutput:
    """Canonical response plus intents produced by one evaluation."""

    response: dict[str, object]
    decision: DecisionWrite
    delivery_intents: tuple[DeliveryIntent, ...]
    mode: EvaluationMode


@runtime_checkable
class ActionView(Protocol):
    @property
    def agent_id(self) -> str:
        """Stable agent identifier."""

    @property
    def action_type(self) -> str:
        """Normalized action type."""

    @property
    def target(self) -> str:
        """Redacted action target."""


class ClockPort(Protocol):
    def now(self) -> datetime:
        """Return an aware UTC instant."""


class TraceIdPort(Protocol):
    def new(self) -> str:
        """Return a new trace identifier."""


class IdentityPort(Protocol):
    def authorize(self, principal: EvaluationPrincipal, action: ActionView) -> None:
        """Reject when the trusted principal may not evaluate the action."""


class SemanticEnrichmentPort(Protocol):
    def extract(self, text: str) -> list[ExtractedEntity]:
        """Extract provider-neutral entities or return an empty list."""

    def score(self, query: str, candidates: list[str]) -> list[float] | None:
        """Return aligned similarity scores or None when unavailable."""

    def embed(self, text: str) -> list[float]:
        """Return a stable vector, using a deterministic fallback if needed."""


class BehavioralAnalysisPort(Protocol):
    def evaluate(
        self,
        action: ActionView,
        *,
        offenses: list[object],
        semantic: SemanticEnrichmentPort,
        observed_at: datetime,
        trace_id: str,
    ) -> BehavioralDecision:
        """Return a behavioral decision without mutating durable state."""


class OffenseMemoryPort(Protocol):
    def offenses_for(self, agent_id: str) -> list[object]:
        """Return prior refused actions for one agent."""

    def record(self, offense: OffenseWrite) -> None:
        """Persist one refused action."""


class PolicyPort(Protocol):
    def evaluate(
        self,
        principal: EvaluationPrincipal,
        action: ActionView,
        behavioral: BehavioralDecision,
    ) -> PolicyDecision:
        """Return the policy verdict for this trusted context."""


class DecisionPersistencePort(Protocol):
    def find_similar(self, agent_id: str, action_text: str) -> list[str]:
        """Return stable references to similar committed decisions."""

    def record(self, decision: DecisionWrite, embedding: list[float]) -> None:
        """Persist one committed decision and its precomputed embedding."""


class DeliveryPort(Protocol):
    def publish(self, intent: DeliveryIntent) -> None:
        """Publish one intent without claiming downstream execution."""


@dataclass(frozen=True)
class EvaluatorPorts:
    """All trust and side-effect boundaries required by the evaluator."""

    clock: ClockPort
    trace_ids: TraceIdPort
    identity: IdentityPort
    semantic: SemanticEnrichmentPort
    behavioral: BehavioralAnalysisPort
    offenses: OffenseMemoryPort
    policy: PolicyPort
    persistence: DecisionPersistencePort
    delivery: DeliveryPort


@dataclass
class CanonicalEvaluator:
    """Orchestrate one evaluation while making every effect explicit."""

    ports: EvaluatorPorts
    _allowed_policy_verdicts: frozenset[str] = field(
        default=frozenset({"ALLOW", "WOULD-BLOCK", "BLOCK"}), init=False
    )

    def evaluate(
        self,
        action: ActionView,
        principal: EvaluationPrincipal,
        *,
        mode: EvaluationMode = EvaluationMode.ACTIVE,
    ) -> EvaluationOutput:
        self.ports.identity.authorize(principal, action)
        observed_at = self.ports.clock.now()
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("clock port must return a timezone-aware instant")

        trace_id = self.ports.trace_ids.new()
        offenses = (
            self.ports.offenses.offenses_for(action.agent_id)
            if mode is EvaluationMode.ACTIVE
            else []
        )
        behavioral = self.ports.behavioral.evaluate(
            action,
            offenses=offenses,
            semantic=self.ports.semantic,
            observed_at=observed_at,
            trace_id=trace_id,
        )
        policy = self.ports.policy.evaluate(principal, action, behavioral)
        if policy.verdict not in self._allowed_policy_verdicts:
            raise ValueError("policy port returned an unsupported verdict")

        reasons = behavioral.reasons + policy.reasons
        action_text = f"{action.action_type} {action.target}"
        similar_ids = (
            tuple(self.ports.persistence.find_similar(action.agent_id, action_text))
            if mode is EvaluationMode.ACTIVE
            else ()
        )
        response: dict[str, object] = {
            "trace_id": trace_id,
            "verdict": policy.verdict,
            "score": round(behavioral.score, 4),
            "blast": behavioral.blast_radius,
            "mitre_attack": [behavioral.mitre_attack] if behavioral.mitre_attack else [],
            "mitre_atlas": [behavioral.mitre_atlas] if behavioral.mitre_atlas else [],
            "reasons": list(reasons),
            "predicted_next": behavioral.predicted_next,
            "similar_decision_ids": list(similar_ids),
        }
        decision = DecisionWrite(
            trace_id=trace_id,
            principal=principal,
            agent_id=action.agent_id,
            action_type=action.action_type,
            target=action.target,
            action_text=action_text,
            verdict=policy.verdict,
            score=behavioral.score,
            blast_radius=behavioral.blast_radius,
            reasons=reasons,
            mitre_attack=behavioral.mitre_attack,
            mitre_atlas=behavioral.mitre_atlas,
            predicted_next=behavioral.predicted_next,
            similar_decision_ids=similar_ids,
            occurred_at=observed_at,
        )
        webhook_payload = {
            **response,
            "agent_id": action.agent_id,
            "action_type": action.action_type,
            "target": action.target,
        }
        intents = (
            DeliveryIntent("decision", webhook_payload),
            DeliveryIntent("report", webhook_payload),
            *((DeliveryIntent("alert", webhook_payload),) if policy.verdict != "ALLOW" else ()),
        )

        if mode is EvaluationMode.ACTIVE:
            if policy.verdict != "ALLOW":
                self.ports.offenses.record(
                    OffenseWrite(
                        trace_id=trace_id,
                        agent_id=action.agent_id,
                        action_type=action.action_type,
                        target_class=behavioral.target_class,
                        tokens=behavioral.target_tokens,
                        verdict=policy.verdict,
                        occurred_at=observed_at,
                    )
                )
            self.ports.persistence.record(
                decision, self.ports.semantic.embed(f"{action.agent_id} {action_text}")
            )
            for intent in intents:
                self.ports.delivery.publish(intent)

        return EvaluationOutput(
            response=response,
            decision=decision,
            delivery_intents=intents,
            mode=mode,
        )
