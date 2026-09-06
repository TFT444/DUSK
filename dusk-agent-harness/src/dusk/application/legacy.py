"""Legacy v1 adapters for the framework-neutral canonical evaluator."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from dusk.application.evaluator import (
    ActionView,
    BehavioralDecision,
    DecisionPersistencePort,
    DecisionWrite,
    DeliveryIntent,
    EvaluationPrincipal,
    ExtractedEntity,
    IdentityPort,
    OffenseMemoryPort,
    OffenseWrite,
    PolicyDecision,
    PolicyPort,
    SemanticEnrichmentPort,
)


class LegacyClock:
    """UTC clock routed through the legacy offense module for test compatibility."""

    def now(self) -> datetime:
        from dusk.actions.offense_memory import utc_now

        return utc_now()


class LegacyTraceIds:
    """Generate trace IDs through the historical monkeypatch boundary."""

    def new(self) -> str:
        from dusk.actions.verdict import new_trace_id

        return new_trace_id()


class AuthenticatedV1Identity(IdentityPort):
    """Mark identity as already authenticated by the frozen HTTP adapter."""

    def authorize(self, principal: EvaluationPrincipal, action: ActionView) -> None:
        if principal.identity_kind != "legacy-workload":
            raise PermissionError("legacy v1 identity was not authenticated")


class SieSemanticEnrichment(SemanticEnrichmentPort):
    """Expose SIE and its deterministic fallback through an explicit port."""

    def extract(self, text: str) -> list[ExtractedEntity]:
        from dusk.trace.vector import sie_extract

        return [
            ExtractedEntity(text=value.text, label=value.label, score=value.score)
            for value in sie_extract(text)
        ]

    def score(self, query: str, candidates: list[str]) -> list[float] | None:
        from dusk.trace.vector import sie_score

        return sie_score(query, candidates)

    def embed(self, text: str) -> list[float]:
        from dusk.trace.vector import embed_text

        return embed_text(text)


class LegacyBehavioralAnalysis:
    """Adapt ActionGate preview evaluation without mutating offense memory."""

    def __init__(self, gate: object) -> None:
        self._gate = gate

    def evaluate(
        self,
        action: ActionView,
        *,
        offenses: list[object],
        semantic: SemanticEnrichmentPort,
        observed_at: datetime,
        trace_id: str,
    ) -> BehavioralDecision:
        from dusk.actions.baseline import action_features
        from dusk.actions.event import AgentAction
        from dusk.actions.verdict import ActionGate

        if not isinstance(self._gate, ActionGate) or not isinstance(action, AgentAction):
            raise TypeError("legacy behavioral adapter requires ActionGate and AgentAction")
        verdict = self._gate.preview(
            action,
            offenses=offenses,
            semantic=semantic,
            observed_at=observed_at,
            trace_id=trace_id,
        )
        analysis = verdict.analysis
        features = action_features(action)
        return BehavioralDecision(
            trace_id=verdict.trace_id,
            verdict=verdict.verdict,
            score=analysis.score,
            blast_radius=analysis.blast_radius,
            reasons=tuple(analysis.reasons),
            mitre_attack=analysis.mitre_attack,
            mitre_atlas=analysis.mitre_atlas,
            predicted_next=analysis.predicted_next,
            target_class=features["target_class"],
            target_tokens=frozenset(features["tokens"]),
        )


class LegacyOffenseMemory(OffenseMemoryPort):
    """Adapt the bounded v1 offense store to canonical writes."""

    def __init__(self, memory: object) -> None:
        self._memory = memory

    def offenses_for(self, agent_id: str) -> list[object]:
        from dusk.actions.offense_memory import OffenseMemory

        if not isinstance(self._memory, OffenseMemory):
            raise TypeError("legacy offense adapter requires OffenseMemory")
        return list(self._memory.offenses_for(agent_id))

    def record(self, offense: OffenseWrite) -> None:
        from dusk.actions.offense_memory import OffenseMemory

        if not isinstance(self._memory, OffenseMemory):
            raise TypeError("legacy offense adapter requires OffenseMemory")
        self._memory.record(
            trace_id=offense.trace_id,
            agent_id=offense.agent_id,
            action_type=offense.action_type,
            target_class=offense.target_class,
            tokens=set(offense.tokens),
            verdict=offense.verdict,
            timestamp=offense.occurred_at,
        )


class BehavioralPassthroughPolicy(PolicyPort):
    """Preserve the frozen v1 verdict until policy integration issue #196."""

    def evaluate(
        self,
        principal: EvaluationPrincipal,
        action: ActionView,
        behavioral: BehavioralDecision,
    ) -> PolicyDecision:
        return PolicyDecision(verdict=behavioral.verdict)


class LegacyDecisionPersistence(DecisionPersistencePort):
    """Adapt capped in-memory v1 decision history through callbacks."""

    def __init__(
        self,
        find: Callable[[str, str], list[str]],
        record: Callable[[DecisionWrite, list[float]], None],
    ) -> None:
        self._find = find
        self._record = record

    def find_similar(self, agent_id: str, action_text: str) -> list[str]:
        return self._find(agent_id, action_text)

    def record(self, decision: DecisionWrite, embedding: list[float]) -> None:
        self._record(decision, embedding)


class LegacyWebhookDelivery:
    """Dispatch canonical delivery intents through legacy webhook functions."""

    def __init__(self, publishers: dict[str, Callable[[dict[str, object]], None]]) -> None:
        self._publishers = dict(publishers)

    def publish(self, intent: DeliveryIntent) -> None:
        publisher = self._publishers.get(intent.kind)
        if publisher is None:
            raise ValueError(f"unsupported delivery intent: {intent.kind}")
        publisher(intent.payload)
