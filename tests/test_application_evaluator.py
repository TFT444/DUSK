"""Canonical evaluator port, ordering, and shadow-isolation tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

import pytest

from dusk.application.evaluator import (
    BehavioralDecision,
    CanonicalEvaluator,
    DecisionWrite,
    DeliveryIntent,
    EvaluationMode,
    EvaluationPrincipal,
    EvaluatorPorts,
    ExtractedEntity,
    OffenseWrite,
    PolicyDecision,
)


@dataclass(frozen=True)
class _Action:
    agent_id: str = "agent-1"
    action_type: str = "role_assignment"
    target: str = "role-owner-self"


@dataclass
class _Clock:
    value: datetime = datetime(2026, 8, 31, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value


class _TraceIds:
    def new(self) -> str:
        return "trace-1"


@dataclass
class _Identity:
    calls: int = 0
    reject: bool = False

    def authorize(self, principal: EvaluationPrincipal, action: _Action) -> None:
        self.calls += 1
        if self.reject:
            raise PermissionError("denied")


@dataclass
class _Semantic:
    embeds: list[str] = field(default_factory=list)

    def extract(self, text: str) -> list[ExtractedEntity]:
        return []

    def score(self, query: str, candidates: list[str]) -> list[float] | None:
        return None

    def embed(self, text: str) -> list[float]:
        self.embeds.append(text)
        return [1.0, 0.0]


@dataclass
class _Behavioral:
    calls: int = 0
    offense_counts: list[int] = field(default_factory=list)

    def evaluate(self, action: _Action, **context: object) -> BehavioralDecision:
        self.calls += 1
        offenses = context["offenses"]
        assert isinstance(offenses, list)
        self.offense_counts.append(len(offenses))
        return BehavioralDecision(
            trace_id=str(context["trace_id"]),
            verdict="WOULD-BLOCK",
            score=0.85,
            blast_radius="high",
            reasons=("behavioral refusal",),
            mitre_attack="T1098 Account Manipulation",
            mitre_atlas="AML.T0051 LLM Prompt Injection",
            predicted_next="expect privilege use",
            target_class="role",
            target_tokens=frozenset({"role", "owner", "self"}),
        )


@dataclass
class _Offenses:
    reads: int = 0
    writes: list[OffenseWrite] = field(default_factory=list)

    def offenses_for(self, agent_id: str) -> list[object]:
        self.reads += 1
        return [object()]

    def record(self, offense: OffenseWrite) -> None:
        self.writes.append(offense)


@dataclass
class _Policy:
    calls: int = 0

    def evaluate(
        self,
        principal: EvaluationPrincipal,
        action: _Action,
        behavioral: BehavioralDecision,
    ) -> PolicyDecision:
        self.calls += 1
        return PolicyDecision(verdict=behavioral.verdict)


@dataclass
class _Persistence:
    reads: int = 0
    writes: list[tuple[DecisionWrite, list[float]]] = field(default_factory=list)

    def find_similar(self, agent_id: str, action_text: str) -> list[str]:
        self.reads += 1
        return ["prior-trace"]

    def record(self, decision: DecisionWrite, embedding: list[float]) -> None:
        self.writes.append((decision, embedding))


@dataclass
class _Delivery:
    intents: list[DeliveryIntent] = field(default_factory=list)

    def publish(self, intent: DeliveryIntent) -> None:
        self.intents.append(intent)


def _evaluator() -> tuple[CanonicalEvaluator, dict[str, object]]:
    values: dict[str, object] = {
        "clock": _Clock(),
        "identity": _Identity(),
        "semantic": _Semantic(),
        "behavioral": _Behavioral(),
        "offenses": _Offenses(),
        "policy": _Policy(),
        "persistence": _Persistence(),
        "delivery": _Delivery(),
    }
    evaluator = CanonicalEvaluator(
        EvaluatorPorts(
            clock=values["clock"],  # type: ignore[arg-type]
            trace_ids=_TraceIds(),
            identity=values["identity"],  # type: ignore[arg-type]
            semantic=values["semantic"],  # type: ignore[arg-type]
            behavioral=values["behavioral"],  # type: ignore[arg-type]
            offenses=values["offenses"],  # type: ignore[arg-type]
            policy=values["policy"],  # type: ignore[arg-type]
            persistence=values["persistence"],  # type: ignore[arg-type]
            delivery=values["delivery"],  # type: ignore[arg-type]
        )
    )
    return evaluator, values


def _principal() -> EvaluationPrincipal:
    return EvaluationPrincipal("tenant-1", "workload-1", "workload")


def test_active_evaluation_commits_each_explicit_effect_once() -> None:
    evaluator, ports = _evaluator()
    output = evaluator.evaluate(_Action(), _principal())

    assert output.response == {
        "trace_id": "trace-1",
        "verdict": "WOULD-BLOCK",
        "score": 0.85,
        "blast": "high",
        "mitre_attack": ["T1098 Account Manipulation"],
        "mitre_atlas": ["AML.T0051 LLM Prompt Injection"],
        "reasons": ["behavioral refusal"],
        "predicted_next": "expect privilege use",
        "similar_decision_ids": ["prior-trace"],
    }
    assert ports["identity"].calls == 1  # type: ignore[attr-defined]
    assert ports["offenses"].reads == 1  # type: ignore[attr-defined]
    assert len(ports["offenses"].writes) == 1  # type: ignore[attr-defined]
    assert ports["persistence"].reads == 1  # type: ignore[attr-defined]
    assert len(ports["persistence"].writes) == 1  # type: ignore[attr-defined]
    assert ports["semantic"].embeds == [  # type: ignore[attr-defined]
        "agent-1 role_assignment role-owner-self"
    ]
    assert [intent.kind for intent in ports["delivery"].intents] == [  # type: ignore[attr-defined]
        "decision",
        "report",
        "alert",
    ]


def test_shadow_evaluation_has_zero_stateful_or_external_effects() -> None:
    evaluator, ports = _evaluator()
    output = evaluator.evaluate(_Action(), _principal(), mode=EvaluationMode.SHADOW)

    assert output.mode is EvaluationMode.SHADOW
    assert output.response["similar_decision_ids"] == []
    assert ports["offenses"].reads == 0  # type: ignore[attr-defined]
    assert ports["offenses"].writes == []  # type: ignore[attr-defined]
    assert ports["persistence"].reads == 0  # type: ignore[attr-defined]
    assert ports["persistence"].writes == []  # type: ignore[attr-defined]
    assert ports["semantic"].embeds == []  # type: ignore[attr-defined]
    assert ports["delivery"].intents == []  # type: ignore[attr-defined]
    assert [intent.kind for intent in output.delivery_intents] == [
        "decision",
        "report",
        "alert",
    ]


def test_identity_failure_stops_before_analysis_or_effects() -> None:
    evaluator, ports = _evaluator()
    ports["identity"].reject = True  # type: ignore[attr-defined]

    with pytest.raises(PermissionError, match="denied"):
        evaluator.evaluate(_Action(), _principal())

    assert ports["behavioral"].calls == 0  # type: ignore[attr-defined]
    assert ports["offenses"].reads == 0  # type: ignore[attr-defined]
    assert ports["persistence"].writes == []  # type: ignore[attr-defined]
    assert ports["delivery"].intents == []  # type: ignore[attr-defined]


def test_clock_must_return_timezone_aware_instant() -> None:
    evaluator, ports = _evaluator()
    ports["clock"].value = datetime(2026, 8, 31, 12, 0)  # type: ignore[attr-defined]
    with pytest.raises(ValueError, match="timezone-aware"):
        evaluator.evaluate(_Action(), _principal())
