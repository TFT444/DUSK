"""Render ALLOW, WOULD-BLOCK, or BLOCK from behavioral analysis."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from dusk.actions.analyse import AnalysisResult, analyse
from dusk.actions.baseline import Baseline, action_features
from dusk.actions.event import AgentAction
from dusk.config import Config, get_config

if TYPE_CHECKING:
    from dusk.actions.offense_memory import OffenseMemory, OffenseRecord
    from dusk.application.evaluator import SemanticEnrichmentPort

logger = logging.getLogger("dusk.actions.verdict")

#: Verdict strings.
ALLOW = "ALLOW"
WOULD_BLOCK = "WOULD-BLOCK"
BLOCK = "BLOCK"


def new_trace_id() -> str:
    """Return a trace identifier through the historical UUID patch boundary."""
    return uuid.uuid4().hex


@dataclass
class GateVerdict:
    """A gate decision about a single action.

    Attributes:
        verdict: One of ``ALLOW``, ``WOULD-BLOCK``, ``BLOCK``.
        analysis: The :class:`AnalysisResult` the verdict is based on.
        trace_id: Unique id for this decision, generated once here so every
            downstream consumer (the HTTP response, offense memory, n8n
            webhooks) cites the same identifier for the same decision.
    """

    verdict: str
    analysis: AnalysisResult
    trace_id: str = field(default_factory=new_trace_id)

    @property
    def refused(self) -> bool:
        """True when the action was not allowed."""
        return self.verdict != ALLOW

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the verdict."""
        return {"trace_id": self.trace_id, "verdict": self.verdict, **self.analysis.to_dict()}


class ActionGate:
    """Inline gate: learn normal behaviour, then judge new actions."""

    def __init__(
        self,
        baseline: Baseline | None = None,
        config: Config | None = None,
        enforce: bool = False,
        offense_memory: OffenseMemory | None = None,
    ) -> None:
        """Create the gate.

        Args:
            baseline: A pre-learned baseline, or ``None`` to start empty and
                learn with :meth:`learn`.
            config: Configuration providing ``gate_block_threshold``. Defaults
                to the process-wide singleton.
            enforce: When ``True``, refused actions are BLOCK; otherwise they
                are WOULD-BLOCK (watch mode).
            offense_memory: Persisted per-agent record of past refusals, used
                for the repeat-offense scoring signal. When ``None``, that
                signal is skipped entirely -- every evaluation behaves as it
                did before this store existed.
        """
        self.config = config if config is not None else get_config()
        self.baseline = baseline if baseline is not None else Baseline()
        self.enforce = enforce
        self.offense_memory = offense_memory
        self._history: dict[str, list[AgentAction]] = {}

    def learn(self, actions: list[AgentAction]) -> None:
        """Fold known-good actions into the baseline."""
        for action in actions:
            self.baseline.observe(action)
            self._history.setdefault(action.agent_id, []).append(action)
        logger.info(
            "gate baseline learned: %d agent(s) from %d action(s)",
            len(self.baseline),
            len(actions),
        )

    def evaluate(self, action: AgentAction) -> GateVerdict:
        """Analyse one action and render a verdict."""
        offenses = (
            self.offense_memory.offenses_for(action.agent_id) if self.offense_memory else None
        )
        gate_verdict = self.preview(action, offenses=offenses)
        if gate_verdict.refused and self.offense_memory is not None:
            features = action_features(action)
            self.offense_memory.record(
                trace_id=gate_verdict.trace_id,
                agent_id=action.agent_id,
                action_type=action.action_type,
                target_class=features["target_class"],
                tokens=features["tokens"],
                verdict=gate_verdict.verdict,
            )
        return gate_verdict

    def preview(
        self,
        action: AgentAction,
        *,
        offenses: list[OffenseRecord] | list[object] | None = None,
        semantic: SemanticEnrichmentPort | None = None,
        observed_at: datetime | None = None,
        trace_id: str | None = None,
    ) -> GateVerdict:
        """Evaluate without updating offense memory or any external state."""
        result = analyse(
            self.baseline,
            action,
            agent_history=self._history.get(action.agent_id),
            offenses=offenses,  # type: ignore[arg-type]
            config=self.config,
            semantic=semantic,
            observed_at=observed_at,
        )
        if result.score >= self.config.gate_block_threshold:
            verdict = BLOCK if self.enforce else WOULD_BLOCK
            logger.error(
                "gate refused: verdict=%s agent=%s action_type=%s target=%s "
                "score=%.2f attack=%s atlas=%s blast=%s",
                verdict,
                result.agent_id,
                result.action_type,
                result.target,
                result.score,
                result.mitre_attack,
                result.mitre_atlas,
                result.blast_radius,
            )
        else:
            verdict = ALLOW
        if trace_id is None:
            return GateVerdict(verdict=verdict, analysis=result)
        return GateVerdict(verdict=verdict, analysis=result, trace_id=trace_id)

    def evaluate_all(self, actions: list[AgentAction]) -> list[GateVerdict]:
        """Evaluate a sequence of actions in order."""
        return [self.evaluate(action) for action in actions]
