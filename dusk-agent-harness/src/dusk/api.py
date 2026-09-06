from __future__ import annotations

import logging
import os
import threading
from typing import TYPE_CHECKING

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS

from dusk.auth import gate_request_is_authorized

if TYPE_CHECKING:
    from dusk.actions.verdict import ActionGate
    from dusk.application.evaluator import (
        CanonicalEvaluator,
        DecisionWrite,
        SemanticEnrichmentPort,
    )
    from dusk.trace.models import TraceDecision

load_dotenv()

app = Flask(__name__)
_cors_origins = [
    origin.strip()
    for origin in os.getenv("DUSK_CORS_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]
if _cors_origins:
    CORS(
        app,
        origins=_cors_origins,
        methods=["POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
# Bound public input without constraining normal AgentAction payloads.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_gate_engine: ActionGate | None = None
_gate_lock = threading.Lock()

#: Baseline failure exposed by the health endpoint.
_baseline_load_error: str | None = None


def _load_gate_engine() -> ActionGate:
    from dusk.actions.ingest import ingest_file
    from dusk.actions.offense_memory import OffenseMemory
    from dusk.actions.verdict import ActionGate
    from dusk.config import get_config

    global _baseline_load_error
    _baseline_load_error = None

    baseline_path = os.getenv("DUSK_GATE_BASELINE_PATH", "")
    baseline_source = os.getenv("DUSK_GATE_BASELINE_SOURCE", "generic")

    config = get_config()
    offense_memory = OffenseMemory(storage_path=config.offense_memory_path or None)
    gate_engine = ActionGate(config=config, enforce=config.enforce, offense_memory=offense_memory)
    if baseline_path:
        try:
            known_good = ingest_file(baseline_path, baseline_source)
            gate_engine.learn(known_good)
        except (FileNotFoundError, ValueError) as exc:
            _baseline_load_error = str(exc)
            logger.error(
                "gate baseline could not be loaded from %s: %s -- every agent will read as "
                "unknown until this is fixed and the process restarts",
                baseline_path,
                exc,
            )
    else:
        logger.warning(
            "DUSK_GATE_BASELINE_PATH not set; gate has no baseline, every agent is unknown"
        )
    return gate_engine


def _get_gate_engine() -> ActionGate:
    # Live traffic never updates the trusted baseline; doing so would permit
    # gradual baseline poisoning.
    global _gate_engine
    if _gate_engine is None:
        with _gate_lock:
            if _gate_engine is None:
                _gate_engine = _load_gate_engine()
    return _gate_engine


def reset_gate_engine() -> None:
    """Clear the cached gate engine so the next request reloads it. Test-only hook."""
    global _gate_engine
    with _gate_lock:
        _gate_engine = None


#: Capped decision history with embeddings computed at record time.
_DECISION_HISTORY_CAP = 200
#: Per-agent sub-cap so one noisy agent can't evict the whole fleet's candidates.
_DECISION_HISTORY_PER_AGENT_CAP = 40
_decision_history: list[tuple[TraceDecision, list[float]]] = []
_decision_history_lock = threading.Lock()


def reset_decision_history() -> None:
    """Clear recorded decisions used for similarity lookups. Test-only hook."""
    with _decision_history_lock:
        _decision_history.clear()


def _find_similar_decisions(
    agent_id: str,
    action_text: str,
    semantic: SemanticEnrichmentPort | None = None,
) -> list[str]:
    from dusk.trace.vector import find_similar_cached

    with _decision_history_lock:
        history_snapshot = list(_decision_history)
    similar = (
        find_similar_cached(
            action_text,
            agent_id,
            history_snapshot,
            top_k=3,
            embedder=semantic.embed,
            scorer=semantic.score,
        )
        if semantic is not None
        else find_similar_cached(action_text, agent_id, history_snapshot, top_k=3)
    )
    return [s.id for s in similar]


def _record_decision(decision: DecisionWrite, embedding: list[float]) -> None:
    from dusk.trace.models import TraceDecision

    trace = TraceDecision(
        id=decision.trace_id,
        agent_id=decision.agent_id,
        action=decision.action_text,
        score=round(decision.score * 100),
        reasoning=decision.reasons[0] if decision.reasons else "",
        risk_flags=list(decision.reasons),
        similar_decision_ids=list(decision.similar_decision_ids),
        verdict=decision.verdict,
        timestamp=decision.occurred_at.timestamp(),
    )
    with _decision_history_lock:
        agent_indices = [
            i
            for i, (value, _vector) in enumerate(_decision_history)
            if value.agent_id == decision.agent_id
        ]
        if len(agent_indices) >= _DECISION_HISTORY_PER_AGENT_CAP:
            del _decision_history[agent_indices[0]]
        _decision_history.append((trace, embedding))
        if len(_decision_history) > _DECISION_HISTORY_CAP:
            del _decision_history[: len(_decision_history) - _DECISION_HISTORY_CAP]


def _build_canonical_evaluator() -> CanonicalEvaluator:
    from dusk.application.evaluator import CanonicalEvaluator, EvaluatorPorts
    from dusk.application.legacy import (
        AuthenticatedV1Identity,
        BehavioralPassthroughPolicy,
        LegacyBehavioralAnalysis,
        LegacyClock,
        LegacyDecisionPersistence,
        LegacyOffenseMemory,
        LegacyTraceIds,
        LegacyWebhookDelivery,
        SieSemanticEnrichment,
    )
    from dusk.trace.n8n_client import fire_alert, fire_decision, fire_report

    gate = _get_gate_engine()
    if gate.offense_memory is None:
        raise RuntimeError("legacy Gate offense memory is unavailable")
    semantic = SieSemanticEnrichment()
    return CanonicalEvaluator(
        EvaluatorPorts(
            clock=LegacyClock(),
            trace_ids=LegacyTraceIds(),
            identity=AuthenticatedV1Identity(),
            semantic=semantic,
            behavioral=LegacyBehavioralAnalysis(gate),
            offenses=LegacyOffenseMemory(gate.offense_memory),
            policy=BehavioralPassthroughPolicy(),
            persistence=LegacyDecisionPersistence(
                lambda agent_id, action_text: _find_similar_decisions(
                    agent_id, action_text, semantic
                ),
                _record_decision,
            ),
            delivery=LegacyWebhookDelivery(
                {"decision": fire_decision, "report": fire_report, "alert": fire_alert}
            ),
        )
    )


@app.route("/v1/gate", methods=["POST"])
def evaluate_gate_action() -> object:
    """Evaluate a proposed agent action against the learned baseline.

    Contract: contracts/gate.openapi.yaml.
    """
    from dusk.actions.event import AgentAction

    if not gate_request_is_authorized(request.headers.get("Authorization", "")):
        auth_response = jsonify({"error": "authentication required"})
        auth_response.headers["WWW-Authenticate"] = "Bearer"
        return auth_response, 401

    raw = request.get_json(force=True, silent=True)
    if not isinstance(raw, dict):
        return jsonify({"error": "request body must be a JSON object"}), 400

    try:
        action = AgentAction.from_dict(raw)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    from dusk.application.evaluator import EvaluationPrincipal

    output = _build_canonical_evaluator().evaluate(
        action,
        EvaluationPrincipal(
            tenant_id="legacy-v1",
            principal_id="authenticated-gate-client",
            identity_kind="legacy-workload",
        ),
    )
    response = output.response
    logger.info(
        "gate verdict trace_id=%s agent=%s verdict=%s score=%.2f",
        response["trace_id"],
        action.agent_id,
        response["verdict"],
        output.decision.score,
    )

    return jsonify(response), 200


@app.route("/health")
def health() -> object:
    gate_engine = _get_gate_engine()  # forces the baseline load attempt so it's reflected below
    if _baseline_load_error is not None:
        logger.error("health degraded: baseline load failed: %s", _baseline_load_error)
        return jsonify({"status": "degraded", "baseline_error": "BASELINE_LOAD_FAILED"}), 503
    offense_memory = gate_engine.offense_memory
    persist_error = offense_memory.last_persist_error if offense_memory is not None else None
    if persist_error is not None:
        logger.error("health degraded: offense memory persist failed: %s", persist_error)
        return jsonify(
            {"status": "degraded", "offense_memory_error": "OFFENSE_MEMORY_PERSIST_FAILED"}
        ), 503
    return jsonify({"status": "ok"})


def run() -> None:
    port = int(os.getenv("FLASK_PORT", "5000"))
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    app.run(host=host, port=port)


if __name__ == "__main__":
    run()
