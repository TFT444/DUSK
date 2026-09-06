"""In-memory downstream target used to verify gate enforcement."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from flask import Flask, request

logging.basicConfig(level=logging.INFO, format="%(asctime)s mock-prod: %(message)s")
logger = logging.getLogger("mock-prod")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

#: In-memory log of applied actions, most recent last. Demo-scale only.
applied_log: list[dict[str, Any]] = []
webhook_log: list[dict[str, Any]] = []
_WEBHOOK_LOG_CAP = 200
_WEBHOOK_KINDS = frozenset({"alert", "decision", "report"})


@app.get("/health")
def health() -> tuple[dict[str, str], int]:
    return {"status": "ok"}, 200


@app.post("/apply")
def apply() -> tuple[dict[str, Any], int]:
    action = request.get_json(force=True, silent=True)
    if not isinstance(action, dict):
        return {"error": "expected a JSON object"}, 400

    record = {
        "received_at": datetime.now(UTC).isoformat(),
        "agent_id": action.get("agent_id"),
        "action_type": action.get("action_type"),
        "target": action.get("target"),
    }
    applied_log.append(record)
    logger.info("applied: %s", record)
    return {"status": "applied", **record}, 200


@app.get("/log")
def log() -> tuple[dict[str, Any], int]:
    return {"count": len(applied_log), "entries": applied_log}, 200


@app.post("/webhook/<kind>")
def webhook(kind: str) -> tuple[dict[str, Any], int]:
    if kind not in _WEBHOOK_KINDS:
        return {"error": "unknown webhook kind"}, 404
    payload = request.get_json(force=True, silent=True)
    if not isinstance(payload, dict):
        return {"error": "expected a JSON object"}, 400

    webhook_log.append(
        {
            "received_at": datetime.now(UTC).isoformat(),
            "kind": kind,
            "trace_id": payload.get("trace_id"),
            "verdict": payload.get("verdict"),
        }
    )
    if len(webhook_log) > _WEBHOOK_LOG_CAP:
        del webhook_log[: len(webhook_log) - _WEBHOOK_LOG_CAP]
    return {"status": "received", "kind": kind}, 200


@app.get("/webhook-log")
def webhooks() -> tuple[dict[str, Any], int]:
    return {"count": len(webhook_log), "entries": webhook_log}, 200


def run() -> None:
    port = int(os.getenv("MOCK_PROD_PORT", "9000"))
    host = os.getenv("MOCK_PROD_HOST", "127.0.0.1")
    app.run(host=host, port=port)


if __name__ == "__main__":
    run()
