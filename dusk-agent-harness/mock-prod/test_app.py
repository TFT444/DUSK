"""Tests for the mock-prod dummy downstream target."""

from __future__ import annotations

import pytest
from app import app, applied_log, webhook_log


@pytest.fixture(autouse=True)
def _clear_log():
    applied_log.clear()
    webhook_log.clear()
    yield
    applied_log.clear()
    webhook_log.clear()


@pytest.fixture
def client():
    app.testing = True
    return app.test_client()


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_apply_logs_the_action(client):
    action = {"agent_id": "agent-1", "action_type": "route_change", "target": "rt-123"}
    resp = client.post("/apply", json=action)
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "applied"
    assert body["agent_id"] == "agent-1"

    log_resp = client.get("/log")
    log_body = log_resp.get_json()
    assert log_body["count"] == 1
    assert log_body["entries"][0]["target"] == "rt-123"


def test_apply_rejects_non_object_body(client):
    resp = client.post("/apply", json=["not", "an", "object"])
    assert resp.status_code == 400


def test_webhook_sink_records_bounded_metadata(client):
    response = client.post(
        "/webhook/decision",
        json={"trace_id": "trace-1", "verdict": "ALLOW", "sensitive": "discarded"},
    )

    assert response.status_code == 200
    assert webhook_log == [
        {
            "received_at": webhook_log[0]["received_at"],
            "kind": "decision",
            "trace_id": "trace-1",
            "verdict": "ALLOW",
        }
    ]
    assert "sensitive" not in webhook_log[0]


def test_webhook_sink_rejects_unknown_kind_and_invalid_body(client):
    assert client.post("/webhook/unknown", json={}).status_code == 404
    assert client.post("/webhook/alert", json=[]).status_code == 400


def test_webhook_sink_rejects_oversized_body(client):
    response = client.post(
        "/webhook/alert",
        data=b"x" * (1024 * 1024 + 1),
        content_type="application/json",
    )
    assert response.status_code == 413
