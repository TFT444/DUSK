"""Operational API, dependency injection, and safe error tests."""

from __future__ import annotations

import re
import sys

from fastapi import APIRouter
from fastapi.testclient import TestClient

from dusk_control_plane.app import REQUEST_ID_HEADER, create_app
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dependencies import AppContainer, DependencyProbe
from dusk_control_plane.identity import IdentityKind, Principal

REQUEST_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def _settings(**overrides: object) -> Settings:
    return Settings(environment=Environment.TEST, **overrides)


def test_liveness_and_readiness_are_minimal_and_hardened() -> None:
    app = create_app(container=AppContainer.build(settings=_settings()))
    with TestClient(app) as client:
        live = client.get("/livez")
        ready = client.get("/readyz")

    assert live.status_code == 200
    assert live.json() == {
        "status": "live",
        "service": "dusk-control-plane",
        "version": "0.1.0",
    }
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ready",
        "service": "dusk-control-plane",
        "version": "0.1.0",
        "components": [],
    }
    for response in (live, ready):
        assert REQUEST_ID_PATTERN.fullmatch(response.headers[REQUEST_ID_HEADER])
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "DUSK_" not in response.text


def test_server_generates_request_ids_and_ignores_caller_value() -> None:
    app = create_app(container=AppContainer.build(settings=_settings()))
    with TestClient(app) as client:
        first = client.get("/livez", headers={REQUEST_ID_HEADER: "caller-controlled"})
        second = client.get("/livez")
    first_id = first.headers[REQUEST_ID_HEADER]
    second_id = second.headers[REQUEST_ID_HEADER]
    assert REQUEST_ID_PATTERN.fullmatch(first_id)
    assert REQUEST_ID_PATTERN.fullmatch(second_id)
    assert first_id != "caller-controlled"
    assert first_id != second_id


def test_critical_readiness_failure_is_sanitized_and_does_not_break_liveness() -> None:
    async def unavailable() -> None:
        raise RuntimeError("postgresql://user:secret@internal.example/private")

    probe = DependencyProbe(name="postgresql", critical=True, check=unavailable)
    app = create_app(container=AppContainer.build(settings=_settings(), readiness_probes=[probe]))
    with TestClient(app) as client:
        readiness = client.get("/readyz")
        liveness = client.get("/livez")

    assert readiness.status_code == 503
    assert readiness.json() == {
        "status": "not_ready",
        "service": "dusk-control-plane",
        "version": "0.1.0",
        "components": [{"name": "postgresql", "status": "unavailable", "critical": True}],
    }
    assert "secret" not in readiness.text
    assert "internal.example" not in readiness.text
    assert liveness.status_code == 200


def test_noncritical_readiness_failure_reports_degradation_without_failing_readiness() -> None:
    async def unavailable() -> None:
        raise TimeoutError("optional enrichment timeout")

    probe = DependencyProbe(name="sie", critical=False, check=unavailable)
    app = create_app(container=AppContainer.build(settings=_settings(), readiness_probes=[probe]))
    with TestClient(app) as client:
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["components"] == [
        {"name": "sie", "status": "unavailable", "critical": False}
    ]


def test_readiness_probe_is_bounded_by_configuration() -> None:
    async def never_finishes() -> None:
        import asyncio

        await asyncio.sleep(60)

    probe = DependencyProbe(name="slow", critical=True, check=never_finishes)
    settings = _settings(readiness_timeout_ms=50)
    app = create_app(container=AppContainer.build(settings=settings, readiness_probes=[probe]))
    with TestClient(app) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json()["components"][0]["status"] == "unavailable"


def test_structured_errors_are_safe_and_correlated() -> None:
    app = create_app(container=AppContainer.build(settings=_settings()))
    router = APIRouter()

    @router.get("/__test_failure")
    async def fail_for_test() -> None:
        raise RuntimeError("password=do-not-leak")

    app.include_router(router, include_in_schema=False)
    with TestClient(app, raise_server_exceptions=False) as client:
        missing = client.get("/missing")
        failed = client.get("/__test_failure")

    assert missing.status_code == 404
    assert missing.json() == {
        "error": {
            "code": "NOT_FOUND",
            "message": "Resource not found",
            "request_id": missing.headers[REQUEST_ID_HEADER],
            "retryable": False,
        }
    }
    assert failed.status_code == 500
    assert failed.json() == {
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "Internal service error",
            "request_id": failed.headers[REQUEST_ID_HEADER],
            "retryable": True,
        }
    }
    assert "password" not in failed.text
    assert "do-not-leak" not in failed.text


def test_configured_request_size_limit_returns_standard_error() -> None:
    app = create_app(container=AppContainer.build(settings=_settings(max_request_body_bytes=1024)))
    with TestClient(app) as client:
        response = client.post("/missing", content=b"x" * 2048)
    assert response.status_code == 413
    assert response.json() == {
        "error": {
            "code": "REQUEST_TOO_LARGE",
            "message": "Request body exceeds the configured limit",
            "request_id": response.headers[REQUEST_ID_HEADER],
            "retryable": False,
        }
    }


def test_service_does_not_import_or_mount_flask_boundary() -> None:
    before = set(sys.modules)
    app = create_app(container=AppContainer.build(settings=_settings()))
    added = set(sys.modules) - before
    paths = {route.path for route in app.routes}
    assert "/v1/gate" not in paths
    assert "dusk.api" not in added
    assert all(not module.startswith("flask") for module in added)


class _WorkloadAuthenticator:
    async def authenticate(self, token: str) -> Principal:
        return Principal(
            issuer="https://identity.example.test/",
            subject="subject-a",
            tenant_id="tenant-a",
            kind=IdentityKind.WORKLOAD,
            workload_id="agent-a",
        )


def test_v2_evaluation_route_fails_closed_without_activated_service() -> None:
    settings = _settings(
        v2_enabled=True,
        oidc_issuer="https://identity.example.test/",
        oidc_audience="dusk-control-plane",
        oidc_jwks_uri="https://identity.example.test/jwks.json",
    )
    app = create_app(
        container=AppContainer.build(
            settings=settings,
            authenticator=_WorkloadAuthenticator(),
        )
    )
    with TestClient(app) as client:
        response = client.post(
            "/v2/evaluations",
            headers={"Authorization": "Bearer valid-test-token"},
            json={
                "action": {
                    "agent_id": "agent-a",
                    "action_type": "network.firewall.update",
                    "target": "firewall-prod",
                    "consequential": True,
                },
                "evidence": [
                    {
                        "domain": "action",
                        "source_identity": "aws-cloudtrail",
                        "provenance": "signed-event",
                        "observed_at": "2026-09-01T00:00:00Z",
                        "digest": "sha256:" + "0" * 64,
                        "payload": {"type": "network.firewall.update"},
                        "tenant_id": "tenant-a",
                        "key_id": "test-key",
                        "nonce": "test-nonce-00000001",
                        "signature": "a" * 86,
                    }
                ],
                "idempotency_key": "request-1",
            },
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "EVALUATION_UNAVAILABLE"
    assert response.json()["error"]["retryable"] is True


class _LifecycleWorker:
    def __init__(self) -> None:
        import asyncio

        self.started = asyncio.Event()
        self.stopped = asyncio.Event()

    async def run_forever(self) -> None:
        self.started.set()
        await self.stopped.wait()

    def stop(self) -> None:
        self.stopped.set()


def test_enabled_outbox_worker_starts_and_stops_with_application() -> None:
    worker = _LifecycleWorker()
    settings = _settings(
        storage_enabled=True,
        database_url="postgresql+asyncpg://user:secret@database/control_plane",
        outbox_worker_enabled=True,
    )
    app = create_app(
        container=AppContainer(
            settings=settings,
            outbox_worker=worker,  # type: ignore[arg-type] - lifecycle test double
        )
    )
    with TestClient(app) as client:
        assert client.get("/livez").status_code == 200
        assert worker.started.is_set()
    assert worker.stopped.is_set()
