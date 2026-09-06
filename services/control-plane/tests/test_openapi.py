"""OpenAPI exposure and generation tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from dusk_control_plane.app import create_app
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dependencies import AppContainer


def _app(*, docs: bool = False):
    settings = Settings(environment=Environment.TEST, api_docs_enabled=docs)
    return create_app(container=AppContainer.build(settings=settings))


def test_openapi_is_generated_even_when_public_docs_route_is_disabled() -> None:
    app = _app()
    schema = app.openapi()
    assert schema["info"] == {
        "title": "DUSK Control Plane API",
        "summary": "Production security decision control plane",
        "description": (
            "A separately deployed, multi-tenant service. The legacy Flask /v1/gate "
            "boundary is not part of this application."
        ),
        "version": "0.1.0",
    }
    assert set(schema["paths"]) == {"/livez", "/readyz"}
    with TestClient(app) as client:
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/docs").status_code == 404


def test_local_operator_can_explicitly_enable_openapi_and_swagger() -> None:
    app = _app(docs=True)
    with TestClient(app) as client:
        schema = client.get("/openapi.json")
        docs = client.get("/docs")
    assert schema.status_code == 200
    assert schema.json() == app.openapi()
    assert docs.status_code == 200
