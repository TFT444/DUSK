"""Deterministic OpenAPI rendering."""

from __future__ import annotations

import json

from dusk.policies import load_enterprise_pack
from pydantic import SecretStr

from dusk_control_plane.app import create_app
from dusk_control_plane.config import Environment, Settings
from dusk_control_plane.dependencies import AppContainer


def render_openapi() -> str:
    """Return stable, human-reviewable OpenAPI JSON."""
    settings = Settings(
        environment=Environment.TEST,
        api_docs_enabled=False,
        v2_enabled=True,
        oidc_issuer="https://identity.example.test/",
        oidc_audience="dusk-control-plane",
        oidc_jwks_uri="https://identity.example.test/.well-known/jwks.json",
        storage_enabled=True,
        database_url=SecretStr("postgresql+asyncpg://contract@database/control_plane"),
        decision_read_api_enabled=True,
        dashboard_read_api_enabled=True,
        operations_read_api_enabled=True,
        decision_cursor_signing_key=SecretStr("contract-only-cursor-signing-key-32"),
    )
    app = create_app(
        container=AppContainer.build(settings=settings, policy_pack=load_enterprise_pack())
    )
    return json.dumps(app.openapi(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
