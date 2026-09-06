"""ASGI entry point and local process launcher."""

from __future__ import annotations

import uvicorn

from dusk_control_plane.app import create_app
from dusk_control_plane.config import Settings
from dusk_control_plane.observability import configure_structured_logging

_settings = Settings()
configure_structured_logging(_settings.log_level)
app = create_app()


def run() -> None:
    """Run Uvicorn with validated settings."""
    settings = Settings()
    uvicorn.run(
        "dusk_control_plane.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        server_header=False,
        proxy_headers=False,
    )
