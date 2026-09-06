"""Single-writer, bounded Alembic migration entry point for deployment jobs."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

_MIGRATION_LOCK_ID = 443_206
_DEFAULT_LOCK_TIMEOUT_MS = 10_000
_DEFAULT_STATEMENT_TIMEOUT_MS = 300_000


class MigrationConfigurationError(RuntimeError):
    """Deployment migration configuration is absent or unsafe."""


class MigrationLockUnavailableError(RuntimeError):
    """Another deployment owns the global schema migration lease."""


def _bounded_milliseconds(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise MigrationConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise MigrationConfigurationError(f"{name} is outside the supported range")
    return value


def _database_url() -> str:
    value = os.environ.get("DUSK_CP_DATABASE_URL")
    if value is None or not value.startswith("postgresql+asyncpg://"):
        raise MigrationConfigurationError(
            "DUSK_CP_DATABASE_URL must use the postgresql+asyncpg dialect"
        )
    return value


def _alembic_config(
    *, lock_timeout_ms: int | None = None, statement_timeout_ms: int | None = None
) -> Config:
    configured = os.environ.get("DUSK_CP_ALEMBIC_CONFIG", "/app/alembic.ini")
    path = Path(configured)
    if not path.is_file():
        raise MigrationConfigurationError("Alembic configuration is unavailable")
    config = Config(str(path))
    migrations = Path(__file__).resolve().parent / "migrations"
    if not migrations.is_dir():
        raise MigrationConfigurationError("installed Alembic migrations are unavailable")
    config.set_main_option("script_location", str(migrations))
    if lock_timeout_ms is not None:
        config.set_main_option("dusk_lock_timeout_ms", str(lock_timeout_ms))
    if statement_timeout_ms is not None:
        config.set_main_option("dusk_statement_timeout_ms", str(statement_timeout_ms))
    return config


async def migrate() -> None:
    """Hold the deployment lock while applying the additive migration chain."""
    lock_timeout = _bounded_milliseconds(
        "DUSK_CP_MIGRATION_LOCK_TIMEOUT_MS", _DEFAULT_LOCK_TIMEOUT_MS, 1_000, 60_000
    )
    statement_timeout = _bounded_milliseconds(
        "DUSK_CP_MIGRATION_STATEMENT_TIMEOUT_MS",
        _DEFAULT_STATEMENT_TIMEOUT_MS,
        30_000,
        900_000,
    )
    engine = create_async_engine(
        _database_url(),
        poolclass=NullPool,
        hide_parameters=True,
        connect_args={
            "timeout": lock_timeout / 1000,
            "server_settings": {
                "lock_timeout": str(lock_timeout),
                "statement_timeout": str(statement_timeout),
                "timezone": "UTC",
            },
        },
    )
    try:
        async with engine.connect() as connection:
            acquired = await connection.scalar(
                text("SELECT pg_try_advisory_lock(:lock_id)"),
                {"lock_id": _MIGRATION_LOCK_ID},
            )
            if acquired is not True:
                raise MigrationLockUnavailableError("schema migration lock is already held")
            try:
                alembic_config = _alembic_config(
                    lock_timeout_ms=lock_timeout,
                    statement_timeout_ms=statement_timeout,
                )
                await asyncio.to_thread(command.upgrade, alembic_config, "head")
            finally:
                await connection.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": _MIGRATION_LOCK_ID},
                )
    finally:
        await engine.dispose()


def main() -> None:
    """Run migrations without printing credentials or database diagnostics."""
    asyncio.run(migrate())


if __name__ == "__main__":
    main()
