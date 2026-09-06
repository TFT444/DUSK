"""Alembic environment with async PostgreSQL support and no embedded credentials."""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

from dusk_control_plane.storage.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata


def _database_url() -> str:
    url = os.environ.get("DUSK_CP_DATABASE_URL")
    if not url:
        raise RuntimeError("DUSK_CP_DATABASE_URL is required for database migrations")
    if not url.startswith("postgresql+asyncpg://"):
        raise RuntimeError("DUSK_CP_DATABASE_URL must use postgresql+asyncpg")
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_server_default=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run_migrations(connection: Connection) -> None:
    lock_timeout_ms = config.get_main_option("dusk_lock_timeout_ms")
    statement_timeout_ms = config.get_main_option("dusk_statement_timeout_ms")
    if lock_timeout_ms and statement_timeout_ms:
        actual = connection.execute(
            text(
                "SELECT "
                "(EXTRACT(EPOCH FROM current_setting('lock_timeout')::interval) * 1000)::bigint, "
                "(EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval) "
                "* 1000)::bigint"
            )
        ).one()
        expected = (int(lock_timeout_ms), int(statement_timeout_ms))
        if tuple(actual) != expected:
            raise RuntimeError("Alembic connection is missing bounded database timeouts")
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_server_default=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def _run_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = _database_url()
    lock_timeout_ms = config.get_main_option("dusk_lock_timeout_ms")
    statement_timeout_ms = config.get_main_option("dusk_statement_timeout_ms")
    connect_args: dict[str, object] = {}
    if lock_timeout_ms and statement_timeout_ms:
        connect_args = {
            "timeout": int(lock_timeout_ms) / 1000,
            "server_settings": {
                "lock_timeout": lock_timeout_ms,
                "statement_timeout": statement_timeout_ms,
                "timezone": "UTC",
            },
        }
    engine = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        hide_parameters=True,
        connect_args=connect_args,
    )
    async with engine.connect() as connection:
        await connection.run_sync(_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(_run_online())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
