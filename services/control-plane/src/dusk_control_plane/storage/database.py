"""Bounded async PostgreSQL engine and transaction lifecycle."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from dusk_control_plane.config import Settings


class Database:
    """Own the service engine; callers receive transaction-scoped sessions only."""

    def __init__(
        self, engine: AsyncEngine, session_factory: async_sessionmaker[AsyncSession]
    ) -> None:
        self._engine = engine
        self._session_factory = session_factory

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        if settings.database_url is None:
            raise ValueError("database_url is required")
        engine = create_async_engine(
            settings.database_url.get_secret_value(),
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout=settings.database_pool_timeout_seconds,
            pool_pre_ping=True,
            hide_parameters=True,
            connect_args={
                "timeout": settings.database_pool_timeout_seconds,
                "server_settings": {
                    "statement_timeout": str(settings.database_statement_timeout_ms),
                    "timezone": "UTC",
                },
            },
        )
        return cls(
            engine=engine,
            session_factory=async_sessionmaker(engine, expire_on_commit=False),
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[AsyncSession]:
        async with self._session_factory() as session, session.begin():
            yield session

    async def close(self) -> None:
        await self._engine.dispose()

    async def probe(self) -> None:
        async with self._engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
