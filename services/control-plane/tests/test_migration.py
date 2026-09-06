from __future__ import annotations

from pathlib import Path

import pytest

from dusk_control_plane.migration import (
    MigrationConfigurationError,
    _alembic_config,
    _bounded_milliseconds,
    _database_url,
)


def test_database_url_requires_async_postgresql(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DUSK_CP_DATABASE_URL", raising=False)
    with pytest.raises(MigrationConfigurationError, match=r"postgresql\+asyncpg"):
        _database_url()
    monkeypatch.setenv("DUSK_CP_DATABASE_URL", "sqlite:///unsafe.db")
    with pytest.raises(MigrationConfigurationError, match=r"postgresql\+asyncpg"):
        _database_url()


@pytest.mark.parametrize("value", ["nope", "999", "60001"])
def test_migration_timeout_is_bounded(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("DUSK_TEST_TIMEOUT", value)
    with pytest.raises(MigrationConfigurationError):
        _bounded_milliseconds("DUSK_TEST_TIMEOUT", 10_000, 1_000, 60_000)


def test_alembic_configuration_must_exist(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("DUSK_CP_ALEMBIC_CONFIG", str(tmp_path / "missing.ini"))
    with pytest.raises(MigrationConfigurationError, match="unavailable"):
        _alembic_config()


def test_alembic_configuration_uses_installed_migrations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = Path(__file__).parents[1] / "alembic.ini"
    monkeypatch.setenv("DUSK_CP_ALEMBIC_CONFIG", str(config_path))
    config = _alembic_config(lock_timeout_ms=1_000, statement_timeout_ms=30_000)
    migrations = Path(config.get_main_option("script_location"))
    assert migrations.is_dir()
    assert migrations.name == "migrations"
    assert config.get_main_option("dusk_lock_timeout_ms") == "1000"
    assert config.get_main_option("dusk_statement_timeout_ms") == "30000"
