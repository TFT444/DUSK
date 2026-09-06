"""Static schema and repository invariants that do not require a database."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import DateTime, ForeignKeyConstraint, Index, UniqueConstraint

from dusk_control_plane.storage.models import TENANT_SCOPED_MODELS, Base, Decision
from dusk_control_plane.storage.repositories import RepositorySet

EXPECTED_TABLES = {
    "agent_risk_rollups",
    "audit_events",
    "canonical_actions",
    "dashboard_aggregates",
    "decisions",
    "evidence_replay_claims",
    "integration_health",
    "outbox_deliveries",
    "policy_matches",
    "principals",
    "role_assignments",
    "tenants",
}


def test_authoritative_schema_contains_every_required_storage_surface() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES
    assert {model.__table__.name for model in TENANT_SCOPED_MODELS} == EXPECTED_TABLES - {"tenants"}


@pytest.mark.parametrize("model", TENANT_SCOPED_MODELS)
def test_every_scoped_table_enforces_tenant_qualified_access_paths(model: type[Base]) -> None:
    table = model.__table__
    assert "tenant_id" in table.c

    tenant_foreign_keys = [
        constraint
        for constraint in table.constraints
        if isinstance(constraint, ForeignKeyConstraint) and "tenant_id" in constraint.column_keys
    ]
    assert tenant_foreign_keys, f"{table.name} has no tenant-qualified foreign key"

    access_paths = [
        constraint
        for constraint in (*table.indexes, *table.constraints)
        if isinstance(constraint, (Index, UniqueConstraint))
        and tuple(column.name for column in constraint.columns)[:1] == ("tenant_id",)
    ]
    assert access_paths, f"{table.name} has no tenant-leading index or uniqueness constraint"


def test_all_persisted_timestamps_are_timezone_aware() -> None:
    for table in Base.metadata.sorted_tables:
        for column in table.columns:
            if isinstance(column.type, DateTime):
                assert column.type.timezone is True, f"{table.name}.{column.name} is timezone-naive"


def test_idempotency_and_trace_uniqueness_are_tenant_qualified() -> None:
    unique_columns = {
        tuple(column.name for column in constraint.columns)
        for constraint in Decision.__table__.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert ("tenant_id", "idempotency_key") in unique_columns
    assert ("tenant_id", "trace_id") in unique_columns


def test_repository_set_exposes_only_tenant_bound_data_access() -> None:
    assert "tenant_id" in RepositorySet.__init__.__annotations__
    assert not hasattr(RepositorySet, "tenants")


def test_baseline_revision_is_immutable_and_does_not_import_live_models() -> None:
    revision = next(
        (Path(__file__).parents[1] / "src/dusk_control_plane/migrations/versions").glob(
            "*_create_control_plane_storage.py"
        )
    )
    source = revision.read_text(encoding="utf-8")
    assert "storage.models" not in source
    assert "def upgrade()" in source
    assert "def downgrade()" in source
