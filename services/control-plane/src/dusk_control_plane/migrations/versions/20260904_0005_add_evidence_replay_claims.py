"""add durable provider evidence replay claims

Revision ID: 20260904_0005
Revises: 20260902_0004
Create Date: 2026-09-04 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260904_0005"
down_revision: str | None = "20260902_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_replay_claims",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_identity", sa.String(length=200), nullable=False),
        sa.Column("nonce", sa.String(length=200), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "claimed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_evidence_replay_claims_tenant_id_tenants",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidence_replay_claims"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_evidence_replay_claims_tenant_id_id"),
        sa.UniqueConstraint(
            "tenant_id", "source_identity", "nonce", name="uq_evidence_replay_claim"
        ),
    )
    op.create_index(
        "ix_evidence_replay_claims_tenant_observed",
        "evidence_replay_claims",
        ["tenant_id", "observed_at", "id"],
    )


def downgrade() -> None:
    # Disable signed provider evidence ingestion before rolling this revision back.
    op.drop_index(
        "ix_evidence_replay_claims_tenant_observed",
        table_name="evidence_replay_claims",
    )
    op.drop_table("evidence_replay_claims")
