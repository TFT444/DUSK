"""add outbox delivery lifecycle fields

Revision ID: 20260902_0003
Revises: 20260901_0002
Create Date: 2026-09-02 01:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260902_0003"
down_revision: str | None = "20260901_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "outbox_deliveries",
        sa.Column(
            "destination_kind",
            sa.String(length=32),
            server_default=sa.text("'WEBHOOK'"),
            nullable=False,
        ),
    )
    op.add_column(
        "outbox_deliveries",
        sa.Column("state_version", sa.BigInteger(), server_default=sa.text("1"), nullable=False),
    )
    op.add_column(
        "outbox_deliveries",
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "outbox_deliveries",
        sa.Column("lease_owner", sa.UUID(), nullable=True),
    )
    op.add_column(
        "outbox_deliveries",
        sa.Column("acknowledgement_digest", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "outbox_deliveries",
        sa.Column(
            "acknowledgement_evidence",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )
    op.add_column(
        "outbox_deliveries",
        sa.Column("acknowledgement_signature", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "outbox_deliveries",
        sa.Column("acknowledgement_outcome", sa.String(length=16), nullable=True),
    )
    op.add_column(
        "outbox_deliveries",
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        op.f("ck_outbox_deliveries_state_version"),
        "outbox_deliveries",
        "state_version > 0",
    )
    op.create_check_constraint(
        op.f("ck_outbox_deliveries_destination_kind"),
        "outbox_deliveries",
        "destination_kind IN ('WEBHOOK', 'ENFORCEMENT_BROKER')",
    )
    op.create_check_constraint(
        op.f("ck_outbox_deliveries_acknowledgement_outcome"),
        "outbox_deliveries",
        "acknowledgement_outcome IS NULL OR acknowledgement_outcome IN ('EXECUTED', 'REJECTED')",
    )
    op.create_check_constraint(
        op.f("ck_outbox_deliveries_acknowledgement_shape"),
        "outbox_deliveries",
        "(acknowledgement_digest IS NULL AND acknowledgement_evidence IS NULL AND "
        "acknowledgement_signature IS NULL AND acknowledgement_outcome IS NULL AND "
        "acknowledged_at IS NULL) OR "
        "(acknowledgement_digest IS NOT NULL AND acknowledgement_evidence IS NOT NULL AND "
        "acknowledgement_signature IS NOT NULL AND acknowledgement_outcome IS NOT NULL AND "
        "acknowledged_at IS NOT NULL)",
    )


def downgrade() -> None:
    # Stop workers before rollback. Pending rows and stable delivery identifiers
    # remain in the baseline columns for replay by a compatible worker.
    op.drop_constraint(
        op.f("ck_outbox_deliveries_state_version"),
        "outbox_deliveries",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_outbox_deliveries_destination_kind"),
        "outbox_deliveries",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_outbox_deliveries_acknowledgement_outcome"),
        "outbox_deliveries",
        type_="check",
    )
    op.drop_constraint(
        op.f("ck_outbox_deliveries_acknowledgement_shape"),
        "outbox_deliveries",
        type_="check",
    )
    op.drop_column("outbox_deliveries", "acknowledged_at")
    op.drop_column("outbox_deliveries", "acknowledgement_outcome")
    op.drop_column("outbox_deliveries", "acknowledgement_signature")
    op.drop_column("outbox_deliveries", "acknowledgement_evidence")
    op.drop_column("outbox_deliveries", "acknowledgement_digest")
    op.drop_column("outbox_deliveries", "lease_owner")
    op.drop_column("outbox_deliveries", "last_attempt_at")
    op.drop_column("outbox_deliveries", "state_version")
    op.drop_column("outbox_deliveries", "destination_kind")
