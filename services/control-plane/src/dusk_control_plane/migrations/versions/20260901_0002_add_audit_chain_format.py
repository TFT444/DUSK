"""add audit chain format marker

Revision ID: 20260901_0002
Revises: 20260828_0001
Create Date: 2026-09-01 01:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260901_0002"
down_revision: str | None = "20260828_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "audit_events",
        sa.Column(
            "chain_format",
            sa.String(length=32),
            server_default=sa.text("'dusk.audit.v1'"),
            nullable=False,
        ),
    )
    op.add_column(
        "audit_events",
        sa.Column("signing_key_id", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "audit_events",
        sa.Column("signature", sa.LargeBinary(), nullable=True),
    )


def downgrade() -> None:
    # Digests remain independently verifiable because the format marker is also
    # part of integrity_metadata; rollback therefore preserves written evidence.
    op.drop_column("audit_events", "signature")
    op.drop_column("audit_events", "signing_key_id")
    op.drop_column("audit_events", "chain_format")
