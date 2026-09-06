"""add decision investigation query indexes

Revision ID: 20260902_0004
Revises: 20260902_0003
Create Date: 2026-09-02 16:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260902_0004"
down_revision: str | None = "20260902_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_decisions_tenant_policy_created",
        "decisions",
        ["tenant_id", "policy_decision", "created_at", "id"],
    )
    op.create_index(
        "ix_decisions_tenant_response_created",
        "decisions",
        ["tenant_id", "response_status", "created_at", "id"],
    )
    op.create_index(
        "ix_decisions_search_agent",
        "decisions",
        [sa.text("to_tsvector('simple'::regconfig, agent_id)")],
        postgresql_using="gin",
    )
    op.create_index(
        "ix_canonical_actions_search_document",
        "canonical_actions",
        [sa.text("to_tsvector('simple'::regconfig, redacted_action::text)")],
        postgresql_using="gin",
    )


def downgrade() -> None:
    # Disable decision read routes before dropping their supporting indexes.
    op.drop_index("ix_canonical_actions_search_document", table_name="canonical_actions")
    op.drop_index("ix_decisions_search_agent", table_name="decisions")
    op.drop_index("ix_decisions_tenant_response_created", table_name="decisions")
    op.drop_index("ix_decisions_tenant_policy_created", table_name="decisions")
