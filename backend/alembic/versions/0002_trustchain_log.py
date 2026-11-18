"""TrustChain log: checkpoint statement fields, witness status, EXIF, append-only triggers

Revision ID: 0002_trustchain_log
Revises: 0001_initial_schema
Create Date: 2026-11-17 00:00:01.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_trustchain_log"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("log_checkpoints", sa.Column("log_id", sa.String(255), nullable=False, server_default="trustchain-log-v1"))
    op.add_column("log_checkpoints", sa.Column("timestamp", sa.String(64), nullable=False, server_default=""))
    op.add_column("log_checkpoints", sa.Column("witness_status", sa.String(32), nullable=False, server_default="PENDING"))
    op.add_column("log_checkpoints", sa.Column("witness_key_id", sa.String(255), nullable=True))
    op.add_column("log_checkpoints", sa.Column("witness_public_key", sa.String(64), nullable=True))
    op.add_column("log_checkpoints", sa.Column("witness_timestamp_str", sa.String(64), nullable=True))
    op.add_column("log_checkpoints", sa.Column("witness_alert", sa.Text(), nullable=True))
    op.create_index("ix_log_checkpoints_tree_size", "log_checkpoints", ["tree_size"])

    op.add_column("evidence", sa.Column("exif_json", sa.Text(), nullable=True))

    # Database-level append-only enforcement for committed log data.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION trustchain_forbid_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for table in ("custody_events", "log_entries"):
        op.execute(
            f"""
            CREATE TRIGGER {table}_append_only
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION trustchain_forbid_mutation();
            """
        )


def downgrade() -> None:
    for table in ("custody_events", "log_entries"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_append_only ON {table}")
    op.execute("DROP FUNCTION IF EXISTS trustchain_forbid_mutation()")
    op.drop_column("evidence", "exif_json")
    op.drop_index("ix_log_checkpoints_tree_size", table_name="log_checkpoints")
    for col in ("witness_alert", "witness_timestamp_str", "witness_public_key", "witness_key_id", "witness_status", "timestamp", "log_id"):
        op.drop_column("log_checkpoints", col)
