"""Initial database schema

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-17 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=False),
        sa.Column(
            "role",
            sa.Enum("INVESTIGATOR", "AUDITOR", name="userrole"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)

    # 2. cases
    op.create_table(
        "cases",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum("OPEN", "CLOSED", "ARCHIVED", name="casestatus"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # 3. evidence
    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("cases.id"),
            nullable=False,
        ),
        sa.Column("original_filename", sa.String(length=500), nullable=False),
        sa.Column("storage_key", sa.String(length=1000), unique=True, nullable=False),
        sa.Column("sha256_digest", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.BigInteger(), nullable=False),
        sa.Column("mime_type", sa.String(length=100), nullable=False),
        sa.Column("phash", sa.String(length=64), nullable=True),
        sa.Column(
            "c2pa_status",
            sa.Enum("VALID", "INVALID", "ABSENT", "ERROR", "PENDING", name="c2pastatus"),
            nullable=False,
        ),
        sa.Column("c2pa_summary_json", sa.Text(), nullable=True),
        sa.Column(
            "uploaded_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(op.f("ix_evidence_case_id"), "evidence", ["case_id"], unique=False)
    op.create_index(op.f("ix_evidence_sha256_digest"), "evidence", ["sha256_digest"], unique=False)
    op.create_index(op.f("ix_evidence_phash"), "evidence", ["phash"], unique=False)

    # 4. custody_events
    op.create_table(
        "custody_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "evidence_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("evidence.id"),
            nullable=False,
        ),
        sa.Column(
            "actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column(
            "event_type",
            sa.Enum(
                "EVIDENCE_REGISTERED",
                "CUSTODY_TRANSFER_INITIATED",
                "CUSTODY_TRANSFER_ACKNOWLEDGED",
                "EVIDENCE_VERIFIED",
                "REPORT_EXPORTED",
                name="eventtype",
            ),
            nullable=False,
        ),
        sa.Column("payload_json", sa.Text(), nullable=True),
        sa.Column("canonical_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("key_id", sa.String(length=255), nullable=True),
        sa.Column("log_index", sa.BigInteger(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(op.f("ix_custody_events_evidence_id"), "custody_events", ["evidence_id"], unique=False)
    op.create_index(op.f("ix_custody_events_log_index"), "custody_events", ["log_index"], unique=False)

    # 5. log_entries
    op.create_table(
        "log_entries",
        sa.Column("index", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column(
            "event_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("custody_events.id"),
            nullable=False,
        ),
        sa.Column("leaf_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # 6. log_checkpoints
    op.create_table(
        "log_checkpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tree_size", sa.BigInteger(), nullable=False),
        sa.Column("root_hash", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("key_id", sa.String(length=255), nullable=False),
        sa.Column("witness_ack_signature", sa.Text(), nullable=True),
        sa.Column("witness_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # 7. experiment_runs
    op.create_table(
        "experiment_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("config_json", sa.Text(), nullable=True),
        sa.Column("metrics_json", sa.Text(), nullable=True),
        sa.Column("artifacts_dir", sa.String(length=1000), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("experiment_runs")
    op.drop_table("log_checkpoints")
    op.drop_table("log_entries")
    op.drop_index(op.f("ix_custody_events_log_index"), table_name="custody_events")
    op.drop_index(op.f("ix_custody_events_evidence_id"), table_name="custody_events")
    op.drop_table("custody_events")
    op.drop_index(op.f("ix_evidence_phash"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_sha256_digest"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_case_id"), table_name="evidence")
    op.drop_table("evidence")
    op.drop_table("cases")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_table("users")

    # Drop enum types in postgres
    sa.Enum(name="eventtype").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="c2pastatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="casestatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="userrole").drop(op.get_bind(), checkfirst=True)
