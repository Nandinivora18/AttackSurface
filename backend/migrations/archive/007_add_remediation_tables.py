"""Add remediation tables (Phase 1: Authorized Auto-Remediation)

Revision ID: 007_add_remediation_tables
Revises: 006_cleanup
Create Date: 2026-08-24 00:00:00.000000

Creates:
  - project_connections      (explicit per-domain authorization records)
  - remediation_records      (remediation lifecycle state machine rows)
  - remediation_audit_logs   (append-only transition audit trail)

Idempotent on both SQLite (dev/test) and PostgreSQL (production):
tables are only created when missing; enums are native PostgreSQL ENUMs
and VARCHAR+CHECK on SQLite.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

from app.models.remediation import ConnectionType, RemediationStatus


# revision identifiers, used by Alembic.
revision: str = "007_add_remediation_tables"
down_revision: Union[str, None] = "006_cleanup"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _enum(py_enum, name: str) -> sa.Enum:
    return sa.Enum(py_enum, name=name, native_enum=_is_postgresql(), validate_strings=True)


def _table_exists(inspector, name: str) -> bool:
    return name in inspector.get_table_names()


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # 1. project_connections -------------------------------------------------
    if not _table_exists(inspector, "project_connections"):
        op.create_table(
            "project_connections",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "user_id", sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("connection_type", _enum(ConnectionType, "connectiontype"), nullable=False),
            sa.Column("domain", sa.String(255), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_project_connections_user_id", "project_connections", ["user_id"])
        op.create_index("ix_project_connections_domain", "project_connections", ["domain"])

    # 2. remediation_records --------------------------------------------------
    if not _table_exists(inspector, "remediation_records"):
        op.create_table(
            "remediation_records",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "finding_id", sa.Uuid(),
                sa.ForeignKey("findings.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "user_id", sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "project_connection_id", sa.Uuid(),
                sa.ForeignKey("project_connections.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("vulnerability_type", sa.String(100), nullable=False),
            sa.Column("detector_id", sa.String(100), nullable=True),
            sa.Column("severity", sa.String(20), nullable=False),
            sa.Column("status", _enum(RemediationStatus, "remediationstatus"), nullable=False),
            sa.Column("remediation_description", sa.Text(), nullable=True),
            sa.Column("affected_component", sa.String(255), nullable=True),
            sa.Column("proposed_change", sa.JSON(), nullable=True),
            sa.Column("backup_data", sa.JSON(), nullable=True),
            sa.Column("verification_method", sa.String(255), nullable=True),
            sa.Column("verification_result", sa.JSON(), nullable=True),
            sa.Column(
                "verification_scan_id", sa.Uuid(),
                sa.ForeignKey("scans.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("audit_context", sa.JSON(), nullable=True),
            sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_remediation_records_finding_id", "remediation_records", ["finding_id"])
        op.create_index("ix_remediation_records_user_id", "remediation_records", ["user_id"])
        op.create_index("ix_remediation_records_status", "remediation_records", ["status"])

    # 3. remediation_audit_logs ----------------------------------------------
    if not _table_exists(inspector, "remediation_audit_logs"):
        op.create_table(
            "remediation_audit_logs",
            sa.Column("id", sa.Uuid(), primary_key=True),
            sa.Column(
                "remediation_id", sa.Uuid(),
                sa.ForeignKey("remediation_records.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "user_id", sa.Uuid(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("action", sa.String(100), nullable=False),
            sa.Column("previous_status", sa.String(50), nullable=True),
            sa.Column("new_status", sa.String(50), nullable=True),
            sa.Column("metadata", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )
        op.create_index("ix_remediation_audit_logs_remediation_id", "remediation_audit_logs", ["remediation_id"])


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if "remediation_audit_logs" in tables:
        op.drop_table("remediation_audit_logs")
    if "remediation_records" in tables:
        op.drop_table("remediation_records")
    if "project_connections" in tables:
        op.drop_table("project_connections")

    # Note: PostgreSQL enum types are intentionally left in place — dropping
    # them is destructive and unnecessary for a safe downgrade path.
