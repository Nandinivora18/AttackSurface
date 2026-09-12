"""add missing columns: scope_config, timeline, scan_mode, scan_preferences,
score_breakdown, executive_summary, and findings extended fields

Revision ID: 005_add_missing_columns
Revises: 004_add_cancellation
Create Date: 2026-07-29 00:00:00.000000

Adds all columns present in SQLAlchemy models but absent from earlier migrations.
These gaps would cause column-not-found errors when the application first writes
these fields against a fresh PostgreSQL database.

Columns added:
  scans:
    - scope_config    (JSON,  nullable)   -- scan scope/config options
    - timeline        (JSON,  nullable)   -- stage-by-stage timing log
    - scan_mode       (VARCHAR(20), not null, default='passive')

  users:
    - scan_preferences (JSON, nullable)   -- user-level scan defaults

  reports:
    - score_breakdown  (JSONB, nullable)  -- per-category score breakdown
    - scan_mode        (VARCHAR(20), not null, default='passive')
    - executive_summary (JSONB, nullable) -- AI-generated exec summary
    - timeline         (JSONB, nullable)  -- scan timeline mirrored to report

  findings (extended fields added after initial schema):
    - status           (VARCHAR(20), nullable)
    - confidence       (VARCHAR(20), nullable)
    - cve_id           (VARCHAR(50), nullable)
    - cwe_id           (VARCHAR(50), nullable)
    - endpoint         (TEXT, nullable)
    - published_date   (TIMESTAMP WITH TZ, nullable)
    - problem          (TEXT, nullable)
    - impact           (TEXT, nullable)
    - risk_analysis    (TEXT, nullable)
    - technical_details (TEXT, nullable)
    - fix_steps        (JSONB, nullable)
    - configuration_example (TEXT, nullable)
    - defense_in_depth (TEXT, nullable)
    - references_url   (TEXT, nullable -- renamed from references to avoid keyword)
    - owasp_category   (JSONB, nullable)
    - mitre_technique  (JSONB, nullable)
    - affected_count   (INTEGER, default 0)
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "005_add_missing_columns"
down_revision: Union[str, None] = "004_add_cancellation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgresql() -> bool:
    bind = op.get_bind()
    return bind.dialect.name == "postgresql"


def _json_type():
    """Return JSONB for PostgreSQL, JSON for SQLite."""
    if _is_postgresql():
        return postgresql.JSONB(astext_type=sa.Text())
    return sa.JSON()


def upgrade() -> None:
    # ── scans ────────────────────────────────────────────────────────────────
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(
            sa.Column("scope_config", sa.JSON(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("timeline", sa.JSON(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "scan_mode",
                sa.String(20),
                nullable=False,
                server_default="passive",
            )
        )

    # ── users ─────────────────────────────────────────────────────────────────
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("scan_preferences", sa.JSON(), nullable=True)
        )

    # ── reports ──────────────────────────────────────────────────────────────
    with op.batch_alter_table("reports") as batch_op:
        batch_op.add_column(
            sa.Column("score_breakdown", _json_type(), nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "scan_mode",
                sa.String(20),
                nullable=False,
                server_default="passive",
            )
        )
        batch_op.add_column(
            sa.Column("executive_summary", _json_type(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("timeline", _json_type(), nullable=True)
        )

    # ── findings ─────────────────────────────────────────────────────────────
    # The initial migration created a minimal findings schema.
    # Many fields used by the scanner engine were missing.
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("status", sa.String(20), nullable=True, server_default="open"))
        batch_op.add_column(sa.Column("confidence", sa.String(20), nullable=True))
        batch_op.add_column(sa.Column("cve_id", sa.String(50), nullable=True))
        batch_op.add_column(sa.Column("cwe_id", sa.String(50), nullable=True))
        batch_op.add_column(sa.Column("endpoint", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("published_date", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("problem", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("impact", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("risk_analysis", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("technical_details", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("fix_steps", _json_type(), nullable=True))
        batch_op.add_column(sa.Column("configuration_example", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("defense_in_depth", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("owasp_category", _json_type(), nullable=True))
        batch_op.add_column(sa.Column("mitre_technique", _json_type(), nullable=True))
        batch_op.add_column(
            sa.Column("affected_count", sa.Integer(), nullable=False, server_default="0")
        )


def downgrade() -> None:
    # ── findings ─────────────────────────────────────────────────────────────
    with op.batch_alter_table("findings") as batch_op:
        for col in [
            "affected_count", "mitre_technique", "owasp_category",
            "defense_in_depth", "configuration_example", "fix_steps",
            "technical_details", "risk_analysis", "impact", "problem",
            "published_date", "endpoint", "cwe_id", "cve_id",
            "confidence", "status",
        ]:
            batch_op.drop_column(col)

    # ── reports ──────────────────────────────────────────────────────────────
    with op.batch_alter_table("reports") as batch_op:
        for col in ["timeline", "executive_summary", "scan_mode", "score_breakdown"]:
            batch_op.drop_column(col)

    # ── users ─────────────────────────────────────────────────────────────────
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("scan_preferences")

    # ── scans ────────────────────────────────────────────────────────────────
    with op.batch_alter_table("scans") as batch_op:
        for col in ["scan_mode", "timeline", "scope_config"]:
            batch_op.drop_column(col)
