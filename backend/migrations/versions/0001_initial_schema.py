"""Squashed and corrected initial schema — authoritative production schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-29 00:00:00.000000

WHY THIS MIGRATION EXISTS
=========================
The previous migration chain (001_initial -> 16dd5c96c8e6 -> 003 -> 004 -> 005
-> 006 -> 007) was authored incrementally during development and was derived
from `create_all()` rather than validated against a fresh PostgreSQL install.
As a result, the chain had three classes of defects that broke a FROM-EMPTY
`alembic upgrade head` on a production database:

  1. Missing tables — `assets`, `asset_change_events`, and `share_links` were
     never migrated and only existed because the application called
     `Base.metadata.create_all()` at startup.
  2. Migration 002/005 overlap — migration 16dd5c96c8e6 ("002") and
     migration 005 both ADD `scans.scan_mode`, `reports.scan_mode`, and
     `reports.executive_summary`. On a fresh PostgreSQL database the second
     migration fails with "duplicate column", so `upgrade head` could never
     complete.
  3. `findings` model drift — the Finding model had diverged from migration
     005 (column names/types/nullability for status, confidence, cve_id,
     cwe_id, endpoint, published_date, references, owasp_mapping,
     mitre_mapping, best_practices, official_documentation,
     is_passed_control, ...). create_all() was silently masking this.

CONSOLIDATION DECISION
======================
This project has NO production migration history: development and test use
`create_all()` (SQLite), and no PostgreSQL/docker database has ever been
migrated. Preserving a malformed history that cannot install from scratch
provides no value and produces a permanently broken production path.
Therefore the broken history has been ARCHIVED (see migrations/archive/) and
replaced with this single, squashed, dialect-portable base migration that
recreates the exact current SQLAlchemy model schema (13 tables).

`alembic upgrade head` from an empty database now produces a schema that is
byte-identical to `Base.metadata` (verify with `alembic check` /
autogenerate), on both SQLite (dev/test) and PostgreSQL (production).

Ditch the old chain in favour of this one because the models are the source
of intended behaviour and the schema below mirrors them exactly.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from app.models.user import UserRole  # noqa: F401
from app.models.scan import ScanStatus  # noqa: F401
from app.models.report import RiskLevel  # noqa: F401
from app.models.finding import Severity, FindingStatus, Confidence  # noqa: F401
from app.models.remediation import ConnectionType, RemediationStatus  # noqa: F401


# revision identifiers, used by Alembic.
revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _enum(py_enum, name: str) -> sa.Enum:
    """Dialect-portable enum: native PostgreSQL ENUM, VARCHAR+CHECK on SQLite."""
    return sa.Enum(py_enum, name=name, native_enum=_is_postgresql(), validate_strings=True)


def _now():
    # Use the SQLAlchemy function construct so each dialect renders the
    # correct default: CURRENT_TIMESTAMP on SQLite, now() on PostgreSQL.
    # This exactly matches the models' server_default=func.now().
    return sa.func.now()


def upgrade() -> None:
    # ── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("google_id", sa.String(255), nullable=True),
        sa.Column("avatar_url", sa.String(512), nullable=True),
        sa.Column("role", _enum(UserRole, "userrole"), nullable=False),
        sa.Column("is_verified", sa.Boolean(), nullable=False),
        sa.Column("email_verification_token", sa.String(255), nullable=True),
        sa.Column("email_verification_expires", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_reset_token", sa.String(255), nullable=True),
        sa.Column("password_reset_expires", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_preferences", sa.JSON(), nullable=True),
        sa.UniqueConstraint("google_id"),
    )
    # Model declares email unique=True AND index=True -> unique index.
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ── scans ─────────────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("status", _enum(ScanStatus, "scanstatus"), nullable=False),
        sa.Column("progress", sa.Integer(), nullable=False),
        sa.Column("current_stage", sa.String(100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("cancellation_reason", sa.String(255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_mode", sa.String(20), nullable=False),
        sa.Column("scope_config", sa.JSON(), nullable=True),
        sa.Column("timeline", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
        sa.Column("task_id", sa.String(255), nullable=True),
    )
    op.create_index("ix_scans_user_id", "scans", ["user_id"])

    # ── reports ───────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("overall_score", sa.Integer(), nullable=False),
        sa.Column("grade", sa.String(3), nullable=False),
        sa.Column("risk_level", _enum(RiskLevel, "risklevel"), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("tech_stack", sa.JSON(), nullable=True),
        sa.Column("raw_headers", sa.JSON(), nullable=True),
        sa.Column("ssl_info", sa.JSON(), nullable=True),
        sa.Column("dns_info", sa.JSON(), nullable=True),
        sa.Column("score_breakdown", sa.JSON(), nullable=True),
        sa.Column("scan_mode", sa.String(20), nullable=False),
        sa.Column("executive_summary", sa.JSON(), nullable=True),
        sa.Column("timeline", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
        sa.UniqueConstraint("scan_id"),
    )
    op.create_index("ix_reports_user_id", "reports", ["user_id"])

    # ── findings ──────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("report_id", sa.Uuid(), sa.ForeignKey("reports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", _enum(Severity, "severity"), nullable=False),
        sa.Column("status", _enum(FindingStatus, "findingstatus"), nullable=False),
        sa.Column("confidence", _enum(Confidence, "confidence"), nullable=False),
        sa.Column("cvss_score", sa.Numeric(4, 1), nullable=True),
        sa.Column("cve_id", sa.String(25), nullable=True),
        sa.Column("cwe_id", sa.String(25), nullable=True),
        sa.Column("endpoint", sa.String(255), nullable=True),
        sa.Column("published_date", sa.Date(), nullable=True),
        sa.Column("recommendation", sa.Text(), nullable=True),
        sa.Column("problem", sa.Text(), nullable=True),
        sa.Column("impact", sa.Text(), nullable=True),
        sa.Column("risk_analysis", sa.Text(), nullable=True),
        sa.Column("technical_details", sa.Text(), nullable=True),
        sa.Column("fix_steps", sa.JSON(), nullable=True),
        sa.Column("configuration_example", sa.Text(), nullable=True),
        sa.Column("best_practices", sa.Text(), nullable=True),
        sa.Column("official_documentation", sa.Text(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("owasp_mapping", sa.JSON(), nullable=True),
        sa.Column("mitre_mapping", sa.JSON(), nullable=True),
        sa.Column("is_passed_control", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_findings_report_id", "findings", ["report_id"])
    op.create_index("ix_findings_cve_id", "findings", ["cve_id"])

    # ── notifications ─────────────────────────────────────────────────────────
    op.create_table(
        "notifications",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("is_read", sa.Boolean(), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_notifications_user_id", "notifications", ["user_id"])

    # ── sessions ──────────────────────────────────────────────────────────────
    op.create_table(
        "sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(512), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    # Model declares token_hash unique=True AND index=True -> unique index.
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"], unique=True)

    # ── audit_logs ────────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource", sa.String(100), nullable=True),
        sa.Column("resource_id", sa.Uuid(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])

    # ── assets (formerly missing from migrations) ─────────────────────────────
    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("canonical_url", sa.String(255), nullable=False),
        sa.Column("verification_status", sa.String(50), nullable=False),
        sa.Column("current_score", sa.Integer(), nullable=False),
        sa.Column("current_grade", sa.String(10), nullable=False),
        sa.Column("current_risk_level", sa.String(50), nullable=False),
        sa.Column("open_critical_count", sa.Integer(), nullable=False),
        sa.Column("open_high_count", sa.Integer(), nullable=False),
        sa.Column("open_medium_count", sa.Integer(), nullable=False),
        sa.Column("open_low_count", sa.Integer(), nullable=False),
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("tech_summary", sa.JSON(), nullable=True),
        sa.Column("tls_summary", sa.JSON(), nullable=True),
        sa.Column("dns_summary", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_assets_user_id", "assets", ["user_id"])
    op.create_index("ix_assets_domain", "assets", ["domain"])

    # ── asset_change_events (formerly missing from migrations) ────────────────
    op.create_table(
        "asset_change_events",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("change_type", sa.String(100), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_asset_change_events_asset_id", "asset_change_events", ["asset_id"])

    # ── share_links (formerly missing from migrations) ────────────────────────
    op.create_table(
        "share_links",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("report_id", sa.Uuid(), sa.ForeignKey("reports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token", sa.String(64), nullable=False),
        sa.Column("is_public", sa.Boolean(), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_share_links_report_id", "share_links", ["report_id"])
    # Model declares token unique=True AND index=True -> unique index.
    op.create_index("ix_share_links_token", "share_links", ["token"], unique=True)

    # ── project_connections (remediation Phase 1) ─────────────────────────────
    op.create_table(
        "project_connections",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("connection_type", _enum(ConnectionType, "connectiontype"), nullable=False),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_project_connections_user_id", "project_connections", ["user_id"])
    op.create_index("ix_project_connections_domain", "project_connections", ["domain"])

    # ── remediation_records (remediation Phase 1) ─────────────────────────────
    op.create_table(
        "remediation_records",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("finding_id", sa.Uuid(), sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_connection_id", sa.Uuid(), sa.ForeignKey("project_connections.id", ondelete="CASCADE"), nullable=False),
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
        sa.Column("verification_scan_id", sa.Uuid(), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("audit_context", sa.JSON(), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_remediation_records_finding_id", "remediation_records", ["finding_id"])
    op.create_index("ix_remediation_records_user_id", "remediation_records", ["user_id"])
    op.create_index("ix_remediation_records_status", "remediation_records", ["status"])

    # ── remediation_audit_logs (remediation Phase 1) ──────────────────────────
    op.create_table(
        "remediation_audit_logs",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("remediation_id", sa.Uuid(), sa.ForeignKey("remediation_records.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("previous_status", sa.String(50), nullable=True),
        sa.Column("new_status", sa.String(50), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
    )
    op.create_index("ix_remediation_audit_logs_remediation_id", "remediation_audit_logs", ["remediation_id"])


def downgrade() -> None:
    # Reverse in dependency order (children before parents).
    op.drop_table("remediation_audit_logs")
    op.drop_table("remediation_records")
    op.drop_table("project_connections")
    op.drop_table("share_links")
    op.drop_table("asset_change_events")
    op.drop_table("assets")
    op.drop_table("audit_logs")
    op.drop_table("sessions")
    op.drop_table("notifications")
    op.drop_table("findings")
    op.drop_table("reports")
    op.drop_table("scans")
    op.drop_table("users")

    # Drop native PostgreSQL enums (SQLite enums are VARCHAR + CHECK, no type).
    if _is_postgresql():
        for enum_name in (
            "userrole", "scanstatus", "risklevel", "severity", "findingstatus",
            "confidence", "connectiontype", "remediationstatus",
        ):
            op.execute(f'DROP TYPE IF EXISTS "{enum_name}"')
