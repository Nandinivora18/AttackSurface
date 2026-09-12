# Database

## Overview

SentinelScan supports dual database engines: **SQLite** via `aiosqlite` for local development and rapid automated testing, and **PostgreSQL 16** via `asyncpg` for multi-tenant production deployments. Database access is managed through **SQLAlchemy 2.0** (async ORM) and **Alembic** for schema migrations. The schema is designed around a clear ownership hierarchy: every resource belongs to a user.

---

## Entity-Relationship Diagram

```mermaid
erDiagram
    users {
        UUID id PK
        string email UK
        string name
        string password_hash
        string google_id UK
        string avatar_url
        enum role
        bool is_verified
        string email_verification_token
        datetime email_verification_expires
        string password_reset_token
        datetime password_reset_expires
        datetime created_at
        datetime updated_at
        datetime last_login
    }

    scans {
        UUID id PK
        UUID user_id FK
        string url
        enum status
        int progress
        string current_stage
        text error_message
        string cancellation_reason
        datetime started_at
        datetime completed_at
        string scan_mode
        json scope_config
        json timeline
        datetime created_at
        string task_id
    }

    reports {
        UUID id PK
        UUID scan_id FK UK
        UUID user_id FK
        int overall_score
        string grade
        enum risk_level
        text summary
        json tech_stack
        json raw_headers
        json ssl_info
        json dns_info
        json score_breakdown
        string scan_mode
        json executive_summary
        json timeline
        datetime created_at
    }

    findings {
        UUID id PK
        UUID report_id FK
        string category
        string title
        text description
        enum severity
        float cvss_score
        string cve_id
        date published_date
        text recommendation
        text problem
        text impact
        text risk_analysis
        text technical_details
        json fix_steps
        text configuration_example
        text best_practices
        string official_documentation
        json references
        text evidence
        string owasp_mapping
        string mitre_mapping
        enum status
        bool is_passed_control
        datetime created_at
    }

    notifications {
        UUID id PK
        UUID user_id FK
        string type
        string title
        text message
        bool is_read
        json metadata
        datetime created_at
    }

    audit_logs {
        UUID id PK
        UUID user_id FK
        string action
        string resource
        UUID resource_id
        string ip_address
        json metadata
        datetime created_at
    }

    users ||--o{ scans : "owns"
    users ||--o{ reports : "owns"
    users ||--o{ notifications : "receives"
    users ||--o{ audit_logs : "generates"
    scans ||--o| reports : "produces"
    reports ||--o{ findings : "contains"
```

---

## Table Reference

### `users`

The central identity table. All other resources reference this table.

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | UUID | PK, default=uuid4 | User's unique identifier |
| `email` | VARCHAR(255) | UNIQUE, NOT NULL, indexed | Login email — normalized to lowercase |
| `name` | VARCHAR(255) | NOT NULL | Display name |
| `password_hash` | VARCHAR(255) | nullable | bcrypt hash; NULL for OAuth-only users |
| `google_id` | VARCHAR(255) | UNIQUE, nullable | Google OAuth subject identifier |
| `avatar_url` | VARCHAR(512) | nullable | Profile picture URL |
| `role` | ENUM | NOT NULL, default=`user` | `user` or `admin` |
| `is_verified` | BOOLEAN | NOT NULL, default=false | Email verification status |
| `email_verification_token` | VARCHAR(255) | nullable | SHA-256 of verification secret |
| `email_verification_expires` | TIMESTAMP TZ | nullable | Verification token expiry |
| `password_reset_token` | VARCHAR(255) | nullable | SHA-256 of reset secret |
| `password_reset_expires` | TIMESTAMP TZ | nullable | Reset token expiry |
| `created_at` | TIMESTAMP TZ | server_default=NOW() | Account creation time |
| `updated_at` | TIMESTAMP TZ | server_default=NOW(), onupdate | Last profile update |
| `last_login` | TIMESTAMP TZ | nullable | Last successful login timestamp |

**Indexes:** `email` (unique), `google_id` (unique)

**Why it exists:** Central identity store. All resources (scans, reports, notifications) cascade-delete when a user is deleted.

---

### `scans`

One record per scan job. Tracks the scan lifecycle from pending through completion.

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | Scan identifier |
| `user_id` | UUID FK → users | Owner (indexed) |
| `url` | VARCHAR(2048) | Target URL |
| `status` | ENUM | `pending`, `running`, `completed`, `failed`, `cancelled` |
| `progress` | INTEGER | 0–100 completion percentage |
| `current_stage` | VARCHAR(100) | Human-readable current stage name |
| `error_message` | TEXT | Error detail if status=failed |
| `cancellation_reason` | VARCHAR(255) | Set on user cancellation |
| `started_at` | TIMESTAMP TZ | When worker picked up the job |
| `completed_at` | TIMESTAMP TZ | When scan finished |
| `scan_mode` | VARCHAR(20) | `passive` |
| `scope_config` | JSON | Scope configuration (profile, crawl depth, max requests) |
| `timeline` | JSON | Stage-by-stage timing breakdown |
| `created_at` | TIMESTAMP TZ | When scan was created |
| `task_id` | VARCHAR(255) | ARQ job ID for cancellation/observability |

**Indexes:** `user_id`

**Why it exists:** Tracks the full lifecycle of every scan. The `task_id` enables ARQ job lookup for cancellation. The `timeline` JSON stores per-stage timing for report display.

---

### `reports`

One report per completed scan (1:1 relationship). Stores the aggregated scan output.

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | Report identifier |
| `scan_id` | UUID FK → scans | Parent scan (UNIQUE — one report per scan) |
| `user_id` | UUID FK → users | Owner (indexed) |
| `overall_score` | INTEGER | 0–100 security score |
| `grade` | VARCHAR(3) | Letter grade: A+, A, B, C, D, F |
| `risk_level` | ENUM | `critical`, `high`, `medium`, `low`, `info` |
| `summary` | TEXT | Plain-text executive summary |
| `tech_stack` | JSON | Detected technologies dict |
| `raw_headers` | JSON | Complete HTTP response headers |
| `ssl_info` | JSON | Certificate details, TLS version, cipher |
| `dns_info` | JSON | SPF, DMARC, DKIM, MX, A, NS records |
| `score_breakdown` | JSON | Per-category scores and penalties |
| `scan_mode` | VARCHAR(20) | Matches parent scan's scan_mode |
| `executive_summary` | JSON | Structured business impact analysis |
| `timeline` | JSON | Scan stage timing summary |
| `created_at` | TIMESTAMP TZ | Report creation time |

**Why it exists:** Separates scan metadata (status, progress) from scan results (findings, scores). A report only exists when a scan completes successfully.

---

### `findings`

Every individual security finding produced by a scan, stored as a structured record.

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | Finding identifier |
| `report_id` | UUID FK → reports | Parent report (indexed) |
| `category` | VARCHAR(100) | E.g. "SSL/TLS", "Email Security", "Cookie" |
| `title` | VARCHAR(255) | Short finding title |
| `description` | TEXT | Detailed explanation |
| `severity` | ENUM | `critical`, `high`, `medium`, `low`, `info` |
| `status` | ENUM | `open`, `accepted_risk`, `resolved`, `false_positive` |
| `confidence` | ENUM | `high`, `medium`, `low` |
| `cvss_score` | DECIMAL(4,1) | CVSS v3 score (nullable) |
| `cve_id` | VARCHAR(25) | CVE identifier (indexed, nullable) |
| `cwe_id` | VARCHAR(25) | CWE identifier (nullable) |
| `endpoint` | VARCHAR(255) | Affected path/endpoint |
| `published_date` | DATE | NVD published date (nullable) |
| `recommendation` | TEXT | Remediation guidance |
| `problem` | TEXT | Root cause explanation |
| `impact` | TEXT | Business impact description |
| `risk_analysis` | TEXT | Risk context |
| `technical_details` | TEXT | Technical implementation details |
| `fix_steps` | JSON | Step-by-step remediation list |
| `configuration_example` | TEXT | Example secure configuration |
| `best_practices` | TEXT | Security best practices |
| `official_documentation` | TEXT | Reference to official docs |
| `references` | JSON | Array of reference URLs |
| `evidence` | TEXT | Proof of finding (redacted) |
| `owasp_mapping` | JSON | `{id, title, description, reference}` |
| `mitre_mapping` | JSON | `{technique_id, technique_name, description, reference}` |
| `is_passed_control` | BOOLEAN | True for info-severity passing checks |
| `created_at` | TIMESTAMP TZ | Finding creation time |

**Indexes:** `report_id`, `cve_id`

**Why it exists:** Findings are the primary value output of a scan. Each finding is a self-contained security assertion with full metadata for PDF export, API consumption, and frontend display.

---

### `notifications`

In-app notifications delivered to users.

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | Notification identifier |
| `user_id` | UUID FK → users | Recipient (indexed) |
| `type` | VARCHAR(50) | E.g. `scan_complete`, `scan_failed` |
| `title` | VARCHAR(255) | Notification title |
| `message` | TEXT | Notification body |
| `is_read` | BOOLEAN | Read status |
| `metadata_` | JSON | Additional data (e.g. scan_id, report_id) |
| `created_at` | TIMESTAMP TZ | Creation time |

---

### `audit_logs`

Security event log for authentication and administrative actions.

| Column | Type | Description |
|---|---|---|
| `id` | UUID PK | Log entry identifier |
| `user_id` | UUID FK → users | Actor (nullable — for failed login attempts) |
| `action` | VARCHAR(100) | E.g. `login`, `logout`, `register`, `scan_cancelled` |
| `resource` | VARCHAR(100) | Resource type affected |
| `resource_id` | UUID | Resource identifier |
| `ip_address` | VARCHAR(45) | Client IP |
| `metadata_` | JSON | Additional context |
| `created_at` | TIMESTAMP TZ | Event time |

---

## Migration Strategy

Database migrations are managed by **Alembic**. The current active database schema consists of the core models (`users`, `scans`, `reports`, `findings`, `notifications`, `audit_logs`, `remediations`). Schema changes and dialect-portable upgrades are managed via Alembic (with historical migration `7340c9ab6be5` dropping retired tables) ensuring byte-identical synchronization with `Base.metadata` (verified with `alembic check`).

```bash
# Apply all pending migrations (from an empty or existing database)
alembic upgrade head

# Generate a new migration from model changes
alembic revision --autogenerate -m "description"

# Rollback one step
alembic downgrade -1

# View migration history
alembic history

# Verify the current DB schema matches the models (no drift)
alembic check
```

**In Docker:** The backend container runs `alembic upgrade head` before starting Uvicorn.

### Production Database Rule

**Production databases are initialized and upgraded using Alembic migrations. `create_all()` is not relied upon for production schema creation.**

The application enforces this: at startup, `create_tables()` (which calls `Base.metadata.create_all()`) runs **only when `ENVIRONMENT != "production"`** (development/test convenience). In production, `create_all()` is gated off and schema is managed exclusively by `alembic upgrade head`.

---

## Cascade Delete Policy

| Parent | Child | On Delete |
|---|---|---|
| `users` | `scans` | CASCADE |
| `users` | `reports` | CASCADE |
| `users` | `notifications` | CASCADE |
| `users` | `audit_logs` | SET NULL |
| `scans` | `reports` | CASCADE |
| `reports` | `findings` | CASCADE |
