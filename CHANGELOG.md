# Changelog

All notable changes to SentinelScan are documented here.

Format: `[Version] — Date — Category: Description`

---

## [Unreleased]

### Repository & Security Architecture
- **Threat Model**: Added complete threat model and security controls architecture (`docs/THREAT_MODEL.md`) covering SSRF, IDOR, OAuth CSRF, session theft, and worker resilience.
- **GitHub Actions CI/CD**: Added end-to-end multi-job workflow (`.github/workflows/ci.yml`) validating backend Pytest suites, frontend TypeScript/build checks, and repository secret hygiene.
- **Community Templates**: Standardized Pull Request template (`.github/pull_request_template.md`) and Issue Templates (`bug_report.md`, `feature_request.md`, `security_issue.md`).
- **Documentation Polish**: Synchronized all documentation (`docs/Testing.md`, `docs/API.md`, `docs/Frontend.md`, `docs/README.md`) to reflect the 367-test suite, 29 registered detectors, and ticket-authenticated SSE progress architecture.

---

## [1.0.1] — 2026-08-15

### Security & Accuracy
- **False-Positive Hardening**: Hardened server banner regex extraction and false-positive suppression regression suite.
- **SSRF Hardening**: Re-validated DNS resolution and internal/cloud metadata IP filtering across all scan endpoints.

---

## [1.0.0] — 2024 — Initial Release

### Architecture

- **FastAPI backend** with async SQLAlchemy 2.0 and PostgreSQL 16
- **Next.js 14** frontend with App Router, TypeScript, and Tailwind CSS
- **ARQ worker** architecture: scan jobs enqueued to Redis and executed by a separate worker process
- **Docker Compose** orchestration for all services (PostgreSQL, Redis, FastAPI, ARQ Worker, Next.js, Nginx)
- **Alembic** database migrations replacing auto-create tables
- **pydantic-settings** configuration management with production secret validation

### Authentication

- JWT dual-token scheme (30-minute access token + 7-day refresh token)
- **bcrypt** password hashing via passlib
- **Email verification** flow with configurable bypass for development
- **Google OAuth 2.0** social login
- **Redis token blacklist** for immediate logout revocation
- Password reset flow with token expiry
- **Audit log** for all security-relevant events

### Scanner Engine

Seven-stage passive scanning pipeline:
1. DNS analysis (SPF, DMARC, DKIM, MX, A, NS records via dnspython)
2. SSL/TLS certificate analysis (expiry, TLS version, cipher suite)
3. HTTP security header analysis (12 headers + deep CSP/HSTS/CORS analysis)
4. Technology fingerprinting (23 technologies via signature database)
5. CVE lookup via NIST NVD API v2
6. Content analysis (15 sensitive file probes + HTML comment + email scanning)
7. OWASP Top 10 + MITRE ATT&CK threat intelligence mapping

### Detection Accuracy

- **False-positive investigation** of goclasses.in revealed systematic false positives in exposed-file detection
- Implemented **baseline soft-404 fingerprinting**: before probing sensitive paths, the engine captures a baseline "404" response and uses it to reject soft-404 matches
- Implemented **content validation per file type**: `.env` requires ≥ 2 KEY=VALUE lines; `.git/HEAD` requires `ref:` prefix; `.sql` requires SQL dump keywords
- Implemented **admin detection refinement**: requires both `<input type="password">` AND a form action targeting login/admin — generic pages with login navigation are no longer flagged
- **Server header version regex**: tightened from digit-matching to `\w[\w-]*/\d[\d.]*` format — prevents hostname false positives (`github.com`, etc.)
- **DKIM confidence**: downgraded to `info/low` with explicit caveat that custom selectors cannot be enumerated passively

### Dashboard

- Fixed dashboard data loading failure caused by schema mismatch between backend and frontend
- Dashboard API endpoints return correct aggregated score, severity counts, and recent scan data
- SSE progress relay fixed: progress events correctly delivered cross-process via Redis pub/sub

### Worker System

- Migrated from in-process background tasks (`asyncio.create_task`) to **ARQ Redis-backed job queue**
- Scan jobs survive API restarts — jobs persist in Redis
- `task_id` stored in scan record for cancellation and observability
- Job abort support via `Job.abort()` for user-initiated cancellation
- **Reconciliation cron job** runs every 5 minutes to detect and mark orphaned scans
- Cancellation checks between each scanner stage for responsive cancellation
- **Idempotency guards**: completed/cancelled scans detected and skipped on retry attempts
- Worker heartbeat written to Redis; checked by `/api/readiness` endpoint

### Security

- **SSRF protection**: target URLs validated against private/loopback/RFC1918/link-local ranges before job enqueue
- **IDOR protection**: all resource queries filtered by authenticated user ID
- **Rate limiting**: 5 req/min on auth endpoints (slowapi); scans limited to `MAX_ACTIVE_SCANS_PER_USER=2` concurrent active scans per user
- **Production secret validation**: weak SECRET_KEY values rejected at startup in production environment
- **Security headers** added to all API responses (X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- **CORS** limited to configured frontend URL

### PDF Reports

- Full PDF report generation via ReportLab
- Includes executive summary, all findings, OWASP mappings, SSL/TLS details, DNS analysis
- On-demand generation via `GET /api/reports/{id}/pdf`

### Testing

- **126 automated tests** passing with 0 failures
- `test_accuracy.py` — false-positive detection, soft-404, content validation
- `test_auth_security.py` — JWT, token revocation, password hashing
- `test_core.py` — full scan lifecycle, user registration
- `test_delta.py` — scan comparison / delta
- `test_idor.py` — IDOR protection
- `test_pdf.py` — PDF generation
- `test_reliability.py` — worker recovery, reconciliation, Redis auth failsafe
- `test_server_dkim.py` — server header FP regression, DKIM confidence
- `test_ssrf.py` — SSRF protection
- `test_worker.py` — ARQ job lifecycle, cancellation, idempotency

### Report Features

- Security score: 0–100 weighted across 7 categories
- Grade: A+ through F based on score thresholds
- Per-category score breakdown with color-coded visualization
- Executive summary with business impact, strengths, weaknesses, quick wins
- Scan timeline with per-stage duration
- Public report sharing via signed tokens with expiry
- Scan comparison (delta between two scans)

---

## Pre-release Development History

### Worker Migration

The system initially used `asyncio.create_task` for background scan execution. This approach had a critical flaw: any API restart would silently kill all running scans and leave them in a permanently `running` state with no mechanism for recovery.

The migration to ARQ solved this by:
1. Making scans durable — jobs persist in Redis across API restarts
2. Providing explicit retry logic — ARQ retries jobs up to 3 times
3. Enabling true worker isolation — scans and the API run in separate processes
4. Supporting reconciliation — a periodic cron detects and marks orphaned scans

### Dashboard Fix

The dashboard was returning empty data (`score: 0, findings: 0`) despite scans existing. Root cause: the dashboard API was making an authenticated request but the frontend was attaching the token incorrectly, causing 401 errors that were silently caught. Fixed by:
1. Correcting the frontend API client auth header attachment
2. Adding explicit error handling with toast notifications
3. Fixing the backend dashboard endpoint to correctly aggregate across the user's most recent scan

### False-Positive Fix

During accuracy validation against goclasses.in (~25 false-positive findings), investigation revealed that the exposed-file detector was reporting "Exposed .env File" based solely on HTTP 200 response code and content-type, without validating whether the response body actually contained environment variable syntax.

The fix added:
1. Baseline soft-404 detection (compare probe response to known-nonexistent path response)
2. Content type validation (HTML responses rejected for data file paths)
3. Minimum content validation (`.env` requires ≥ 2 KEY=VALUE lines, not just one)
4. Token-overlap heuristic (if probe body overlaps 50%+ with baseline error page, it's a soft-404)
