# Testing

## Philosophy

SentinelScan's test suite is designed around one principle: **tests must validate actual behaviour, not mock it away**. Where external dependencies (database, Redis) would make tests slow, lightweight in-memory or SQLite alternatives are used — but scanner logic is tested against real heuristics.

---

## Test Suite Overview

```
backend/tests/
├── test_accuracy.py              # Scanner accuracy, FP detection, soft-404 verification
├── test_active_safety.py         # Passive-only boundary and non-intrusive safety checks
├── test_admin_users.py           # Admin center permissions, telemetry, and management
├── test_ai.py                    # Sentinel Intelligence grounding rules, sanitization, chat
├── test_arq_pool.py              # Shared ARQ Redis pool reuse and concurrency safety
├── test_auth_rate_limiting.py    # Slowapi rate limits on authentication endpoints
├── test_auth_regression.py       # Token blacklist TTL, logout revocation, refresh logic
├── test_auth_security.py         # Password hashing, email verification, secret validation
├── test_benchmark.py             # Server header version extraction benchmark regression
├── test_component_engine.py      # Component fingerprinting and semver parser
├── test_confidence.py            # Finding confidence assignment and threshold logic
├── test_controlled_evaluation.py # Controlled active probing safety constraints
├── test_core.py                  # Full scan lifecycle, user registration, auth flows
├── test_crawler.py               # Single-page target parsing and link extract constraints
├── test_email_service.py         # SMTP delivery, template rendering, and error handling
├── test_exporter.py              # CSV/HTML/JSON export generation and formula sanitization
├── test_exposure_detector.py     # 45 External Exposure detectors across all 12 domains (36 tests)
├── test_fp_regression.py         # False-positive suppression regressions
├── test_hsts_deduplication.py    # Cross-detector HSTS deduplication and canonical keys
├── test_hybrid_pipeline.py       # Hybrid scan execution and stage sequencing
├── test_idor.py                  # IDOR tenant isolation db boundary verification
├── test_lifecycle.py             # Scan state machine, cooperative cancellation, idempotency
├── test_oauth.py                 # Google OAuth 2.0 flow, CSRF state lifecycle, account-linking
├── test_outbound_tls.py          # Strict outbound SNI and TLS certificate verification
├── test_owasp_2025_regression.py # OWASP Top 10:2025 category mapping regressions
├── test_owasp_modules.py         # Core OWASP passive inspection heuristics
├── test_pdf.py                   # Executive/Technical PDF generation and redaction
├── test_port_policy.py           # Port restrictions and non-standard port blocking
├── test_readiness.py             # DB, Redis, and Worker health check readiness probes
├── test_reliability.py           # Worker heartbeat recovery, orphan scan reconciliation
├── test_report_limits.py         # Report pagination, sizing, and finding clamping
├── test_response_body_limits.py  # Response payload size clamping and streaming safety
├── test_sanitize.py              # Secret redaction, CSV sanitization, finding length clamping
├── test_scan_deletion.py         # Active scan protection and history deletion constraints
├── test_scan_pipeline_e2e.py     # End-to-end worker queue, SSE, reconciliation tests
├── test_scan_rate_limit.py       # Max active scans per user & per-hour scan rate limits
├── test_server_dkim.py           # Server banner parsing and DKIM selector heuristics
├── test_sse_stream.py            # Redis pub/sub progress streaming and disconnect handling
├── test_sse_ticket.py            # Single-use ticket issuance, TTL expiry, stream auth
├── test_ssrf.py                  # IPv4, IPv6, loopback, link-local, cloud metadata SSRF validation
├── test_visual_chat.py           # Circle to Sentinel visual region chat, DOM text, and safety
└── test_worker.py                # ARQ job lifecycle, cancellation, idempotency
```

**Final Verified Test Baseline:**
- **Full Backend Test Suite:** **907 tests passed, 0 failures, 0 errors** (38 downstream deprecation warnings from `python-jose` `datetime.utcnow()` and `reportlab` `ast.NameConstant`; zero project-level warnings)
- **External Exposure Test Suite (`test_exposure_detector.py`):** **36/36 tests passed**
- **Circle to Sentinel Visual Chat Suite (`test_visual_chat.py`):** **21 tests passed**
- **Historical Milestones:** 871 tests (AI & hardening baseline) → 806 tests → 774 tests → 704 tests → 565 tests (early scanner prototype)
- **Frontend Quality Assurance:** TypeScript type-check (`npm run type-check`) **PASS**; Next.js 14 production build (`npm run build`) **PASS** (20/20 routes prerendered cleanly)

---

## Running Tests

```bash
cd backend

# Run all tests using the virtual environment
.venv\Scripts\python.exe -m pytest tests/ -v     # Windows
# .venv/bin/python -m pytest tests/ -v          # macOS/Linux

# Run a specific test file
.venv\Scripts\python.exe -m pytest tests/test_accuracy.py -v

# Run a specific test class
.venv\Scripts\python.exe -m pytest tests/test_worker.py::TestScanStateMachine -v

# Run with short traceback
.venv\Scripts\python.exe -m pytest tests/ --tb=short

# Run with coverage report
.venv\Scripts\python.exe -m pytest tests/ --cov=app --cov-report=html
# Open htmlcov/index.html in browser
```

**Dependencies:** Install both runtime and testing requirements:
```bash
pip install -r requirements.txt -r requirements-dev.txt
```

---

## Test Files in Detail

### `test_accuracy.py` — Scanner Detection Accuracy

Tests the false-positive mitigation logic in the content analyzer and URL validator.

**What's tested:**
- Soft-404 detection: a page returning HTTP 200 for a nonexistent path is correctly classified as a soft-404, not a real finding
- Environment file validation: content that looks like `.env` but is HTML is rejected
- Content validator: `.git/HEAD`, `.env` pattern matching (minimum 2 KEY=VALUE lines)
- Exposed admin panel: requires both password `<input>` and login form `action` — generic pages are not flagged

**Example:**
```python
def test_soft_404_suppresses_env_finding():
    """A site returning 200 for all paths should not produce false-positive .env finding"""
    # Baseline is identical to probe response → classified as soft-404
    assert _is_soft_404(baseline, response, "/.env") is True
```

---

### `test_auth_security.py` — Authentication Security

Tests the security properties of the authentication system.

**What's tested:**
- JWT creation: access and refresh tokens have correct `type` claim
- JWT type enforcement: refresh token cannot be used as access token
- Wrong token type rejection: passing wrong type raises exception
- Password hashing: bcrypt produces different hashes for same input (salted)
- Password verification: constant-time comparison
- Token blacklist: revoked token is rejected on subsequent requests
- Expiry: expired tokens rejected

---

### `test_core.py` — Core Business Logic

29 tests covering the entire user and scan lifecycle.

**Test classes:**
- `TestSecurityUtils` — token creation, decoding, hashing
- `TestScanLifecycle` — scan status transitions, progress updates
- `TestUserRegistration` — email normalization, duplicate prevention
- `TestAuthFlow` — login, JWT validation, verification requirement
- `TestNotifications` — notification creation and read status
- `TestReportGeneration` — score calculation from finding sets
- `TestDashboardData` — dashboard summary aggregation

---

### Scan Lifecycle & Reconciliation Tests

`test_lifecycle.py` and `test_worker.py` cover the scan state machine (`pending → running → completed|failed|cancelled`), cooperative cancellation, idempotency, and the 5-minute `reconcile_orphan_scans` cron. The legacy `delta_engine.py` scan-comparison service and `test_delta.py` documented here previously do not exist in the current codebase (scan-comparison/delta intelligence was retired).

---

### `test_idor.py` — IDOR Protection

Verifies that a user cannot access resources belonging to another user.

```python
def test_user_cannot_access_other_user_report():
    """Report query must include user_id filter"""
    # Create two users, user_a has a report
    # user_b queries report by ID — must get 404
```

---

### `test_pdf.py` — PDF Generation

**What's tested:**
- PDF bytes are non-empty for a complete report
- PDF header (`%PDF`) is present in the output
- PDF generates without raising exceptions for reports with zero findings

---

### `test_reliability.py` — Worker Reliability

35 tests covering all failure scenarios in the worker system.

**Test classes:**

**`TestRetryExhaustion`** — behaviour when all retry attempts fail:
- Timeout message is safe (no exception propagation)
- `CancelledError` on final attempt marks scan as failed
- `CancelledError` on non-final attempt re-raises (allows ARQ retry)

**`TestReconciliation`** — orphan scan cleanup:
- Pending scans past grace period with no ARQ job → marked failed
- Pending scans within grace period → not touched
- Pending scans with queued ARQ job → not touched
- Running scans with in-progress ARQ job → not touched
- Running scans past retry window with no ARQ job → marked failed
- Cancelled/completed scans → never touched by reconciliation
- Reconciliation is idempotent (running twice produces same result)
- No active scans → returns OK without error

**`TestProductionRedisAuth`** — Redis failsafe for token blacklisting:
- Blacklist raises in production when Redis is down
- Blacklist is a no-op (logged) in development when Redis is down
- Blacklist succeeds when Redis is available

**`TestTaskIdConsistency`** — ARQ job ID management:
- Job ID format is deterministic
- Different scans get different job IDs
- Job ID is never empty or None
- Reconciliation uses stored `task_id`, not a derived value

**`TestWorkerRecovery`** — worker configuration validation:
- Scan status enum values are distinct (no overlap)
- ARQ retry window is adequate (≥ max_tries * timeout)
- Reconcile orphan grace period exceeds single timeout
- Completed scan is skipped by late retry (idempotency)

---

### `test_server_dkim.py` — False-Positive Regression Tests

19 tests specifically covering the two accuracy improvements made during the FP investigation:

**`TestServerDisclosure`** — server header version detection:
```python
def test_apache_version_detected():
    # "Apache/2.4.58" → medium severity (correctly flagged)

def test_hostname_github_not_version():
    # "github.com" → no version disclosure finding (FP prevented)

def test_cloudflare_skipped():
    # "cloudflare" → silently skipped (known benign CDN)
```

**`TestDkimConfidence`** — DKIM detection severity:
```python
def test_dkim_not_detected_is_info_severity():
    # Missing DKIM → info (not medium/high)

def test_dkim_not_detected_evidence_contains_caveat():
    # Evidence text mentions custom selectors caveat

def test_no_mx_records_no_dkim_finding():
    # No mail server → no DKIM finding emitted
```

---

### `test_ssrf.py` — SSRF Protection

```python
def test_ssrf_forbidden_ip_addresses():
    # localhost, 127.0.0.1, 192.168.1.1, 10.0.0.1 → all rejected

def test_ssrf_forbidden_urls():
    # http://internal/, http://169.254.169.254/ → rejected

def test_ssrf_valid_public_urls():
    # https://example.com, https://google.com → allowed
```

---

### `test_worker.py` — ARQ Worker Logic

29 tests across 7 test classes:

**`TestScanStateMachine`** — status enum and transitions:
- Terminal states are correct: `completed`, `failed`, `cancelled`
- Valid transitions defined
- Completed cannot transition
- Cancelled cannot become completed

**`TestScanTaskIdempotency`** — duplicate job safety:
- Completed scan skipped (no double report)
- Cancelled scan skipped
- Nonexistent scan handled gracefully

**`TestCancellationRaceSafety`** — concurrent state conflicts:
- `mark_failed_safe` respects `cancelled` status (does not overwrite)
- `mark_failed_safe` respects `completed` status
- `is_cancelled` returns True for cancelled scans
- `is_cancelled` returns False for running scans

**`TestProgressUtility`** — SSE progress events:
- `publish_progress` writes correct JSON structure to Redis
- Last event is persisted for SSE reconnect
- `get_last_event` returns None when key missing
- Progress tolerates Redis failures (does not raise)

**`TestDeterministicJobId`** — job ID generation:
- Correct format
- Unique IDs for unique scans

**`TestEnqueueFailure`** — Redis unavailable:
- 503 returned when job cannot be enqueued
- Scan status set to `failed` when enqueue fails

**`TestWorkerConfig`** — configuration sanity:
- `max_tries ≥ 1 and ≤ 5`
- `max_jobs ≥ 1`
- `job_timeout ≥ 60` seconds
- Queue name is a non-empty string

---

## Test Infrastructure

Tests use **pytest** with:
- `pytest-asyncio` for async test functions
- `unittest.mock` for mocking external dependencies (Redis, SMTP)
- In-memory SQLite (via aiosqlite) where database is needed
- Real heuristic logic (no mocking of scanner modules themselves)

**`pytest.ini`:**
```ini
[pytest]
asyncio_mode = auto
```

---

## What Is NOT Tested

The following are explicitly not covered by automated tests and require manual validation:

| Area | Reason |
|---|---|
| Real DNS lookups | Require network access; non-deterministic |
| Real SSL handshakes | Require network access; certificate data changes |
| Live NVD API queries | Rate-limited; non-deterministic |
| End-to-end browser tests | No Playwright/Selenium suite implemented |
| Email delivery | SMTP sends are mocked |
| PDF visual fidelity | Only binary output validated, not rendering |

---

## Coverage

```bash
python -m pytest tests/ --cov=app --cov-report=term-missing
```

Highest coverage areas:
- `models/` — 95%+ (simple SQLAlchemy models)
- `scanner/scoring.py` — 90%+
- `tasks/scan_task.py` — 85%+
- `utils/security.py` — 90%+
- `routers/auth.py` — 75%+ (auth flow well-tested)

Lowest coverage areas:
- `routers/reports.py` — PDF generation path (covered by unit and integration tests)
