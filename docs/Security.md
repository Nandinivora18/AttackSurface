# Security Model

## Overview

SentinelScan implements a layered security architecture based on defense-in-depth principles. Each layer is independently documented below with its implementation, trust assumptions, and known limitations.

---

## Authentication

### JWT Token Architecture

SentinelScan uses a **dual-token authentication scheme** — a short-lived access token and a long-lived refresh token:

| Token | Type | Lifetime | Storage |
|---|---|---|---|
| Access Token | `access` | 30 minutes | Memory / Authorization header |
| Refresh Token | `refresh` | 7 days | Secure cookie / localStorage |

**Algorithm:** HS256 (HMAC-SHA256) via `python-jose`

**Claims:**
```json
{
  "sub": "user-uuid",
  "type": "access",
  "jti": "unique-token-identifier",
  "iat": 1700000000,
  "exp": 1700001800
}
```

The `jti` (JWT ID) claim is a UUID generated per token and used for blacklisting.

### Token Creation

```python
# Access token: short-lived
create_access_token(user_id)   # exp=30min

# Refresh token: long-lived
create_refresh_token(user_id)  # exp=7days
```

Both tokens encode `type` (`access` or `refresh`) to prevent refresh tokens from being used as access tokens and vice versa.

### Token Verification

Every protected endpoint calls `get_verified_user()` which:

1. Extracts `Authorization: Bearer {token}` from the request
2. Calls `decode_token()` — validates signature, expiry, and `type=access`
3. Checks Redis blacklist: `GET blacklist:{jti}` — if present, rejects with 401
4. Queries the database for the user record
5. Verifies `user.is_verified == True` (email verification enforced)
6. Returns the user object

### Password Hashing

All passwords are hashed with **bcrypt** via `passlib`:

```python
hash_password(password)   # bcrypt rounds=12 (default)
verify_password(plain, hashed)   # constant-time comparison
```

bcrypt is intentionally slow to compute, making offline brute-force attacks computationally expensive.

### Token Blacklist (Redis)

On logout, the access token's `jti` is stored in Redis with a TTL equal to the token's remaining lifetime:

```python
SETEX blacklist:{jti} {remaining_seconds} "1"
```

This ensures the blacklist entry self-expires when the token would have expired anyway, keeping Redis memory usage bounded.

**Refresh token revocation:** If the client supplies a `refresh_token` in the logout request body, its JTI is also blacklisted. The refresh endpoint (`POST /api/auth/refresh`) checks the blacklist before issuing new tokens, so a revoked refresh token cannot obtain fresh access tokens.

```python
# Logout body (backward-compatible — refresh_token is optional)
{"refresh_token": "<optional>"}  # access token always revoked via Authorization header
```

**SSE stream authentication:** The real-time scan progress endpoint (`GET /api/scans/{id}/stream`) accepts a `?token=` query parameter. After decoding the JWT it also calls `is_token_blacklisted(jti)`, matching the blacklist semantics of all REST endpoints.

**Production behaviour:** If Redis is unavailable in production, token blacklisting raises an exception (fail-secure) and logout returns 503. In development, the operation logs a warning and falls back to an in-memory store.

### Email Verification

New accounts require email verification before they can log in:

1. On registration, a `email_verification_token` (SHA-256 of a random secret) is stored with a 24-hour expiry
2. The verification URL is emailed to the user
3. On `GET /api/auth/verify/{token}`, the token is validated and `is_verified` set to True
4. `REQUIRE_EMAIL_VERIFICATION=True` is enforced in production; the config validator rejects `False` in production environments

**Development bypass:** `DEV_BYPASS_EMAIL_VERIFICATION=True` allows skipping email verification locally without SMTP. This flag is **explicitly rejected at startup if `ENVIRONMENT=production`**.

---

## Google OAuth

Google OAuth 2.0 is implemented with:

1. `GET /api/auth/google/login` → redirects to Google authorization URL with `state` parameter
2. Google redirects to `GET /api/auth/google/callback?code=...&state=...`
3. State is validated to prevent CSRF
4. Authorization code exchanged for Google access token
5. Google user info fetched (`/userinfo` endpoint)
6. User created or found by `google_id`; JWT pair issued

Google OAuth users do not have a `password_hash` and cannot use email/password login.

---

## Authorization (RBAC)

### Roles

| Role | Capabilities |
|---|---|
| `user` | Manage own scans, reports, notifications, profile |
| `admin` | All user capabilities + admin panel access |

Role is stored as `UserRole` enum in the database and checked via `get_current_admin_user()` dependency.

### Resource Ownership (IDOR Protection)

All queries for scans, reports, and findings include a `WHERE user_id = current_user.id` condition enforced **at the database query level**. It is not possible to access another user's data by guessing or enumerating IDs:

```python
# Example — enforced on every report query
report = await db.execute(
    select(Report)
    .where(Report.id == report_id)
    .where(Report.user_id == current_user.id)  # ← ownership enforced in DB
)

# Finding detail — ownership enforced via JOIN (not post-load)
finding = await db.execute(
    select(Finding)
    .join(Finding.report)
    .where(
        Finding.id == finding_id,
        Report.user_id == current_user.id,  # ← DB-level ownership via JOIN
    )
    .options(selectinload(Finding.report))
)
```

Using a DB-level `JOIN` for the finding detail endpoint eliminates a class of race condition where a post-load ownership check could be defeated by database state changes.

UUID primary keys (randomly generated) make ID enumeration infeasible even without ownership checks.

**Public report sharing:** The `GET /api/reports/shared/{token}` endpoint is intentionally public — share tokens are only creatable by the authenticated report owner, and optional password protection and expiry may be configured. This is documented as an intentional public-share security model; normal user ownership checks are deliberately not applied to the share endpoint.

**Test coverage:** `test_idor.py` and `test_auth_regression.py` verify that DB-level ownership filtering is in place.

### Remediation Authorization

Remediation endpoints enforce domain-level authorization:

- A `ProjectConnection` must exist for the user with the exact normalized hostname matching the scan target
- No credentials are stored — the connection proves domain ownership via DNS/HTTP verification
- The remediation engine (`app/remediation/engine.py`) normalizes domains before matching
- State machine violations (invalid transitions) return HTTP 409 Conflict
- All state transitions are logged to `remediation_audit_logs` for auditability

**Contract:** All remediation probes are passive read-only — the system never connects to or modifies user servers.

---

## SSRF Prevention

The scan creation endpoint validates every target URL against SSRF (Server-Side Request Forgery) attacks before enqueuing a job. DNS resolution runs **off the event loop** via `asyncio.to_thread()` so that slow or timing-out DNS lookups do not stall other concurrent API requests:

```python
async def _is_ssrf_safe_url(url: str) -> tuple[bool, str]:
    # URL parsing and hostname extraction (sync, fast)
    ...
    # DNS resolution runs in a thread pool — never blocks the event loop
    return await asyncio.to_thread(_ssrf_check_blocking, hostname)

def _ssrf_check_blocking(hostname: str) -> tuple[bool, str]:
    # Blocks localhost and loopback literals
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "internal"):
        return False, "..."

    # DNS resolves the hostname and checks all returned IPs
    addresses = socket.getaddrinfo(hostname, None)
    for _, _, _, _, sockaddr in addresses:
        ip_obj = ipaddress.ip_address(sockaddr[0])
        # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
        if isinstance(ip_obj, IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
            return False, "..."
```

The `safe_http.py` module also exposes `async_validate_url_target()` — an async wrapper around the synchronous `validate_url_target()` — used by `safe_fetch_http()` to validate every redirect hop without blocking the event loop.

**Blocked networks:**
- `127.0.0.0/8` — loopback
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — RFC 1918 private
- `169.254.0.0/16` — link-local (AWS metadata: `169.254.169.254`)
- `::1` — IPv6 loopback
- `fc00::/7` — IPv6 unique local
- `fe80::/10` — IPv6 link-local
- IPv4-mapped IPv6 addresses (`::ffff:...`) — unwrapped and checked against IPv4 rules
- Unspecified addresses (`0.0.0.0`, `::`) — rejected
- DNS failure (NXDOMAIN, SERVFAIL, timeout) — rejected (fail-closed)

**Test coverage:** `test_ssrf.py` verifies private, loopback, link-local, and DNS-failure scenarios against both the synchronous and async validation paths.

---

## Rate Limiting

Rate limiting is implemented via `slowapi` (Starlette middleware wrapping `limits`):

| Endpoint Group | Limit |
|---|---|
| Auth endpoints (`/api/auth/*`) | 5 requests / minute per IP |
| `POST /api/auth/dev-verify` | 10 requests / minute per IP |
| `POST /api/auth/resend-verification` | 10 per 15 minutes per IP + 3 per 15 minutes per email (Redis) |
| Scan creation (`POST /api/scans`) | Max 2 concurrent scans per user (`MAX_ACTIVE_SCANS_PER_USER`) |

Rate limit exceeded returns `429 Too Many Requests`.

The `POST /api/auth/dev-verify` endpoint is already blocked in production (`ENVIRONMENT=production` returns 403); rate limiting provides an additional safety layer for staging/development environments where the endpoint is active.

The global rate limiter key function is `get_remote_address` which uses `X-Forwarded-For` when behind a proxy (Nginx).

---

## Input Validation

**Pydantic v2** validates all request bodies. Invalid payloads return `422 Unprocessable Entity` before reaching handler code.

**URL validation:**
- Must start with `http://` or `https://` (added automatically if missing)
- Hostname must resolve via DNS
- Hostname must not resolve to private/loopback ranges (SSRF check)

**Email validation:** `email-validator` library enforces RFC 5321 email format.

**Password requirements:** Minimum 8 characters (enforced in `UserCreate` schema).

---

## Secrets Management

**SECRET_KEY:**
- Used to sign all JWTs
- Minimum 32 characters enforced at startup in production
- Known placeholder values (`changeme`, `secret`, `dev`, etc.) rejected in production
- Generated securely: `python -c "import secrets; print(secrets.token_hex(32))"`

**SMTP credentials:** Stored only in `.env` file; never committed to version control.

**Database credentials:** Passed via environment variables in Docker Compose; not hardcoded.

**NVD API key:** Optional; stored in `.env` only.

---

## Security Headers (API Responses)

The FastAPI middleware stack adds security headers to every response:

```python
response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["X-Frame-Options"] = "DENY"
response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
response.headers["Content-Security-Policy"] = csp  # see below
response.headers["X-Response-Time"] = f"{elapsed_ms}ms"
```

**Content-Security-Policy** is set per-route:

| Route | CSP |
|---|---|
| All API / JSON routes (production) | `default-src 'none'; frame-ancestors 'none'` |
| `/api/docs`, `/api/redoc` (DEBUG=True only) | Relaxed (allows Swagger/ReDoc scripts, scoped to dev) |

Docs routes are only available when `DEBUG=True` (enforced by the FastAPI app config); in production, `docs_url` and `redoc_url` are `None`, so the relaxed CSP path is never reached.

HSTS is left to Nginx in production (where TLS termination occurs).

---

## Worker Isolation

The ARQ worker runs as a **completely separate process** from the FastAPI API:

- Workers communicate only through Redis (job queue) and PostgreSQL (data)
- A compromised worker cannot directly affect API process memory
- Worker concurrency is limited to `WORKER_CONCURRENCY` (default: 5) simultaneous jobs
- Each scan runs within a single asyncio task; long-running scans are bounded by `MAX_SCAN_TIMEOUT` (600 seconds)

---

## Docker Security

In the default Docker Compose configuration:

- PostgreSQL and Redis are **not exposed to the internet** in production (no `ports` directive; they communicate over the internal Docker network)
- Nginx is the only public-facing component
- Backend runs as the application user (not root) in the Docker image
- Secrets are passed via `env_file` (not baked into the image)
- `restart: unless-stopped` ensures services recover from crashes

---

## Trust Boundaries

```
╔═══════════════════════════════════════════════════════╗
║ INTERNET (Untrusted)                                  ║
║  ┌─────────────────────────────────────────────────┐  ║
║  │ Nginx (DMZ)                                     │  ║
║  │  - TLS termination                              │  ║
║  │  - Rate limiting (connection level)             │  ║
║  └──────────┬──────────────────────┬───────────────┘  ║
║             ▼                      ▼                   ║
║  ┌────────────────┐    ┌─────────────────────────┐    ║
║  │ Next.js        │    │ FastAPI                 │    ║
║  │ (Semi-trusted) │    │ (Application boundary)  │    ║
║  │ Renders data   │    │ Auth, SSRF, IDOR checks │    ║
║  └────────────────┘    └─────────────┬───────────┘    ║
║                                      ▼                 ║
║                         ┌─────────────────────────┐   ║
║                         │ Internal Network        │   ║
║                         │  ├── PostgreSQL         │   ║
║                         │  ├── Redis              │   ║
║                         │  └── ARQ Worker         │   ║
║                         └─────────────────────────┘   ║
╚═══════════════════════════════════════════════════════╝
```

**Security assumptions:**
1. The internal Docker network is trusted; no additional auth between API and database
2. Redis does not require authentication in development (use Redis AUTH in production)
3. The Nginx reverse proxy correctly forwards `X-Forwarded-For` for rate limiting
4. SMTP credentials are valid — email service is not rate-limited internally
5. NVD API is available and returns accurate data

---

## Attack Surface Analysis

| Vector | Risk | Mitigation |
|---|---|---|
| Unauthenticated API endpoints | Low | Only `/health`, `/readiness`, auth endpoints are public |
| JWT forgery | Low | HS256 with 32+ char key; JTI blacklisting |
| Session fixation | Low | New JWTs issued on each login |
| Token reuse after logout | Mitigated | Access + refresh token JTIs blacklisted in Redis on logout |
| SSRF via scan target | **Mitigated** | Async DNS + IP validation before job enqueue; all redirect hops re-validated |
| SSRF event-loop blocking | Mitigated | DNS resolution runs via `asyncio.to_thread` — event loop never blocked |
| SSE stream with revoked token | Mitigated | SSE stream endpoint checks token blacklist before establishing connection |
| IDOR via predictable IDs | Low | UUID v4 primary keys + DB-level ownership JOIN filtering |
| Brute force | Mitigated | Rate limiting on all auth endpoints; dev-verify additionally rate-limited |
| SQL injection | Low | SQLAlchemy ORM with parameterized queries |
| XSS in stored findings | Mitigated | React auto-escapes; `Content-Security-Policy: default-src 'none'` on all API routes |
| Scanner triggering WAF bans | Medium | Single HTTP request per probe; no automated crawling |
| Redis data poisoning | Low | Redis accessible only on internal Docker network |
| Stale cached tokens | Low | Redis TTL = remaining token lifetime; self-expiring |
