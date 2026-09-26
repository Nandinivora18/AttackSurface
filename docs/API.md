# API Reference

Base URL: `http://localhost:8000` (development) | `https://api.sentinelscan.io` (production)

All endpoints return JSON. Authenticated endpoints require `Authorization: Bearer {access_token}`.

---

## Authentication

### POST /api/auth/register

Register a new user account.

**Rate limit:** 5 requests/minute per IP

**Request:**
```json
{
  "email": "user@example.com",
  "name": "Jane Smith",
  "password": "StrongPassword123!"
}
```

**Response `201`:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "name": "Jane Smith",
  "role": "user",
  "is_verified": false,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Errors:**
- `409 Conflict` — email already registered
- `422` — invalid email format or password too short

**Security:** A verification email is sent immediately. The account cannot be used until verified (unless `DEV_BYPASS_EMAIL_VERIFICATION=True` in development).

---

### POST /api/auth/login

**Rate limit:** 5 requests/minute per IP

**Request:**
```json
{
  "email": "user@example.com",
  "password": "StrongPassword123!"
}
```

**Response `200`:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "Jane Smith",
    "role": "user",
    "is_verified": true
  }
}
```

**Errors:**
- `401` — invalid credentials
- `403` — account not email-verified

---

### POST /api/auth/refresh

Exchange a valid refresh token for a new access token.

**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response `200`:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Errors:**
- `401` — invalid or expired refresh token

---

### POST /api/auth/logout

**Auth:** Required

Revokes the current access token by adding its JTI to the Redis blacklist.

**Response `200`:**
```json
{"message": "Logged out successfully"}
```

---

### GET /api/auth/verify/{token}

Verify email address using the token from the verification email.

**Response `200`:**
```json
{"message": "Email verified successfully"}
```

**Errors:**
- `400` — token invalid or expired

---

### POST /api/auth/forgot-password

**Rate limit:** 5 requests/minute per IP

**Request:**
```json
{"email": "user@example.com"}
```

**Response `200`:** Always returns success to prevent user enumeration.

---

### POST /api/auth/reset-password

**Request:**
```json
{
  "token": "abc123...",
  "new_password": "NewStrongPassword456!"
}
```

**Errors:**
- `400` — token invalid or expired

---

### GET /api/auth/google/login

Redirects to Google OAuth authorization URL. Handles state parameter for CSRF protection.

**Response:** `302 Redirect` to Google

---

### GET /api/auth/google/callback

OAuth callback endpoint — exchanges authorization code for tokens.

**Query params:** `code`, `state`

**Response:** `302 Redirect` to frontend with `?token={access_token}&refresh={refresh_token}`

---

## Scans

### POST /api/scans

Create and enqueue a new scan.

**Auth:** Required  
**Concurrency limit:** Max 2 active (pending/running) scans per user (`MAX_ACTIVE_SCANS_PER_USER`)

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response `201`:**
```json
{
  "id": "7f000001-0000-0000-0000-000000000001",
  "url": "https://example.com",
  "status": "pending",
  "progress": 0,
  "current_stage": null,
  "created_at": "2024-01-15T10:30:00Z",
  "started_at": null,
  "completed_at": null
}
```

**Errors:**
- `400` — URL fails SSRF validation (private/loopback target)
- `409` — duplicate scan already pending/running for this URL
- `429` — rate limit exceeded
- `503` — Redis unavailable (cannot enqueue job)

**Example curl:**
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

### GET /api/scans

List all scans for the authenticated user.

**Auth:** Required  
**Query params:** `page` (default: 1), `per_page` (default: 20), `status` (filter)

**Response `200`:**
```json
{
  "scans": [
    {
      "id": "7f000001-...",
      "url": "https://example.com",
      "status": "completed",
      "progress": 100,
      "created_at": "2024-01-15T10:30:00Z",
      "completed_at": "2024-01-15T10:30:45Z"
    }
  ],
  "total": 1,
  "page": 1,
  "per_page": 20
}
```

---

### GET /api/scans/{scan_id}

Get status and metadata for a single scan.

**Auth:** Required  
**Errors:**
- `404` — scan not found or belongs to another user (IDOR protection)

---

### DELETE /api/scans/{scan_id}

Cancel a pending or running scan.

**Auth:** Required

Sets `scan.status = cancelled` in the database and calls `Job.abort()` on the ARQ job via Redis.

**Response `200`:**
```json
{"status": "cancelled", "message": "Scan cancellation requested"}
```

**Errors:**
- `400` — scan already in terminal state (completed/failed/cancelled)

---

### POST /api/scans/{scan_id}/sse-ticket

Issue a single-use authentication ticket for SSE progress streaming. This avoids exposing long-lived JWT tokens in EventSource URLs or browser query strings.

**Auth:** Required (Bearer JWT)

**Response `200`:**
```json
{
  "ticket": "9f8e7d6c5b4a...",
  "expires_in": 60
}
```

---

### GET /api/scans/{scan_id}/stream

Server-Sent Events stream of real-time scan progress.

**Auth:** Required via `?ticket=<ticket>` query parameter (or fallback `Authorization: Bearer <JWT>`). The ticket is consumed immediately on connection.

**Content-Type:** `text/event-stream`

**Event format:**
```
data: {"scan_id": "...", "stage": "DNS Lookup", "progress": 15, "status": "running", "message": "DNS analysis complete"}

data: {"scan_id": "...", "stage": "SSL/TLS Analysis", "progress": 35, "status": "running", "message": "SSL analysis complete"}

data: {"scan_id": "...", "progress": 100, "status": "completed", "report_id": "..."}
```

**Stages in order:**
1. DNS Lookup (0→15%)
2. SSL/TLS Analysis (15→35%)
3. Header Analysis (35→55%)
4. Technology Detection (55→70%)
5. CVE Database Lookup (70→85%)
6. Content Analysis (85→92%)
7. Generating Report (92→100%)

---

## Reports

### GET /api/reports

List all reports for the authenticated user.

**Auth:** Required

**Response `200`:**
```json
{
  "reports": [
    {
      "id": "abc...",
      "scan_id": "7f0...",
      "url": "https://example.com",
      "overall_score": 72,
      "grade": "B",
      "risk_level": "medium",
      "created_at": "2024-01-15T10:30:45Z",
      "finding_counts": {
        "critical": 0,
        "high": 2,
        "medium": 5,
        "low": 3,
        "info": 8
      }
    }
  ]
}
```

---

### GET /api/reports/{report_id}

Get full report with all findings.

**Auth:** Required

**Response `200`:**
```json
{
  "id": "abc...",
  "scan_id": "7f0...",
  "url": "https://example.com",
  "overall_score": 72,
  "grade": "B",
  "risk_level": "medium",
  "summary": "The site demonstrates moderate security posture...",
  "tech_stack": {
    "Nginx": {"category": "Web Server", "confidence": 99},
    "React": {"category": "JavaScript Framework", "confidence": 90}
  },
  "ssl_info": {
    "certificate": {"subject": "example.com", "days_remaining": 180},
    "tls_version": "TLSv1.3",
    "cipher": {"name": "TLS_AES_256_GCM_SHA384"}
  },
  "dns_info": {
    "spf": "v=spf1 include:_spf.google.com ~all",
    "dmarc": "v=DMARC1; p=quarantine",
    "mx_records": ["10 mail.example.com"]
  },
  "score_breakdown": {
    "ssl_tls": {"score": 18, "max": 20, "label": "SSL / TLS"},
    "security_headers": {"score": 12, "max": 20, "label": "Security Headers"}
  },
  "executive_summary": {...},
  "findings": [
    {
      "id": "...",
      "category": "SSL/TLS",
      "title": "Expired Certificate",
      "severity": "critical",
      "confidence": "high",
      "cvss_score": 9.1,
      ...
    }
  ],
  "timeline": [...]
}
```

---

### GET /api/reports/{report_id}/pdf

Download report as a PDF file.

**Auth:** Required

**Query Parameters:**
- `mode` (optional): `technical` (default) or `executive`

**Response:** `application/pdf` binary

**Headers:** `Content-Disposition: attachment; filename="sentinelscan-report-{id}-{mode}.pdf"`

---

### GET /api/reports/{report_id}/json

Download report as a standardized JSON export.

**Auth:** Required

**Response:** `application/json`

**Headers:** `Content-Disposition: attachment; filename="sentinelscan-report-{id}.json"`

---

### DELETE /api/reports/{report_id}

Delete a report and its associated findings.

**Auth:** Required

**Response `204`:** No Content

---

## Notifications

### GET /api/notifications

**Auth:** Required

**Response `200`:**
```json
{
  "notifications": [
    {
      "id": "...",
      "type": "scan_complete",
      "title": "Scan Complete — example.com",
      "message": "Your scan scored 72/100 (Grade B). 2 high, 5 medium findings.",
      "is_read": false,
      "created_at": "2024-01-15T10:30:45Z",
      "metadata_": {"scan_id": "...", "report_id": "..."}
    }
  ],
  "unread_count": 1
}
```

---

### PATCH /api/notifications/{id}/read

Mark a notification as read.

**Auth:** Required

---

### PATCH /api/notifications/read-all

Mark all notifications as read.

**Auth:** Required

---

## Users

### GET /api/users/me

Get current user profile.

**Auth:** Required

---

### PUT /api/users/me

Update user profile (`name`, `avatar_url`).

**Auth:** Required

---

### PUT /api/users/me/password

Change account password for password-authenticated users.

**Auth:** Required

**Request:**
```json
{
  "current_password": "OldPassword123!",
  "new_password": "NewStrongPassword456!"
}
```

---

### POST /api/users/me/password/set

Set a local password for Google/OAuth accounts.

**Auth:** Required

**Request:**
```json
{
  "new_password": "NewStrongPassword456!"
}
```

---

## Health

### GET /api/health

Liveness probe — confirms the API process is running.

**Auth:** Not required

**Response `200`:**
```json
{
  "status": "healthy",
  "app": "SentinelScan",
  "version": "1.0.0",
  "environment": "development"
}
```

---

### GET /api/readiness

Readiness probe — checks all dependencies.

**Auth:** Not required

**Response `200` (all healthy):**
```json
{
  "ready": true,
  "checks": {
    "database": {"status": "ok"},
    "redis": {"status": "ok"},
    "worker": {"status": "ok", "last_heartbeat": "1700000000"}
  }
}
```

**Response `503` (dependency down):**
```json
{
  "ready": false,
  "checks": {
    "database": {"status": "ok"},
    "redis": {"status": "error", "detail": "Connection refused"},
    "worker": {"status": "unknown", "detail": "Redis unavailable"}
  }
}
```

---

## Admin

### GET /api/admin/stats

Get platform-wide statistics (user count, scan volume, average security score, top vulnerabilities, system status).

**Auth:** Required (admin role)

---

### GET /api/admin/users

List all users in the system with metadata and verification status.

**Auth:** Required (admin role)

**Query Parameters:**
- `limit` (optional): integer (default 50, max 100)
- `offset` (optional): integer (default 0)

---

### DELETE /api/admin/users/{user_id}

Permanently delete a user account and write an audit log entry. Cannot delete self.

**Auth:** Required (admin role)

**Response `204`:** No Content

---

### GET /api/admin/scans

List all scans across the platform with status, progress, and execution timestamps.

**Auth:** Required (admin role)

**Query Parameters:**
- `limit` (optional): integer (default 50, max 100)
- `offset` (optional): integer (default 0)

---

### GET /api/admin/logs

List system security audit logs.

**Auth:** Required (admin role)

**Query Parameters:**
- `limit` (optional): integer (default 100, max 200)
- `offset` (optional): integer (default 0)

---

### GET /api/admin/health

Detailed system health including database query latency, Redis roundtrip, and queue status.

**Auth:** Required (admin role)

---

## Error Responses

All error responses follow this schema:

```json
{
  "detail": "Human-readable error description"
}
```

| Status Code | Meaning |
|---|---|
| `400` | Bad request — validation failed |
| `401` | Unauthorized — missing or invalid token |
| `403` | Forbidden — verified but insufficient permissions |
| `404` | Not found — resource doesn't exist or IDOR blocked |
| `409` | Conflict — duplicate resource |
| `422` | Unprocessable Entity — Pydantic validation failed |
| `429` | Too Many Requests — rate limit exceeded |
| `500` | Internal Server Error — unexpected exception |
| `503` | Service Unavailable — Redis, database, or AI provider unconfigured |

---

## AI Assistant (Ask Sentinel)

Ask Sentinel provides grounded, context-aware passive security intelligence using **Google Gemini Free Tier** by default (with optional OpenAI compatibility).

### Configuration (Google Gemini Free Tier)
Obtain a free Gemini API key from [Google AI Studio](https://aistudio.google.com/).
Add to `backend/.env`:
```env
AI_PROVIDER=gemini
AI_GEMINI_API_KEY=YOUR_GEMINI_API_KEY
AI_GEMINI_MODEL=models/gemini-3.6-flash
AI_TEMPERATURE=0.2
AI_MAX_OUTPUT_TOKENS=1500
AI_MAX_CONVERSATION_TURNS=10
AI_RATE_LIMIT_PER_HOUR=20
AI_REQUEST_TIMEOUT_SECONDS=30
```

---

### GET /api/ai/status

Inspect whether Ask Sentinel is configured and active. Does not make external LLM calls. Never exposes API keys, credentials, or secrets.

**Auth:** Required (verified user)

**Response `200` (Configured):**
```json
{
  "configured": true,
  "provider": "gemini",
  "model": "models/gemini-3.6-flash"
}
```

**Response `200` (Unconfigured):**
```json
{
  "configured": false,
  "provider": null,
  "model": null
}
```

---

### POST /api/ai/chat

Ask security questions with automatic scan-level or finding-level grounding.

**Auth:** Required (verified user)

**Rate Limit:** 20 requests per hour per user (Redis sliding-window)

**Request Body:**
```json
{
  "message": "Explain the severity and remediation for my scan findings.",
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "finding_id": null,
  "conversation_id": "optional-session-id",
  "conversation_history": [
    {"role": "user", "content": "What does missing HSTS mean?"},
    {"role": "assistant", "content": "HSTS ensures browsers only connect via HTTPS..."}
  ]
}
```

**Response `200`:**
```json
{
  "answer": "Markdown-formatted explanation grounded in observed scan data...",
  "sources": ["SentinelScan Scan Data", "OWASP Top 10:2025 A05"],
  "context_type": "scan",
  "finding_id": null,
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "model": "models/gemini-3.6-flash",
  "provider": "gemini"
}
```

---

### POST /api/ai/explain-finding

Generate a structured, section-by-section breakdown of an observed security finding.

**Auth:** Required (verified user)

**Rate Limit:** 20 requests per hour per user

**Request Body:**
```json
{
  "finding_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
}
```

**Response `200`:**
```json
{
  "summary": "Plain-English summary of the finding.",
  "why_it_matters": "Real-world risk and impact analysis.",
  "evidence_explanation": "Explanation of observed headers/records.",
  "technical_explanation": "Underlying mechanism and CWE reference.",
  "severity_explanation": "Confidence and severity grounding.",
  "owasp_context": "OWASP Top 10:2025 mapping.",
  "remediation": "Step-by-step remediation guidance.",
  "limitations": "What SentinelScan cannot verify passively.",
  "sources": ["SentinelScan Scan Data"],
  "model": "models/gemini-3.6-flash",
  "provider": "gemini"
}
```

---

### POST /api/ai/visual-chat (Circle to Sentinel)

Visual security intelligence endpoint. Accepts a cropped screen-region JPEG (base64) along with extracted DOM text and structured scan context to produce an evidence-grounded visual explanation.

**Auth:** Required (verified user)

**Rate Limit:** 20 requests per hour per user (shared Redis sliding-window quota)

**Request Body:**
```json
{
  "message": "What does this risk score card indicate?",
  "image_data": "<base64_encoded_jpeg_string_without_prefix>",
  "selected_text": "Security Dashboard ... Grade B ... 75 / 100",
  "region": {
    "x": 120.5,
    "y": 240.0,
    "width": 450.0,
    "height": 300.0
  },
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "finding_id": null,
  "conversation_id": "optional-session-id",
  "conversation_history": []
}
```

- **Automatic Intent Note**: If `message` is empty or omitted, SentinelScan automatically generates a context-aware visual explanation of the selected area without requiring manual typing.
- **Image Validation**: `image_data` must be valid base64 (max 2,000,000 chars ≈ ~1.5 MB base64 payload). Strips data URI prefixes automatically.
- **Prompt Injection Defense**: Image bytes and DOM text are treated as untrusted `OBSERVED_DATA` (Rule 13/14). Directives embedded within screenshots are ignored.

**Response `200`:**
```json
{
  "answer": "The selected card displays the overall security posture score (75/100, Grade B)...",
  "sources": ["SentinelScan Visual Context", "Scan Findings"],
  "context_type": "visual",
  "finding_id": null,
  "scan_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "model": "models/gemini-3.6-flash",
  "provider": "gemini"
}
```

**Common Errors:**
- `401 Unauthorized`: Missing or invalid bearer token.
- `403 Forbidden`: Attempting to query scan/finding belonging to another user (IDOR prevention).
- `422 Unprocessable Entity`: Invalid base64 image data or micro-selection.
- `429 Too Many Requests`: Exceeded 20 AI requests/hour per user rate limit.
- `503 Service Unavailable`: AI provider not configured or upstream API unreachable.
- `504 Gateway Timeout`: Upstream LLM response exceeded 30s timeout.
