<div align="center">

# 🛡️ SentinelScan

**Controlled, Non-Destructive Hybrid Web Security Assessment Platform for vulnerability assessment, component lifecycle intelligence, real-time scan monitoring, and verified reporting.**

[![Python](https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14.2-black?logo=next.js&logoColor=white)](https://nextjs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7.0-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Team ID: TEAMID_28** &nbsp;|&nbsp; 📎 [View / Download Presentation (TEAMID_28.pdf)](TEAMID_28.pdf)

</div>

---

## 📌 Why SentinelScan?

Modern organizations deploy web applications across complex, hybrid cloud environments. Traditional active vulnerability scanners often introduce operational risk through invasive fuzzing, authentication brute-forcing, or disruptive payload injection.

SentinelScan solves this by providing a **controlled, non-destructive hybrid assessment**:

- **Multi-Mode Execution**: Operates in default `passive` mode or opt-in `safe_active` / `authenticated_safe_active` modes requiring mandatory authorization consent.
- **Evidence-Backed Findings**: Identified risks include a verifiable evidence chain, eliminating ambiguity and reducing false positives.
- **OWASP Top 10:2025 Assessment Coverage**: SentinelScan provides OWASP Top 10:2025 assessment coverage across A01-A10 using passive analysis, controlled non-destructive testing, and evidence-assisted assessment. Detection and verification depth varies by category.
- **Component Lifecycle Intelligence**: Multi-signal technology detection (23 technologies fingerprinted, 10 supporting version extraction), version normalization (distro suffixes), upstream `endoflife.date` caching with local fallback, and NVD CVE correlation.
- **Controlled Discovery Crawler**: Bounded same-origin crawling (GET/HEAD only, max 20 pages, max depth 2, max 50 requests, excludes sensitive verbs, respects robots.txt).
- **Real-Time Visibility**: Server-Sent Events (SSE) stream scan progression live through stage-by-stage pipelines.
- **Verified PDF & Multi-Format Reports**: Generates Executive and Technical PDF reports and JSON exports with automatic server-side credential redaction.

---

## 🚀 Key Features

| Capability | Description |
|---|---|
| 🔍 **Multi-Mode Web Scanning** | Default non-invasive passive mode, plus opt-in safe active mode with mandatory consent validation. |
| 🛡️ **SSRF-Safe Ingestion** | Validates target hostnames against private, link-local, and cloud metadata IP ranges with per-hop redirect re-validation. |
| 🕷️ **Controlled Same-Origin Crawler** | Discovers endpoints, parameters, and forms without state-changing mutations or form submissions. |
| 🧩 **Component Intelligence Engine** | Identifies technologies, normalizes version suffixes (Ubuntu, Debian, Sury), and evaluates EOL schedules via upstream API and local DB. |
| 🔟 **OWASP Top 10 Matrix** | Implements dedicated assessment mechanisms for all 10 OWASP categories with an honest 5-state evaluation model. |
| 📋 **Security Header Audits** | Validates HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. |
| 🔒 **TLS/SSL Evaluation** | Inspects cipher suites, certificate validity, expiration dates, SANs, and protocol versions. |
| 🌐 **DNS Hygiene Checks** | Audits SPF, DMARC, and MX records for email authentication and DNS hygiene. |
| 💥 **NVD CVE Correlation** | Correlates discovered software versions with public CVE entries and CVSS scores. |
| ⚡ **Live Progress Streaming** | Relays background worker execution status to the frontend via ticket-authenticated SSE. |
| 🔑 **Secure Authentication** | Dual-token authentication with short-lived JWT access tokens and HttpOnly refresh cookies. |
| 📊 **Security Scoring & Grading** | Computes normalized risk scores (0–100) and letter grades (A+–F) based on finding severity. |
| 📄 **Multi-Format Reporting** | Generates 16-section Executive/Technical PDF and JSON exports with sensitive data redaction. |
| 📜 **Scan History** | Tracks prior scan execution records, statuses, and generated reports across targets. |
| 🔧 **Remediation Guidance** | Context-rich code and configuration snippets (Nginx, Apache, Express) for applicable findings. |
| 🤖 **Sentinel Intelligence (Ask Sentinel)** | Evidence-grounded AI security assistant powered by Google Gemini. Explains findings, evidence, severity, OWASP/CWE/CVE mappings, and remediation — grounded strictly in actual scan data. |
| ⭕ **Circle to Sentinel** | Interactive visual security intelligence (`Ctrl+Shift+S` / `Cmd+Shift+S`). Select any on-screen UI element, chart, or finding to trigger automated visual interpretation via multimodal vision AI. |
| 🎨 **Dark Theme Interface** | Permanent obsidian-black and metallic-gold dark theme. No light mode. |
| 🔔 **In-App Notifications** | Per-user notification center with unread badge, dropdown panel, mark-as-read, and 15-second auto-refresh. |
| 👤 **User Management** | Profile management, scan history browser, findings viewer, and dedicated admin panel. |
| 🔐 **Account Flows** | Email verification, forgot/reset password, and Google OAuth 2.0 Single Sign-On. |

---

## 🎥 Demo

### SentinelScan Full Assessment & Verification

![SentinelScan Live Demo](docs/media/sentinelscan-demo.webp)

> Direct media path: [docs/media/sentinelscan-demo.webp](docs/media/sentinelscan-demo.webp)

### Circle to Sentinel (Visual AI Interaction)

Interactive multimodal security investigation demo recording (`Ctrl+Shift+S` / `Cmd+Shift+S`):  
> Video recording: [docs/media/CircleToSentinel.mp4](docs/media/CircleToSentinel.mp4)

---

## 🏗️ System Architecture

SentinelScan separates web serving, API gateway logic, and background scan execution across an asynchronous, event-driven topology:

```mermaid
flowchart TD
    subgraph Client ["Client Layer"]
        Browser["Modern Web Browser"]
    end

    subgraph Gateway ["Reverse Proxy & Frontend"]
        Nginx["Nginx / Cloudflare (TLS Termination)"]
        Frontend["Next.js 14 Web UI (Tailwind CSS, Recharts)"]
    end

    subgraph API_Layer ["Backend API Gateway"]
        FastAPI["FastAPI 0.115 (Python 3.13)"]
        SSRF["SSRF Guard (app/utils/safe_http.py)"]
    end

    subgraph Queue_State ["Message Broker & Cache"]
        Redis[("Redis 7 (ARQ Queue, SSE Pub/Sub, Blacklist)")]
    end

    subgraph Worker_Layer ["Scan Execution Engine"]
        Worker["ARQ Worker (app/tasks/scan_task.py)"]
        DNS["DNS Analyzer"]
        SSL["SSL / TLS Checker"]
        Headers["Header Analyzer"]
        Tech["Tech Detector"]
        CVE["CVE Lookup (NVD)"]
        Content["Content Exposure"]
        Score["Scoring Engine"]
    end

    subgraph Storage ["Persistent Storage"]
        Postgres[("PostgreSQL 16 (Users, Scans, Reports, Findings)")]
    end

    Browser -->|HTTPS| Nginx
    Nginx -->|Static / SSR| Frontend
    Nginx -->|REST / SSE| FastAPI

    FastAPI --> SSRF
    SSRF -->|Validated| Redis
    FastAPI -->|JWT & Token Blacklist Check| Redis
    FastAPI -->|Tenant Queries| Postgres

    Redis -->|Job Dequeue| Worker
    Worker --> DNS
    Worker --> SSL
    Worker --> Headers
    Worker --> Tech
    Worker --> CVE
    Worker --> Content
    Worker --> Score

    Score -->|Atomic Commit| Postgres
    Worker -->|Progress Events| Redis
    Redis -->|SSE Relay| FastAPI
```

---

## 🔐 Security Architecture

| Threat Vector | Defensive Control Implemented in Source Code |
|---|---|
| **Server-Side Request Forgery (SSRF)** | Strict IP resolution validating against private RFC 1918 subnets, loopback, link-local, and cloud metadata services (`169.254.169.254`). |
| **Insecure Direct Object References (IDOR)** | Enforced tenant isolation in database queries (`filter(Model.user_id == current_user.id)`). |
| **Session Hijacking & XSS Theft** | Refresh tokens stored in `HttpOnly`, `SameSite=Lax`, `Secure` cookies; short-lived JWT access tokens. |
| **Token Replay / Revocation** | Redis token blacklist invalidates tokens immediately on user logout. |
| **SSE Token Leakage in URLs** | Single-use tickets (`POST /api/scans/{id}/sse-ticket`) consumed on connect, avoiding JWTs in query strings. |
| **Credential Disclosure in Exports** | Server-side regex masking replaces passwords, bearer tokens, API keys, and session cookies with `[REDACTED]`. |
| **Worker Queue Starvation** | `MAX_ACTIVE_SCANS_PER_USER = 2` concurrent scan limit and 600s task timeouts. |
| **Brute Force & Flooding** | Endpoint rate limiting via `slowapi` on authentication routes. |

For full threat analysis, see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/Security.md](docs/Security.md).

---

## 🎯 Detection Coverage

SentinelScan features **82 registered detectors** across core security baseline modules and 12 specialized external exposure domains:

### Core Security & OWASP Modules (37 Baseline Detectors)
| Category | Detectors | Primary Standards & References |
|---|:---:|---|
| **Security Headers** | 11 | RFC 6797 (HSTS), W3C CSP Level 3, RFC 7034 (XFO), OWASP ASVS 14.4, Server/Powered-By headers |
| **SSL / TLS** | 6 | NIST SP 800-52r2, Mozilla TLS Guidelines, RFC 8446 (TLS 1.3) |
| **DNS Security** | 4 | RFC 7208 (SPF missing/present), RFC 7489 (DMARC missing/weak policy), RFC 5321 (MX) |
| **Technology Detection** | 2 | Framework, Web Server, CMS, and JavaScript library fingerprinting with version disclosure |
| **Cookie Security** | 1 | RFC 6265, OWASP ASVS 3.4 (HttpOnly, Secure, SameSite) |
| **CVE Correlation** | 1 | NIST NVD CVE database integration with CVSS scoring |
| **Content Exposure** | 1 | Exposed `.env`, `.git/HEAD`, backup files, and soft-404 verification |
| **OWASP Top 10 Assessment** | 11 | Dedicated assessment mechanisms covering OWASP Top 10:2025 categories (A01–A10) |

### External Exposure Intelligence (45 Expanded Detectors across 12 Domains)
| Domain | Detectors | Primary Focus & Verification Scope |
|---|:---:|---|
| **1. Web Security Configuration** | 4 | CORS wildcard/credentials analysis, Server header versioning, X-Powered-By, exposed debug/actuator endpoints |
| **2. Auth & Session Security** | 3 | Session cookie flags (HttpOnly/Secure/SameSite), unencrypted HTTP login forms, exposed Basic Auth |
| **3. API Surface Exposure** | 4 | OpenAPI 3 specs, Swagger/ReDoc docs, unauthenticated GraphQL roots, and confirmed schema introspection |
| **4. JavaScript Secret Detection** | 11 | AWS key/secret, Google API keys, GitHub PATs, Stripe live/test, Slack, SendGrid, JWT secrets, generic API keys, private keys |
| **5. Source Map Exposure** | 1 | Publicly reachable `.map` files enabling client-side source code and internal path reconstruction |
| **6. Sensitive Files & Standards** | 2 | Internal path disclosure in `robots.txt` Disallow directives, missing RFC 9116 `security.txt` |
| **7. Cloud Storage Exposure** | 3 | Publicly listable buckets, accessible cloud assets, and cloud bucket references (AWS S3, Google Cloud, Azure Blob) |
| **8. DNS Intelligence** | 5 | Permissive SPF (`+all`, `~all`), wildcard DNS records, missing DMARC, and monitor-only `p=none` policies |
| **9. TLS Deep Analysis** | 4 | Deprecated TLS 1.0/1.1 protocols, weak cipher suites, HSTS preload list submission, and CT status disclosure |
| **10. Mixed Content Detection** | 2 | Active mixed content (HTTP scripts, form actions) and passive mixed content (images, stylesheets) on HTTPS |
| **11. Third-Party & SRI** | 2 | CDN scripts and external JavaScript assets loaded without Subresource Integrity (`integrity`) hashes |
| **12. Cache Exposure** | 3 | Authenticated responses lacking `no-store`/`private`, sensitive JSON API caching, and missing cache control |


---

## 📑 Reporting & Deliverables

SentinelScan provides **server-side export deliverables** with automated sensitive data redaction:

1. **Technical PDF Assessment**: Comprehensive 16-section technical audit including raw evidence strings, HTTP headers, TLS certificate details, full CVE descriptions, CVSS vectors, and CWE/OWASP Top 10:2025 remediation steps compiled via ReportLab 4.x.
2. **Executive PDF Summary**: High-level risk posture designed for leadership, featuring the overall security grade (A+–F), total score (0–100), severity distribution charts, and executive remediation priorities.
3. **Structured JSON Export**: Machine-readable JSON data stream for direct SIEM ingestion and automated security pipelines.

> **Sensitive Data Redaction**: All export formats automatically mask sensitive credentials, tokens, passwords, and authorization headers before rendering.

---

## 🔧 Actionable Remediation Guidance

SentinelScan focuses on actionable, passive intelligence: **Scan → Detect → Correlate → Recommend**. Applicable findings include concrete guidance so development and infrastructure teams can fix issues quickly:

- **Snippet-Based Configuration**: Applicable findings provide copy-ready configuration snippets for major servers and frameworks (Nginx, Apache, Express/Helmet, Caddy).
- **Structured Finding Metadata**: Applicable findings include a human-readable Problem statement, Potential Impact analysis, Sequential Fix Steps, Configuration Example, and Reference links (RFCs, OWASP, NIST).
- **Non-Invasive Architecture**: SentinelScan does not remotely connect to, modify, or execute changes on live infrastructure. Remediation patches are evaluated and applied directly by system operators.
- **Triage & Tracking**: Security teams review findings across reports, track posture improvements over repeated scans, and export technical PDF and JSON artifacts for ticketing systems.

---

## 🛠️ Installation & Setup

### Prerequisites
- **Python 3.12+** (Python 3.13 recommended)
- **Node.js 18+** (Node.js 20 LTS recommended)
- **Redis 7+**
- **PostgreSQL 16+** (or SQLite for local development)

---

### Local Development Setup

#### 1. Clone Repository
```bash
git clone https://github.com/Nandinivora18/AttackSurface.git
cd AttackSurface
```

#### 2. Backend Setup
```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Windows (CMD):
.venv\Scripts\activate.bat

# macOS / Linux:
source .venv/bin/activate

# Install runtime and testing dependencies
pip install -r requirements.txt -r requirements-dev.txt

# Configure environment variables
cp .env.example .env
```

#### 3. Frontend Setup
```bash
cd ../frontend

# Install dependencies
npm install

# Configure environment
cp .env.local.example .env.local
```

---

## 🏃 Running SentinelScan

### Running Services Locally

```bash
# Terminal 1 — FastAPI Backend (from backend/ with active venv)
uvicorn app.main:app --reload --port 8000

# Terminal 2 — ARQ Background Worker (from backend/ with active venv)
python run_worker.py

# Terminal 3 — Next.js Frontend (from frontend/)
npm run dev
```

The web dashboard is now accessible at `http://localhost:3000` with the API documentation at `http://localhost:8000/docs`.

---

### Running via Docker Compose

#### Quick Start (Development)

```bash
# 1. Generate a SECRET_KEY (minimum 32 characters)
export SECRET_KEY="$(python -c "import secrets; print(secrets.token_urlsafe(48))")"

# 2. Start all services (PostgreSQL, Redis, Backend, Worker, Frontend)
docker compose -f docker/docker-compose.yml up --build -d
```

The stack starts with:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

> **Note**: The nginx reverse proxy requires TLS certificates in `nginx/certs/` and is optional for local development. Omit the `nginx` service if you don't need it:
> ```bash
> docker compose -f docker/docker-compose.yml up postgres redis backend worker frontend --build -d
> ```

#### Production Deployment

```bash
# 1. Set required environment variables
export SECRET_KEY="$(python -c "import secrets; print(secrets.token_urlsafe(48))")"
export POSTGRES_USER="your_db_user"
export POSTGRES_PASSWORD="your_db_password"
export POSTGRES_DB="sentinelscan"
export REDIS_PASSWORD="your_redis_password"

# 2. Optional: NVD API key for faster CVE lookups (50 req/30s vs 5 req/30s)
export NVD_API_KEY="your-nvd-api-key"

# 3. Update nginx/nginx.conf server_name to your domain
# 4. Provision TLS certificates in nginx/certs/

# 5. Start the production stack
docker compose -f docker/docker-compose.prod.yml up --build -d
```

#### Environment Variables

| Variable | Purpose | Required | Default |
|---|---|---|---|
| `SECRET_KEY` | JWT signing key (min 32 chars) | **Yes** | — |
| `POSTGRES_USER` | Database user (prod only) | **Yes (prod)** | — |
| `POSTGRES_PASSWORD` | Database password (prod only) | **Yes (prod)** | — |
| `POSTGRES_DB` | Database name (prod only) | **Yes (prod)** | — |
| `REDIS_PASSWORD` | Redis password (prod only) | **Yes (prod)** | — |
| `ENVIRONMENT` | `development` or `production` | No | `development` |
| `DEBUG` | Debug mode (forced `false` in prod) | No | `true` |
| `REQUIRE_EMAIL_VERIFICATION` | Require email verification | No | `true` |
| `FRONTEND_URL` | Frontend URL for email links | No | `http://localhost:3000` |
| `NEXT_PUBLIC_API_URL` | Backend API URL for frontend | No | `http://localhost:8000` |
| `NVD_API_KEY` | NIST NVD API key for faster CVE lookups | No | — |
| `SMTP_HOST` | SMTP server for email | No | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP port | No | `587` |
| `SMTP_USER` | SMTP username | No | — |
| `SMTP_PASSWORD` | SMTP password | No | — |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | No | — |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | No | — |
| `AI_PROVIDER` | AI provider (`gemini` or `openai`) | No | — |
| `AI_GEMINI_API_KEY` | Google Gemini API key for Ask Sentinel | No | — |
| `AI_GEMINI_MODEL` | Gemini model name | No | `gemini-3.6-flash` |
| `AI_RATE_LIMIT_PER_HOUR` | Max AI requests per user per hour | No | `20` |

> **NVD_API_KEY**: Optional but recommended. Without it, CVE lookups are rate-limited to 5 requests per 30 seconds (~33s for 5 technologies). With a free key from https://nvd.nist.gov/developers/request-an-api-key, the limit increases to 50 requests per 30 seconds (~3.5s). The key must never be committed to Git or baked into Docker images.

---

## 🧪 Testing & Validation
 
SentinelScan maintains high test coverage across unit, security, false-positive regression, external exposure, and integration suites (**907 passing backend tests**; 0 failures, 0 errors; 871 tests as documented prior milestone; all 36/36 dedicated external exposure tests passing).
 
```bash
# Run the complete backend test suite (from backend/)
# Windows:
.\.venv\Scripts\python.exe -m pytest tests/ -q

# macOS / Linux:
.venv/bin/python -m pytest tests/ -q

# Run Frontend Typecheck & Production Build (from frontend/)
npm run type-check
npm run build
```

---

## 🔑 Authentication & Session Security

SentinelScan implements a hardened, defense-in-depth authentication architecture:

- **Email & Password Authentication**: Salted bcrypt password hashing with email verification flows.
- **Google OAuth 2.0 Integration**: Single Sign-On via Google OAuth with automatic verified account provisioning.
- **Dual-Token Architecture**: Short-lived JWT access tokens paired with `HttpOnly`, `SameSite=Lax`, `Secure` refresh cookies to prevent XSS-based credential theft.
- **Immediate Token Revocation**: Redis-backed token blacklist invalidates tokens immediately on user logout.
- **Rate-Limited Endpoints**: Authentication routes are throttled via `slowapi` to defend against automated brute-force and credential stuffing attacks.
- **Tenant Authorization**: Database-level tenant isolation enforces strict ownership checks across all scan and report queries.

---

## 📂 Project Structure

```
SentinelScan/
├── .github/
│   ├── workflows/             # GitHub Actions CI: backend tests, frontend build, security checks
│   ├── ISSUE_TEMPLATE/        # Standardized issue templates
│   └── pull_request_template.md
│
├── backend/
│   ├── app/
│   │   ├── ai/                # Sentinel Intelligence: context, provider, sanitization, prompt injection rules
│   │   ├── models/            # SQLAlchemy database entities (7 active models)
│   │   ├── routers/           # FastAPI route controllers (auth, scans, reports, ai, admin)
│   │   ├── schemas/           # Pydantic request/response schemas
│   │   ├── services/          # Business logic and service layer
│   │   ├── middleware/        # Request middleware
│   │   ├── scanner/           # Modular security inspection detectors (82 detectors: 37 baseline + 45 exposure)
│   │   ├── tasks/             # ARQ background task orchestrators (scan_task.py with Stage 5e exposure)
│   │   └── utils/             # Security, SSRF (19 subnets), safe_http, PDF, and SSE utilities
│   ├── tests/                 # Backend pytest suite (907 passing tests)
│   ├── requirements.txt       # Runtime dependencies
│   └── requirements-dev.txt   # Testing and development dependencies
│
├── frontend/
│   ├── src/
│   │   ├── app/               # Next.js 14 App Router pages and layouts
│   │   ├── components/        # Reusable UI components, score rings, charts, and AI assistant
│   │   │   ├── ai/            # AskSentinelPanel, AskSentinelButton, CircleToSentinel visual overlay
│   │   ├── lib/               # Shared utilities, API client, and aiApi
│   │   ├── store/             # Zustand global client state (aiStore, authStore)
│   │   └── types/             # TypeScript type definitions (ai.ts, scan.ts)
│   ├── package.json
│   └── tailwind.config.js
│
├── docker/                    # Docker Compose configs (base, dev, and production)
├── docs/                      # Technical architecture, threat models, API specs
├── CHANGELOG.md               # Version history and release notes
├── CODE_OF_CONDUCT.md         # Community conduct guidelines
├── CONTRIBUTING.md            # Collaboration & PR workflow guidelines
├── SECURITY.md                # Vulnerability disclosure policy
└── LICENSE                    # MIT License
```

---

## 🗺️ Future Roadmap

- [ ] Subdomain enumeration & multi-target asset discovery (v1.1)
- [ ] Scheduled recurring scans & webhook alert notifications (v1.1)
- [ ] Multi-tenant organizations & team role-based access control (v2.0)
- [ ] Continuous passive DNS change & TLS certificate expiration monitors (v2.0)

---

## 🤖 Sentinel Intelligence & Circle to Sentinel

SentinelScan embeds a context-aware AI security analyst layer — **Sentinel Intelligence** — and an interactive multimodal screen-region interpreter — **Circle to Sentinel**.

### Purpose

Security scanners produce complex technical findings that require expert interpretation. Sentinel Intelligence acts as an evidence-grounded security analyst that interprets scan findings, verifies evidence chains, explains severity ratings, maps OWASP/CWE/CVE vectors, and delivers contextual remediation — grounded strictly in actual scan data.

**The Engineering Principle**:
> *The Scanner detects. The Evidence proves. Sentinel Intelligence explains.*

### Interactive User Experiences

- **Global Assistant** — persistent Ask Sentinel panel available throughout the dashboard
- **Finding-Level Interpretation** — dedicated one-click explanation button on each finding card
- **Report-Level Context** — holistic scan assessment interpreting overall attack surface posture
- **Circle to Sentinel (`Ctrl+Shift+S` / `Cmd+Shift+S`)** — drag-to-select any UI region, score card, or finding on the screen to trigger automated multimodal vision analysis without manual typing
- **Conversational Follow-Up** — multi-turn conversation maintaining grounded context (up to 10 turns)

### Architecture

```
Frontend (AskSentinelPanel / CircleToSentinel visual overlay)
    ↓  POST /api/ai/chat | POST /api/ai/explain-finding | POST /api/ai/visual-chat
FastAPI Router (app/routers/ai.py)
    ↓  verified auth + Redis sliding-window rate limit (20/hr) + tenant authorization
Context & Evidence Engine (app.ai.context)
    ↓  user-ownership-verified scan/finding structured data + DOM text
Secret Sanitizer (app.ai.sanitize)
    ↓  redacted context dict (tokens, passwords, and sensitive keys masked)
Prompt Boundary Engine (app.ai.system_prompt)
    ↓  enforces Rule 1-14 trust boundaries (target data treated as DATA, not instructions)
Provider Abstraction (app.ai.provider → GeminiProvider / OpenAIProvider)
    ↓  structured multimodal messages with low temperature (0.2)
Google Gemini API (models/gemini-3.6-flash)
```

### API Endpoints

| Method | Path | Description | Security Controls |
|--------|------|-------------|-------------------|
| `GET` | `/api/ai/status` | Returns AI configuration status (no secrets exposed) | Verified Auth |
| `POST` | `/api/ai/chat` | Conversational security analysis with scan/finding context | Auth, Rate-Limited (20/hr), Tenant Check |
| `POST` | `/api/ai/explain-finding` | Structured 8-section technical finding explanation | Auth, Rate-Limited, IDOR Validation |
| `POST` | `/api/ai/visual-chat` | Circle to Sentinel: visual crop + DOM text → vision AI | Auth, Rate-Limited, Base64 Validation |

### Security & Trust Model

- **Authentication Required**: All AI endpoints require an active, verified user session (`get_verified_user`).
- **Strict Tenant Isolation**: Context queries enforce database-level `user_id` ownership; cross-tenant inquiries are rejected.
- **Rule 14 Prompt Injection Defense**: Scan findings, HTTP response bodies, DOM text, and extracted JavaScript are encapsulated in explicit `OBSERVED_DATA` blocks. The system prompt strictly prohibits target content from acting as directives.
- **Rule 13 Visual Data Boundary**: Circle to Sentinel screenshot pixels are treated as untrusted external observation data. Prompt override instructions rendered inside images are ignored.
- **Secret Sanitization**: Context strings pass through `app.ai.sanitize` before reaching LLMs; passwords, session cookies, database URLs, and bearer tokens are masked with `[REDACTED]`.
- **Grounded Evidence Mandate**: The model is forbidden from inventing findings, fabricating CVEs, or asserting external remediation. Conditions that cannot be observed passively are disclosed as `NOT_VERIFIABLE`.
- **Redis Sliding-Window Rate Limiting**: Enforces a strict ceiling of 20 requests per hour per user with fail-closed security.
- **Privacy & Transient Processing**: Circle to Sentinel visual captures are processed entirely in-memory and are never written to disk or persisted in database tables.

### Configuration

| Variable | Description |
|----------|-------------|
| `AI_PROVIDER` | `gemini` (current) or `openai` |
| `AI_GEMINI_API_KEY` | Google Gemini API key (never commit to Git) |
| `AI_GEMINI_MODEL` | Gemini model name (default: `gemini-3.6-flash`) |
| `AI_RATE_LIMIT_PER_HOUR` | Max AI requests per user per hour (default: 20) |

Ask Sentinel degrades gracefully: if the provider is not configured or returns an error, SentinelScan continues to function normally and returns a clean error message to the UI.

---

## ⚠️ Responsible Use

SentinelScan is intended for **authorized security assessment**, educational use, research, and testing of systems you own or have explicit permission to assess.

- Do not scan or assess systems without authorization.
- Do not attempt to bypass built-in security controls or rate limits.
- Use the platform only within the scope of authorization granted by the system owner.
- All scans are associated with the authenticated user's account and persisted in the database.

Users are responsible for ensuring that their use of SentinelScan complies with applicable laws, regulations, and organizational policies.

---

## 📄 License & Security

- **Security Policy**: Please review [SECURITY.md](SECURITY.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for vulnerability reporting guidelines.
- **Contributions**: Contributions are welcome under our [CONTRIBUTING.md](CONTRIBUTING.md) guidelines.
- **License**: This project is licensed under the [MIT License](LICENSE).
