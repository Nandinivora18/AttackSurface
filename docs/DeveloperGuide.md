# Developer Guide

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Python | ≥ 3.13 | Backend runtime |
| Node.js | ≥ 20 | Frontend build |
| PostgreSQL | 16 | Database |
| Redis | 7 | Job queue + pub/sub |
| Docker Desktop | ≥ 24 | Containerized setup |
| Git | any | Version control |

---

## Project Setup

See [Deployment Guide — Development section](Deployment.md#development-manual) for the complete setup walkthrough.

**Quick reference:**
```bash
# Backend
cd backend && python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
alembic upgrade head
uvicorn app.main:app --reload

# Worker (separate terminal)
python run_worker.py

# Frontend (separate terminal)
cd frontend && npm install && npm run dev
```

---

## Folder Structure and Conventions

### Backend Conventions

| Layer | Location | Responsibility |
|---|---|---|
| Models | `app/models/` | SQLAlchemy ORM table definitions |
| Schemas | `app/schemas/` | Pydantic request/response types |
| Routers | `app/routers/` | FastAPI route handlers |
| Services | `app/services/` | Business logic (email, auth) |
| Scanner | `app/scanner/` | Core scanning modules |
| Tasks | `app/tasks/` | ARQ task functions |
| Utils | `app/utils/` | Shared utilities (JWT, cache, progress) |
| Config | `app/config.py` | pydantic-settings configuration |

**Naming conventions:**
- File names: `snake_case.py`
- Class names: `PascalCase`
- Functions: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Test files: `test_{module_name}.py`

### Frontend Conventions

- Pages: `page.tsx` in route directories
- Components: `PascalCase.tsx`
- Hooks: `use{Name}.ts`
- Types: `types/{domain}.ts`
- API functions: `lib/api.ts`

---

## Architecture Principles

1. **Separation of concerns** — API never executes scans; worker never handles HTTP requests
2. **Idempotency** — all worker tasks are safe to retry without side effects
3. **Fail-secure** — missing configuration causes startup failure rather than silent insecurity
4. **Evidence-first** — every finding must include machine-verifiable evidence
5. **False-positive avoidance** — prefer missing a finding over reporting a spurious one
6. **Ownership isolation** — every data query includes user ownership filter

---

## Adding a New Detector

A detector is a function that analyzes some aspect of the target and returns a list of finding dicts.

### Step 1: Choose the module

Add your detector to the most relevant scanner module:

| Module | Add detector here if... |
|---|---|
| `header_analyzer.py` | It analyzes HTTP response headers |
| `dns_checker.py` | It queries DNS records |
| `ssl_checker.py` | It analyzes TLS/certificate data |
| `tech_detector.py` | It fingerprints technology |
| `content_analyzer.py` | It probes URLs or analyzes HTML |
| `cve_checker.py` | It queries NVD for CVEs |

### Step 2: Implement the detector

A detector function adds findings to a list using this structure:

```python
def _check_my_header(headers: dict, url: str) -> list[dict]:
    findings = []

    value = headers.get("X-My-Header", "")

    if not value:
        findings.append({
            "category": "Security Headers",
            "title": "Missing X-My-Header",
            "description": "The X-My-Header is not set, which means ...",
            "severity": "medium",
            "cvss_score": 4.3,
            "confidence": "high",
            "recommendation": "Set X-My-Header: safe-value",
            "references": ["https://example.com/header-spec"],
            "evidence": f"X-My-Header not present in response from {url}",
        })

    return findings
```

**Required fields:** `category`, `title`, `description`, `severity`, `confidence`, `recommendation`, `references`, `evidence`

**Optional fields:** `cvss_score`, `cwe_id`, `cve_id`, `endpoint`

**Severity values:** `critical`, `high`, `medium`, `low`, `info`

**Confidence values:** `high`, `medium`, `low`

### Step 3: Call from the analyzer

```python
async def analyze_headers(url: str) -> dict:
    findings = []
    # ... existing code ...

    findings.extend(_check_my_header(headers, url))

    return {"findings": findings, "raw_headers": dict(headers)}
```

### Step 4: Write regression tests

```python
class TestMyHeaderDetector:
    def test_missing_header_produces_finding(self):
        headers = {}
        result = _check_my_header(headers, "https://example.com")
        assert any(f["title"] == "Missing X-My-Header" for f in result)

    def test_present_header_produces_no_finding(self):
        headers = {"X-My-Header": "safe-value"}
        result = _check_my_header(headers, "https://example.com")
        assert not any(f["severity"] in ("high", "medium") for f in result)
```

### Step 5: Verify threat intel mapping

Open `threat_intel.py` and ensure your finding category/title maps to the correct OWASP Top 10 and MITRE ATT&CK entries. Add an entry if needed.

---

## Adding an API Endpoint

### Step 1: Define the schema

In `app/schemas/`:

```python
# schemas/my_feature.py
from pydantic import BaseModel

class MyRequest(BaseModel):
    name: str
    value: int

class MyResponse(BaseModel):
    id: str
    result: str
```

### Step 2: Implement the route

In `app/routers/`:

```python
# routers/my_feature.py
from fastapi import APIRouter, Depends
from app.services.auth_service import get_verified_user
from app.schemas.my_feature import MyRequest, MyResponse

router = APIRouter(prefix="/api/my-feature", tags=["My Feature"])

@router.post("", response_model=MyResponse, status_code=201)
async def create_thing(
    payload: MyRequest,
    current_user = Depends(get_verified_user),
):
    # IMPORTANT: always filter by current_user.id for user-owned resources
    return MyResponse(id="...", result="...")
```

### Step 3: Register the router

In `app/main.py`:

```python
from app.routers import my_feature
app.include_router(my_feature.router)
```

### Step 4: Add tests

Follow the patterns in `tests/test_core.py`.

---

## Adding a Worker Task

Worker tasks must be:
1. **Idempotent** — safe to execute multiple times
2. **Cancellation-aware** — check for cancellation between expensive operations
3. **Registered** in `WorkerSettings.functions`

```python
# tasks/my_task.py
async def my_background_job(ctx: dict, item_id: str) -> dict:
    """
    ARQ task function. Must be idempotent.
    ctx contains ARQ job context (job_id, etc.)
    """
    # Check if already done (idempotency guard)
    async with AsyncSessionLocal() as db:
        item = await db.get(MyModel, item_id)
        if item.status == "done":
            return {"skipped": True}  # already completed

    # Do work...
    return {"success": True}
```

Register in `app/worker.py`:

```python
from app.tasks.my_task import my_background_job

class WorkerSettings:
    functions = [run_scan_job, my_background_job]
```

---

## Debugging

### API Logs

```bash
# View FastAPI logs
uvicorn app.main:app --reload --log-level debug
```

### Worker Logs

```bash
python run_worker.py
# Logs print to stdout with level, timestamp, and scan_id
```

### Database Inspection

```bash
# Connect to PostgreSQL
psql -U sentinelscan sentinelscan

# View recent scans
SELECT id, url, status, created_at FROM scans ORDER BY created_at DESC LIMIT 10;

# View findings for a report
SELECT title, severity, confidence FROM findings WHERE report_id = 'report-uuid-here';
```

### Redis Inspection

```bash
# Connect to Redis
redis-cli

# Check queue depth
LLEN arq:queue

# Check worker health
GET arq:health:sentinelscan-worker

# List recent job keys
KEYS arq:job:*
```

### API Docs (Development)

When `DEBUG=true`, FastAPI auto-generates interactive API docs:
- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`

---

## Coding Standards

### Python

- Python 3.13+ features (match statements, type hints on all functions)
- `async`/`await` for all I/O
- SQLAlchemy async session via `AsyncSessionLocal()`
- Pydantic v2 schemas for all request/response types
- Type annotations on all public functions
- Docstrings on module-level functions

### TypeScript / React

- Strict TypeScript (`strict: true` in tsconfig)
- Function components with hooks (no class components)
- `async`/`await` for all API calls
- Explicit return types on utility functions

### Tests

- Test class per feature
- `test_{what_it_does}` method names (descriptive, lowercase, underscored)
- Assertions test behaviour, not implementation details
- Mock only external dependencies (network, SMTP)

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write your code following the coding standards
4. Write tests for new functionality
5. Ensure all tests pass: `.venv/Scripts/python.exe -m pytest tests/ -v` (Windows) or `.venv/bin/python -m pytest tests/ -v` (macOS/Linux)
6. Submit a pull request with a description of the change

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contribution workflow.

---

## Environment Variable Reference

See [docs/Deployment.md — Environment Variables](Deployment.md#environment-variables) for the complete reference.

**Key settings for development:**

```ini
ENVIRONMENT=development
DEBUG=true
DEV_BYPASS_EMAIL_VERIFICATION=true   # skip email verification locally
SECRET_KEY=any-32-char-string-for-dev
```
