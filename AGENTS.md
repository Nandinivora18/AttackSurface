# SentinelScan — Agent Guide

Full-stack passive web security scanner. FastAPI + PostgreSQL + Redis/ARQ worker backend, Next.js 14 frontend. `docs/` is extensive but frequently stale — **verify against code before trusting it**.

## Commands

- API (from `backend/`): `uvicorn app.main:app --reload` — reads `backend/.env` via pydantic-settings
- Worker (from `backend/`, separate terminal, required for scans): `python run_worker.py` — runs ARQ jobs + the 5-min `reconcile_orphan_scans` cron
- Tests (from `backend/`): `python -m pytest tests/ -v` — async tests use `@pytest.mark.asyncio`; **pytest / pytest-asyncio / aiosqlite are NOT in `requirements.txt`** (only in `.venv`), install dev deps separately on a fresh env
- Migrations: `alembic revision --autogenerate` / `alembic upgrade head` / `alembic check` (run from `backend/`). Head is `7340c9ab6be5` (drops legacy/removed tables; 7 active tables). `app/main.py` auto-creates tables via `create_all()` **only when `ENVIRONMENT != "production"`** — production schema is migration-driven and must never rely on `create_all()`.
- Frontend (from `frontend/`): `npm install; npm run dev` — needs `.env.local` with `NEXT_PUBLIC_API_URL` (defaults to `http://localhost:8000`). No tests, no eslint config.

## Architecture — read this before touching scanner code

- Scan flow: `POST /api/scans` (`app/routers/scans.py`) validates SSRF → inserts Scan (`pending`) → enqueues ARQ job `run_scan_job` with deterministic job id `scan:{scan_id}` → worker `app/tasks/scan_task.py` runs stages → persists Report/Findings in one commit → publishes terminal SSE event.
- **`app/scanner/engine.py` does not exist** (it was removed; it contained legacy `run_scan`/`stream_scan_progress` stubs that were dead code). The active orchestrator is `app/tasks/scan_task.py`. Do not create or extend engine.py. The real SSE route is `GET /api/scans/{scan_id}/stream` with `?token=` (see `app/utils/progress.py` for the Redis pub/sub pipeline).
- Scanner modules live in `app/scanner/` (`dns_checker`, `ssl_checker`, `header_analyzer`, `tech_detector`, `cve_checker`, `content_analyzer`, `scoring`, `threat_intel`). New detectors go in the relevant module and register in `app/scanner/metadata.py` `DETECTOR_REGISTRY` (37 entries — not "52" as old README claimed).
- Remediation Guidance: SentinelScan focuses on passive, actionable intelligence. Finding-level recommendations (`recommendation`, `problem`, `impact`, `fix_steps`, `configuration_example`, and documentation references) are generated directly for each finding and rendered in reports and finding views. The legacy external remediation engine/project-connection automation has been fully retired in favor of clean, passive finding triage.
- Scan states: `pending → running → completed|failed|cancelled`; terminal states never transition. Worker is idempotent and cooperative-cancellation aware — preserve that contract in any changes.

## Gotchas

- `app/config.py` validator: `ENVIRONMENT=production` forces `DEBUG=false` and `REQUIRE_EMAIL_VERIFICATION=true`, rejects weak/short `SECRET_KEY`, and forbids `DEV_BYPASS_EMAIL_VERIFICATION` — a violation raises `ValueError` at import and kills the process. If you add a setting that differs by env, update the validator.
- Docker: `docker/docker-compose.yml` resolves relative paths from `docker/` (so `../backend` references the actual `backend/` directory — this is correct). The compose files require `SECRET_KEY` (>= 32 chars) exported or placed in `docker/.env`. `docker-compose.prod.yml` additionally requires `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, and `REDIS_PASSWORD`. `nginx/nginx.conf` hardcodes `sentinelscan.io` as `server_name` — operators must update this for their domain. TLS certificates must be provisioned in `nginx/certs/` before starting nginx.
- Two scan rate limits exist: `MAX_ACTIVE_SCANS_PER_USER` (2 concurrent) and `RATE_LIMIT_SCANS_PER_HOUR` (10/hour via DB count in `app/routers/scans.py:172`). `@limiter.limit` decorators (slowapi) cover auth routes in `app/routers/auth.py`.
- Tests use in-memory aiosqlite and mock Redis/SMTP — no live network. `.github/workflows/` is empty (no CI).
- Dev `backend/.env` uses SQLite; compose uses Postgres. Keep both paths working when touching models or queries.
- The SSRF check (`app/routers/scans.py:33`) does synchronous `socket.getaddrinfo` (blocks the event loop) and validates only at enqueue time; scanner httpx clients follow redirects. Be cautious extending anything that fetches URLs.
- Passive-only by design: don't add active/authenticated scanning (see `docs/Limitations.md`).

## Conventions

- Conventional Commits (see `CONTRIBUTING.md`); PRs against `main`.
- Every new detector needs a false-positive regression test (`tests/test_*.py`, filename = tested module). Follow `docs/DeveloperGuide.md` for detector/endpoint/task patterns.
