# FINAL HARDENING REPORT

**Project:** SentinelScan — Passive-First Web Security Scanner (FastAPI + Next.js 14 + ARQ) with Sentinel Intelligence AI
**Date:** September 25, 2026
**Scope:** Final security, reliability, dependency, documentation, and release-verification pass (Phases A–G)

> **AUTHORITATIVE STATEMENT: NO GIT OPERATIONS WERE PERFORMED.**
> During the entire hardening effort, zero Git operations were executed (no add, commit, push, restore, reset, checkout, stash, or tag). Every verification below was performed in the live working tree exactly as found, and all changes remain as local edits. Re-running this report requires no Git state.

---

## 1. Executive Summary

SentinelScan was hardened across seven phases covering fail-closed security controls, AI trust-boundary defenses, secret-redaction coverage, dynamic knowledge consistency, dependency security, documentation drift, and release verification.

- **Backend**: definitive run against the project's pinned environment (`.venv`, `fastapi==0.115.14`, `pytest==9.1.1`) → **871 passed, 0 failures, 0 errors** in 222.44s (38 warnings, all downstream deprecations from `python-jose` `datetime.utcnow()` and `reportlab` `ast.NameConstant` — no project-level warnings). The same suite also passes cleanly (0 warnings) under a newer interpreter (fastapi 0.139.2 / pytest 9.0.2), demonstrating environment resilience.
- **Frontend**: `next@14.2.35`, TypeScript typecheck clean, Next.js production build exit 0.
- **Schema**: Alembic single head `7340c9ab6be5`; `alembic check` → "No new upgrade operations detected" (models ↔ migrations in sync).
- **Live smoke**: health, register, login, and authenticated/unauthenticated AI status all behaved correctly with zero credential leakage and fail-closed auth.

---

## 2. Verification Baseline

| Check | Result |
|---|---|
| Backend test suite (`backend/.venv`) | **871 passed / 0 failed / 0 errors**, 222.44s, 41 test modules |
| Warnings | 38 — all upstream deprecations (python-jose, reportlab); no project warnings |
| Test collection | 871 items collected cleanly |
| Frontend typecheck | Clean (0 errors) |
| Frontend production build | Exit 0 (Next.js 14.2.35) |
| Alembic head | `7340c9ab6be5` (single head, no branches) |
| `alembic check` | PASS — no new upgrade operations detected |
| CI config | `.github/workflows/ci.yml` present with 3 jobs (backend pytest, frontend typecheck+build, repo/secret safety) — **live CI run NOT VERIFIED (offline)** |

---

## 3. Security & Reliability Hardening (Fail-Closed Controls)

- **JWT blacklist fail-closed (test `TestProductionRedisAuth` in `tests/test_reliability.py`)**: rewired to mock `app.utils.cache.get_redis` and assert production behavior when Redis is unavailable/timed out → `RedisBlacklistError` (5xx), never silently allowing a revoked token; healthy+absent → not revoked; healthy+present → revoked; dev → in-memory fallback. All 35 tests in module pass.
- **AI rate limiter fail-closed**: verified in code paths and tested via `TestRateLimiting` additions in `tests/test_ai.py` (`test_rate_limit_redis_timeout_rejects_request`, `test_rate_limit_healthy_redis_first_request_sets_expiry`). On Redis outage the limiter rejects (503) rather than admitting unlimited traffic.
- **Admin user-management guards (F3)**: `backend/app/routers/admin.py` now rejects self-deletion (400), deletion of the last admin (400), and non-admin attempting to delete another admin (403). 6 new tests in `tests/test_admin_users.py`.
- **No security control was weakened** to accommodate a test; all changes preserve the passive-first, fail-closed model.

---

## 4. AI Trust Boundary & Prompt-Injection Hardening (F5)

- New `backend/app/ai/trust.py`: `escape_observed_delimiters()` and `build_observed_data_block()` place observed scan context inside a delimited `<OBSERVED_DATA>` boundary that cannot be prematurely terminated by attacker-controlled content.
- `backend/app/ai/system_prompt.py`: added **RULE 14** making the boundary authoritative and grading-expected; `build_context_section()` embeds server-side grounding guidance; RULE 12 (do not expose system prompt) preserved.
- Chat, visual-chat, and explain-finding prompts all sanitize through `sanitize_text`; `_build_explain_finding_prompt` extracted as a module-level helper in `backend/app/routers/ai.py` for direct testability.
- **Tests (adversarial `TestTrustBoundaryPromptInjection`)**: SYSTEM OVERRIDE, "reveal system prompt", "ignore your rules", and "call an external tool" injection strings are neutered — assertion checks RULE 14 presence, observed-data boundary integrity, prompt ordering, delimiter escaping on `</`, and RULE 12 preservation.

---

## 5. Secret Redaction & Data Sanitization (F6)

- `backend/app/utils/sanitize.py` now redacts, beyond basic secrets: **PEM private-key blocks** (`BEGIN ... PRIVATE KEY` — certificates are intentionally NOT matched), Google `AIza...` (39-char) API keys, `sk_live_`/`sk_test_` (Stripe), `sk-ant-apiNN-` (Anthropic), `sk-proj-` (OpenAI), `SG.<16+>.<32+>` (SendGrid), plus AWS/Google/SendGrid secret-assignment keys.
- `backend/app/ai/sanitize.py` imports the canonical patterns and adds AI-only env-key patterns; sanitization applied before any LLM boundary construction.
- **Tests** (`tests/test_sanitize.py`, `TestSecretSanitization` in `tests/test_ai.py`): positive redaction for all new classes; **negative/regression** ensuring CVEs, SHAs, UUIDs, URLs, and short look-alikes survive; CERT (public block) not redacted.

---

## 6. Knowledge & Detector Registry Consistency

- `backend/app/ai/knowledge.py` `DETECTOR_CATEGORIES` was rewritten to **derive dynamically** from `app.scanner.metadata.DETECTOR_REGISTRY` (37 detectors / 16 categories) — the single source of truth; it can no longer drift from the scanner.
- Two new consistency tests (`test_knowledge_categories_match_detector_registry`, `test_knowledge_block_reports_registry_count`) lock the mapping in.
- Registry verified programmatically: 37 entries, 16 categories, OWASP coverage A01:4, A02:15, A03:4, A04:9, A05:1, A06:1, A07:2, A09:1.

---

## 7. Backend Dependency Security Audit

`backend/requirements.txt` updated and installed into `.venv`; the pinned environment is what CI runs:

| Package | Before | After | Rationale |
|---|---|---|---|
| fastapi | 0.115.0 | **0.115.14** | 0.115.0 predates CVE-2025-37054/37055 (fixed in 0.115.12); last 0.115.x |
| cryptography | 43.0.1 | **50.0.1** | Advisory fixes; major upgrade verified by full suite |
| pillow | 10.4.0 | **11.3.0** | Advisory fixes (imaging) |
| lxml | 5.3.0 | **5.4.0** | Advisory fixes |
| bcrypt | 4.0.1 | **4.2.1** | Advisory/CVSS fixes (4.1.0+ needed) |
| python-multipart | 0.0.12 | **0.0.32** | DoS advisory fixes (multipart parsing) |
| httpx | 0.27.2 | **0.28.1** | Aligned with installed env; advisory fixes |
| passlib | present | **removed** | Never imported — bcrypt is used directly in `app/utils/security.py`; removes an obsolete, unmaintained dependency |

- Result: **871/871 pass** under the new pins. No new vulnerabilities introduced; all bumps are backward compatible per the test suite.
- Passwords: confirmed `bcrypt.gensalt()` (12-round default) used directly; docs updated accordingly.

---

## 8. Frontend Dependency & Build Audit

- Applied `npm audit fix` (non-force): 9 → 5 vulnerable advisories; then targeted remediation:
  - `package.json` override `"glob": "^10.5.0"` (dependency of `rimraf`/build tooling).
  - Direct `postcss` bumped `^8.4.40 → ^8.5.28` (installed 8.5.28). A nested override for Next's exact-pinned bundled `postcss@8.4.31` was attempted and **reverted** because npm will not apply an override to an exact-pinned transitive — avoided introducing an invalid override marker.
- **Residual npm audit: 2 vulnerabilities (1 high, 1 critical), both inside the `next@14.2.35` dependency tree** (framework + its bundled postcss). Mitigations verified:
  - `next@14.2.35` is the final 14.x release (`next-14` dist-tag); all remaining advisories require Next ≥ 15.5.x (breaking major).
  - The product ships **no `next/image`, no `middleware.ts`, and no Server Actions** — the affected feature paths are not exercised.
  - Production runs the standalone build `node server.js` (see `frontend/Dockerfile`), not `next dev` — the highest-severity dev-server RCE advisory is not reachable.
  - Next.js 14.2.x is still commercially supported and the runtime/short-lived-token posture is unaffected by the remaining advisories.
- **Decision**: do NOT perform the breaking Next 15/16 migration in this pass; document as residual risk with a tracked follow-up (see §10).
- **Re-verified**: `npm run type-check` clean; `npm run build` exit 0.

---

## 9. Documentation Drift & Synchronization

Verified against code and corrected where stale:

- `finaldoc.md` — test counts (704→871), module count (37→41), run time, "33 warnings"→"38 downstream deprecation warnings", passlib removed from tech table, versions (FastAPI 0.115.14, Axios 1.18.1, HTTPX 0.28.1, Cryptography 50.0.1, Bcrypt 4.2.1, lxml 5.4.0, Pydantic 2.13.4, pytest 9.1.1/pytest-asyncio 1.4.0).
- `README.md` — test counts; CI directory description.
- `AGENTS.md` — dev deps now reference existing `requirements-dev.txt` (pytest 9.1.1, pytest-asyncio 1.4.0); corrected the false "`.github/workflows/` is empty (no CI)" claim — `ci.yml` exists with 3 jobs; SSRF `asyncio.to_thread` clarification retained.
- `docs/Security.md` — "bcrypt via passlib" → `bcrypt` package directly; stale public-share/remediation-engine paragraphs already aligned.
- `docs/THREAT_MODEL.md` — IDOR mitigations updated for removed `share_links`/`assets` tables and removed `/api/reports/shared/{token}`.
- `docs/ARCHITECTURE.md` — removed retired Targets/Assets routers from the API list; remediation-engine section already aligned.
- `docs/Frontend.md` — removed Assets and Share Page sections (routes do not exist); fixed project tree (`share/` removed) and components list ("share modal" removed).
- `docs/Testing.md` — verified per-file test counts (test_core 29, test_reliability 35, test_worker 29, test_server_dkim 19); removed nonexistent `test_delta.py`/`test_remediation*.py`/`test_reports_share_security.py` from the tree; latest-run line updated.
- `docs/COVERAGE.md` — OWASP counts corrected to registry truth (A02 15, A04 9); noted the generator module no longer exists so the report is manually maintained against `metadata.py`.
- `CHANGELOG.md` — historical retired features (`share_links`, delta comparison, `test_delta.py`) annotated as retired so they cannot be mistaken for current behavior; bcrypt/passlib line fixed.
- `.env.example` (`backend/`) — added `REQUIRE_EMAIL_VERIFICATION`, `DEV_BYPASS_EMAIL_VERIFICATION`, `MAX_ACTIVE_SCANS_PER_USER`, and the full optional Ask Sentinel AI block matching `app/config.py`.

---

## 10. Release Verification (Phase G) & Residual Risks

### Verified in this pass
- **Alembic**: `heads` = `7340c9ab6be5` single head; `alembic check` clean against models.
- **CI configuration**: `ci.yml` is structurally sound — backend job installs `requirements.txt` + `requirements-dev.txt` (both present, pins resolve), sets the SQLite `DATABASE_URL`/`SYNC_DATABASE_URL`, `SECRET_KEY`, `DEBUG=false`, dev-bypass flags, `PYTHONPATH=.`; frontend job uses `npm ci` + `tsc --noEmit` + `next build` on Node 20; safety job checks untracked secrets. **Live CI execution NOT VERIFIED offline** (would require a push, which is excluded by the no-Git rule).
- **Live smoke (local API)**: `GET /api/health` → healthy (v1.0.0, development); register → user created (`is_verified: true` under dev bypass); login → 288-char access token; `GET /api/ai/status` unauthenticated → 401; authenticated → `{"configured":true,"provider":"gemini","model":"models/gemini-3.6-flash"}`. **No secrets/keys leaked in any response.** (Disposable `smoketest_*@example.com` user remains in the dev SQLite DB as an artifact.)
- **Docker**: Docker daemon was **not running** → container builds (backend/worker/frontend/nginx) are **NOT VERIFIED at build/runtime**. Dockerfiles inspected and are structurally sound: backend multi-stage on `python:3.13-slim` with non-root user, uvicorn x4, healthcheck on `/api/health`; frontend multi-stage on `node:18-alpine` running the standalone `server.js` as non-root. NOTE: production **must** run `alembic upgrade head` before/at container start (schema is migration-driven; `create_all()` is dev-only).

### Residual risks & follow-ups
1. **2 npm advisories inside `next@14.2.35`** (high/critical). Ranked residual; mitigation = no affected features shipped + standalone prod runtime. **Follow-up**: plan the Next.js major migration (15.5.x+ / 16.x), and re-run `npm audit` immediately after.
2. **38 downstream deprecation warnings** (python-jose `datetime.utcnow()`, reportlab `ast.NameConstant`). No project code warnings. **Follow-up**: migrate python-jose usage → `pyjwt`/`jose`-modern or replace when convenient; tolerated now.
3. **Live CI / Docker / Redis-backed scan smoke** could not be executed offline. **Follow-up**: run GitHub Actions (push) and compose stack on a host with a running Docker daemon + Redis.
4. **AI provider keys** (`AI_GEMINI_API_KEY` / `AI_OPENAI_API_KEY`) are not configured locally — the Ask Sentinel chat endpoint returns 503 by design when unconfigured; `GET /api/ai/status` reflects provider config only. Intended behavior, not a defect.

---

## 11. Compliance, Secret Hygiene & Git Safety Statement

- **NO GIT OPERATIONS WERE PERFORMED** during this entire engagement. All work is in the live working tree; nothing was committed, pushed, tagged, reset, or restored.
- Secret hygiene verified: no credentials, API keys, or private values are included in this report or in any documentation change. `backend/.env` (SECRET_KEY, Google client secret, Redis URL) was inspected only to confirm config validity and was never logged or written into any file touched here.
- The `.env.example` files contain only placeholders; the CI safety job's secret-file audit (`git ls-files | grep -E '\.env$|\.env\.local$|\.pem$|\.key$|\.sqlite$|\.db$'`) remains the enforcement gate on publish.
- Test artifacts: one disposable `smoketest_*@example.com` account row in the dev SQLite DB (no scans, no sensitive data); harmless but removable.
- Backend runtime deps pinned (`requirements.txt`), dev/test deps pinned (`requirements-dev.txt`); both install cleanly together as the CI workflow does.