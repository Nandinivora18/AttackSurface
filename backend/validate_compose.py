"""Validate all Compose YAML files and identify defects."""
import yaml
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))

files = [
    os.path.join(BASE, "../docker/docker-compose.yml"),
    os.path.join(BASE, "../docker/docker-compose.dev.yml"),
    os.path.join(BASE, "../docker/docker-compose.prod.yml"),
]

defects = []

for f in files:
    fname = os.path.basename(f)
    try:
        with open(f) as fh:
            data = yaml.safe_load(fh)
        services = list(data.get("services", {}).keys())
        print(f"\n[VALID YAML] {fname}")
        print(f"  services: {services}")
        for svc, cfg in data.get("services", {}).items():
            hc = cfg.get("healthcheck")
            deps = cfg.get("depends_on")
            build = cfg.get("build")
            image = cfg.get("image", f"<build:{build.get('dockerfile', 'Dockerfile')}>" if build else "<unknown>")
            restart = cfg.get("restart", "no")
            cmd = cfg.get("command", "")
            env = cfg.get("environment", {})
            print(f"  [{svc}]")
            print(f"    image/build={image}")
            print(f"    restart={restart}")
            print(f"    healthcheck={bool(hc)}")
            print(f"    depends_on={list(deps.keys()) if isinstance(deps, dict) else deps}")

        # --- Defect checks ---
        svcs = data.get("services", {})

        # 1. Worker service missing in dev?
        if "worker" not in svcs:
            defects.append(f"{fname}: 'worker' service missing")

        # 2. Backend Dockerfile healthcheck uses /health (not /api/health)?
        backend = svcs.get("backend", {})
        backend_hc = backend.get("healthcheck", {})
        hc_test = str(backend_hc.get("test", ""))
        if "health" in hc_test and "/api/health" not in hc_test and "/health" in hc_test:
            defects.append(f"{fname}: backend healthcheck uses /health but API endpoint is /api/health")

        # 3. Nginx missing in prod?
        if "nginx" not in svcs and "prod" in fname:
            defects.append(f"{fname}: 'nginx' service missing in prod compose")

        # 4. Multiple workers defined?
        if "worker2" in svcs or "worker_2" in svcs:
            print(f"  [NOTE] Multiple workers defined in {fname}")

        # 5. Frontend standalone mode?
        frontend = svcs.get("frontend", {})
        frontend_build = frontend.get("build", {})
        print(f"  frontend build context: {frontend_build.get('context', 'N/A')}")

        # 6. Check backend command includes alembic migration
        backend_cmd = backend.get("command", "")
        if backend_cmd and "alembic" not in str(backend_cmd):
            defects.append(f"{fname}: backend command does not include alembic upgrade head")

    except Exception as e:
        defects.append(f"{fname}: YAML ERROR: {e}")
        print(f"\n[INVALID] {fname}: {e}")

# --- Check Nginx config ---
nginx_conf = os.path.join(BASE, "../nginx/nginx.conf")
try:
    with open(nginx_conf) as f:
        nginx_text = f.read()
    print(f"\n[Nginx Config] nginx.conf ({len(nginx_text)} bytes)")
    checks = {
        "proxy_buffering off": "proxy_buffering off" in nginx_text,
        "proxy_read_timeout": "proxy_read_timeout" in nginx_text,
        "proxy_http_version 1.1": "proxy_http_version 1.1" in nginx_text,
        "X-Accel-Buffering no": 'X-Accel-Buffering "no"' in nginx_text,
        "SSE location /api/scans": "location /api/scans" in nginx_text,
        "HTTPS configured": "ssl_certificate" in nginx_text,
        "HSTS header": "Strict-Transport-Security" in nginx_text,
        "Rate limiting": "limit_req_zone" in nginx_text,
    }
    for check, result in checks.items():
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {check}")
        if not result:
            defects.append(f"nginx.conf: missing {check}")
except Exception as e:
    defects.append(f"nginx.conf: ERROR: {e}")

# --- Check Dockerfiles ---
backend_df = os.path.join(BASE, "Dockerfile")
try:
    with open(backend_df) as f:
        df_text = f.read()
    print(f"\n[Backend Dockerfile]")
    df_checks = {
        "Multi-stage build": "AS builder" in df_text,
        "Non-root user": "appuser" in df_text or "USER " in df_text,
        "PYTHONDONTWRITEBYTECODE": "PYTHONDONTWRITEBYTECODE" in df_text,
        "PYTHONUNBUFFERED": "PYTHONUNBUFFERED" in df_text,
        "EXPOSE 8000": "EXPOSE 8000" in df_text,
        "asyncpg dependency (psycopg/asyncpg in requirements)": True,  # will check requirements.txt
    }
    for check, result in df_checks.items():
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {check}")
        if not result:
            defects.append(f"backend/Dockerfile: missing {check}")

    # Check healthcheck path
    if "/health" in df_text and "/api/health" not in df_text:
        print("  [WARN] Dockerfile HEALTHCHECK uses /health (not /api/health)")
        defects.append("backend/Dockerfile: HEALTHCHECK uses /health instead of /api/health")
except Exception as e:
    defects.append(f"backend/Dockerfile: ERROR: {e}")

# --- Check requirements.txt for PostgreSQL + ARQ ---
req_file = os.path.join(BASE, "requirements.txt")
try:
    with open(req_file) as f:
        reqs = f.read().lower()
    print(f"\n[requirements.txt checks]")
    req_checks = {
        "asyncpg (PostgreSQL async driver)": "asyncpg" in reqs,
        "psycopg2 (PostgreSQL sync driver)": "psycopg2" in reqs or "psycopg" in reqs,
        "arq": "arq" in reqs,
        "redis": "redis" in reqs,
        "sqlalchemy": "sqlalchemy" in reqs,
        "alembic": "alembic" in reqs,
        "reportlab (PDF)": "reportlab" in reqs,
        "httpx": "httpx" in reqs,
    }
    for check, result in req_checks.items():
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {check}")
        if not result:
            defects.append(f"requirements.txt: missing {check}")
except Exception as e:
    defects.append(f"requirements.txt: ERROR: {e}")

# --- Check frontend next.config.js for standalone output ---
next_config = os.path.join(BASE, "../frontend/next.config.js")
if not os.path.exists(next_config):
    next_config = os.path.join(BASE, "../frontend/next.config.mjs")
try:
    with open(next_config) as f:
        nc_text = f.read()
    print(f"\n[next.config check]")
    standalone = "standalone" in nc_text
    print(f"  [{'PASS' if standalone else 'FAIL'}] output: 'standalone' (required for Docker)")
    if not standalone:
        defects.append("frontend/next.config: missing output: 'standalone' (required for Docker Dockerfile)")
except Exception as e:
    defects.append(f"next.config: not found or ERROR: {e}")

# --- Summary ---
print(f"\n{'='*60}")
print(f"DEFECTS FOUND: {len(defects)}")
for d in defects:
    print(f"  [DEFECT] {d}")
if not defects:
    print("  No defects found.")
print("="*60)
