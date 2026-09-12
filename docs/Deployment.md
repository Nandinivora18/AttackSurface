# Deployment Guide

## Environments

| Environment | Stack | Use Case |
|---|---|---|
| Development | Python venv + Node, local services | Active development |
| Docker (dev) | Docker Compose, hot-reload | Integration testing |
| Docker (prod) | Docker Compose with prod overrides | Staging / Production |

---

## Development (Manual)

### Prerequisites

- Python 3.13+
- Node.js 20+ and npm
- PostgreSQL 16 running locally
- Redis 7 running locally

### Backend Setup

```bash
# 1. Navigate to backend
cd backend

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
cp .env.example .env
# Edit .env — minimum required settings:
# DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/sentinelscan
# REDIS_URL=redis://localhost:6379/0
# SECRET_KEY=<generate 32+ char random string>
# ENVIRONMENT=development
# DEBUG=true
# DEV_BYPASS_EMAIL_VERIFICATION=true  # skips SMTP in dev

# 5. Create database (PostgreSQL must be running)
createdb sentinelscan   # or use pgAdmin

# 6. Run migrations
alembic upgrade head

# 7. Start API server
uvicorn app.main:app --reload --port 8000

# 8. Start worker (separate terminal)
python run_worker.py
```

### Frontend Setup

```bash
# 1. Navigate to frontend
cd frontend

# 2. Install dependencies
npm install

# 3. Configure environment
echo "NEXT_PUBLIC_API_URL=http://localhost:8000" > .env.local

# 4. Start development server
npm run dev
```

Visit [http://localhost:3000](http://localhost:3000)

---

## Docker Compose (Development)

The `docker/docker-compose.yml` defines all services for a containerized development environment.

```bash
# Build and start all services
docker compose -f docker/docker-compose.yml up -d

# View logs
docker compose -f docker/docker-compose.yml logs -f

# Run migrations inside the backend container
docker exec sentinelscan_backend alembic upgrade head

# Stop all services
docker compose -f docker/docker-compose.yml down
```

### Service Startup Order

Docker Compose `depends_on` with health checks ensures services start in the correct order:

```
PostgreSQL (healthy) ──►  Backend + Worker (start)
Redis (healthy) ─────►    Backend + Worker (start)
Backend (healthy) ───►    Frontend (start)
Frontend + Backend ──►    Nginx (start)
```

---

## Service Configuration Reference

### PostgreSQL

```yaml
postgres:
  image: postgres:16-alpine
  environment:
    POSTGRES_DB: sentinelscan
    POSTGRES_USER: sentinelscan
    POSTGRES_PASSWORD: sentinelscan_pass
  volumes:
    - postgres_data:/var/lib/postgresql/data
    - ./docker/init.sql:/docker-entrypoint-initdb.d/init.sql
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U sentinelscan"]
    interval: 10s
    timeout: 5s
    retries: 5
```

**Persistent storage:** The `postgres_data` named volume persists data across container restarts.

**Initialization:** `docker/init.sql` creates the database if it doesn't exist and sets up extensions.

---

### Redis

```yaml
redis:
  image: redis:7-alpine
  command: redis-server --appendonly yes
  volumes:
    - redis_data:/data
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
```

**Persistence:** `--appendonly yes` enables AOF persistence — Redis data survives container restarts.

**Production:** Add `--requirepass {password}` and set `REDIS_URL=redis://:password@redis:6379/0`.

---

### FastAPI Backend

```yaml
backend:
  command: >
    sh -c "alembic upgrade head &&
           uvicorn app.main:app --host 0.0.0.0 --port 8000"
  healthcheck:
    test: ["CMD-SHELL", "curl -f http://localhost:8000/api/health || exit 1"]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 20s
```

Migrations run automatically before the API starts. In production, consider running migrations as a separate init container or one-off command.

---

### ARQ Worker

```yaml
worker:
  command: python run_worker.py
  environment:
    WORKER_CONCURRENCY: "5"
  # No port exposure — only communicates via Redis + DB
```

The worker does not expose any ports. It only communicates through Redis (job queue) and PostgreSQL (data). Scaling: add more worker replicas.

---

### Next.js Frontend

```yaml
frontend:
  environment:
    NEXT_PUBLIC_API_URL: http://localhost:8000
  ports:
    - "3000:3000"
```

In production, `NEXT_PUBLIC_API_URL` should point to the public API URL (via Nginx).

---

### Nginx

```yaml
nginx:
  image: nginx:alpine
  ports:
    - "80:80"
    - "443:443"
  volumes:
    - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
```

Nginx routes traffic and handles TLS termination. The `nginx/nginx.conf` configuration proxies `/api/` to the FastAPI backend and everything else to the Next.js frontend.

---

## Environment Variables

Complete reference for all environment variables:

### Backend (`.env`)

| Variable | Default | Required | Description |
|---|---|---|---|
| `ENVIRONMENT` | `development` | ✅ | `development` or `production` |
| `DEBUG` | `true` | ✅ | `false` in production |
| `SECRET_KEY` | *(weak placeholder)* | ✅ | JWT signing key — ≥32 chars |
| `ALGORITHM` | `HS256` | — | JWT algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | — | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | — | Refresh token lifetime |
| `REQUIRE_EMAIL_VERIFICATION` | `true` | — | `true` always in production |
| `DEV_BYPASS_EMAIL_VERIFICATION` | `false` | — | `true` in dev without SMTP |
| `DATABASE_URL` | PostgreSQL async URL | ✅ | asyncpg connection string |
| `SYNC_DATABASE_URL` | PostgreSQL sync URL | ✅ | psycopg2 connection string (Alembic) |
| `REDIS_URL` | `redis://localhost:6379/0` | ✅ | Redis connection URL |
| `FRONTEND_URL` | `http://localhost:3000` | — | CORS allowed origin |
| `BACKEND_URL` | `http://localhost:8000` | — | Self-reference for email links |
| `SMTP_HOST` | `smtp.gmail.com` | — | SMTP server |
| `SMTP_PORT` | `587` | — | SMTP port |
| `SMTP_USER` | `null` | — | SMTP username |
| `SMTP_PASSWORD` | `null` | — | SMTP password |
| `SMTP_FROM` | `noreply@sentinelscan.io` | — | Sender address |
| `GOOGLE_CLIENT_ID` | `null` | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | `null` | — | Google OAuth client secret |
| `NVD_API_KEY` | `null` | — | NVD API key for CVE lookups |
| `MAX_SCAN_TIMEOUT` | `600` | — | Max scan job duration (seconds) |
| `WORKER_CONCURRENCY` | `5` | — | Concurrent scan jobs per worker |
| `WORKER_MAX_TRIES` | `3` | — | Max ARQ job delivery attempts |
| `RATE_LIMIT_SCANS_PER_HOUR` | `10` | — | Scan creation rate limit |
| `RATE_LIMIT_AUTH_PER_MINUTE` | `5` | — | Auth endpoint rate limit |
| `MAX_ACTIVE_SCANS_PER_USER` | `2` | — | Max pending+running per user |

### Frontend (`.env.local`)

| Variable | Required | Description |
|---|---|---|
| `NEXT_PUBLIC_API_URL` | ✅ | Backend API base URL |

---

## Production Checklist

Before deploying to production, verify each item:

### Security
- [ ] `SECRET_KEY` is a cryptographically random 32+ character string
- [ ] `ENVIRONMENT=production` and `DEBUG=false`
- [ ] `REQUIRE_EMAIL_VERIFICATION=true`
- [ ] `DEV_BYPASS_EMAIL_VERIFICATION=false` (or not set)
- [ ] PostgreSQL password is strong and unique (not `sentinelscan_pass`)
- [ ] Redis authentication enabled (`--requirepass`)
- [ ] PostgreSQL port NOT exposed publicly (internal Docker network only)
- [ ] Redis port NOT exposed publicly (internal Docker network only)
- [ ] Nginx TLS certificate installed and renewed
- [ ] HSTS enabled in Nginx config

### Operations
- [ ] `alembic upgrade head` has run successfully
- [ ] `/api/readiness` returns `{"ready": true}` with all checks passing
- [ ] Worker heartbeat visible in readiness response
- [ ] Log aggregation configured
- [ ] Database backup schedule in place
- [ ] Redis persistence enabled (`--appendonly yes`)

### Performance
- [ ] `WORKER_CONCURRENCY` tuned to available CPU cores
- [ ] PostgreSQL connection pool sized appropriately
- [ ] Nginx worker processes = number of CPUs

---

## Database Backups

```bash
# Backup PostgreSQL to file
docker exec sentinelscan_postgres pg_dump \
  -U sentinelscan sentinelscan > backup-$(date +%Y%m%d).sql

# Restore from backup
cat backup-20240115.sql | docker exec -i sentinelscan_postgres \
  psql -U sentinelscan sentinelscan
```

---

## Horizontal Scaling

**API:** Run multiple FastAPI instances behind Nginx (round-robin or least-connections). All state is in Redis and PostgreSQL.

**Worker:** Run multiple worker containers. All pull from the same `arq:queue` Redis list. ARQ handles job distribution automatically.

**Database:** PostgreSQL read replicas can serve read-heavy report queries. Write operations go to primary.

**Redis:** Redis Cluster or Redis Sentinel for high availability. ARQ supports Redis Cluster via `arq.connections.RedisSettings`.

---

## Health Check Endpoints

| Endpoint | Purpose | Expected Response |
|---|---|---|
| `GET /api/health` | Liveness — API alive | `200 {"status": "healthy"}` |
| `GET /api/readiness` | Readiness — all deps healthy | `200 {"ready": true, ...}` |

Use `/api/health` for container liveness probes and `/api/readiness` for load balancer health checks.
