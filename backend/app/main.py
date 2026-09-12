import logging
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.database import create_tables
from app.routers import auth, users, scans, reports, admin, notifications, oauth
from app.exceptions import SentinelException, sentinel_exception_handler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

limiter = Limiter(key_func=get_remote_address, key_style="endpoint")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SentinelScan API starting up...")

    # Create DB tables ONLY in non-production environments (dev convenience).
    # Production schema management is migration-driven (alembic upgrade head);
    # create_all() is never relied upon for production schema creation.
    if settings.ENVIRONMENT != "production":
        try:
            await create_tables()
            logger.info("Database tables created/verified (non-production)")
        except Exception as e:
            logger.warning(f"DB auto-create skipped (use alembic migrations): {e}")

    # ARQ-aware startup reconciliation.
    # With ARQ workers, we must NOT blindly mark all pending/running scans as failed.
    # ARQ will re-deliver jobs within their retry budget.
    # We only log orphaned running scans here for observability.
    # The worker's on_startup hook performs deeper reconciliation.
    try:
        from app.database import AsyncSessionLocal
        from app.models.scan import Scan, ScanStatus
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Scan).where(Scan.status.in_([ScanStatus.running, ScanStatus.pending]))
            )
            active = result.scalars().all()
            if active:
                logger.info(
                    f"API startup: {len(active)} scan(s) in active state "
                    "(pending/running). ARQ workers will process these. "
                    "Call GET /api/readiness to verify worker health."
                )
    except Exception as e:
        logger.error(f"Startup scan check failed (non-fatal): {e}")

    yield
    logger.info("SentinelScan API shutting down")
    # Close the shared Redis client if open
    try:
        from app.utils.cache import close_redis
        await close_redis()
    except Exception:
        pass
    # Close the shared ARQ pool if open
    try:
        from app.routers.scans import _close_arq_pool
        await _close_arq_pool()
    except Exception:
        pass


app = FastAPI(
    title="SentinelScan API",
    description="Website Security Assessment Platform — Know Every Vulnerability Before Attackers Do",
    version=settings.APP_VERSION,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_exception_handler(SentinelException, sentinel_exception_handler)

# CORS
cors_origins = list(set([
    settings.FRONTEND_URL,
    "http://localhost:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
]))
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# Gzip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Response-Time"] = f"{(time.time() - start)*1000:.2f}ms"

    # ── Content-Security-Policy ──────────────────────────────────────────── #
    # Swagger / ReDoc documentation UIs need inline scripts and styles to
    # function. We relax CSP only on those routes and only when DEBUG=True
    # (docs are hidden in production anyway). All other routes get a
    # restrictive policy that prohibits scripts, frames, and connections.
    docs_paths = ("/api/docs", "/api/redoc", "/api/openapi.json")
    is_docs_route = request.url.path.startswith(docs_paths)

    if settings.DEBUG and is_docs_route:
        # Minimal relaxation for Swagger/ReDoc — scoped to development docs only.
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "img-src 'self' data: cdn.jsdelivr.net fastapi.tiangolo.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'"
        )
    else:
        # Restrictive policy for all production / non-docs API routes.
        csp = "default-src 'none'; frame-ancestors 'none'"

    response.headers["Content-Security-Policy"] = csp
    return response


# Routers
app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(users.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(notifications.router)
app.include_router(admin.router)


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Liveness — API process is alive."""
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.get("/api/readiness", tags=["Health"])
async def readiness_check():
    """
    Readiness — checks that required dependencies are reachable.

    Returns 200 if ready, 503 if any required dependency is unavailable.
    """
    checks = {}
    ready = True

    # Database check
    try:
        from app.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        checks["database"] = {"status": "ok"}
    except Exception as e:
        checks["database"] = {"status": "error", "detail": str(e)}
        ready = False

    # Redis check
    try:
        from app.utils.cache import get_redis
        redis = await get_redis()
        await redis.ping()
        checks["redis"] = {"status": "ok"}

        # Worker health check — ARQ workers write a heartbeat key
        worker_key = "arq:health:sentinelscan-worker"
        worker_ts = await redis.get(worker_key)
        if worker_ts:
            try:
                ts = float(worker_ts)
            except (TypeError, ValueError):
                try:
                    import datetime
                    date_part = worker_ts.split(" j_")[0].strip()
                    now = datetime.datetime.now(datetime.timezone.utc)
                    dt = datetime.datetime.strptime(f"{now.year} {date_part}", "%Y %b-%d %H:%M:%S")
                    # Attach UTC tzinfo so .timestamp() uses the correct epoch offset
                    # regardless of the server's local timezone.
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                    ts = dt.timestamp()
                except Exception:
                    ts = 0.0
            age_seconds = time.time() - ts
            if age_seconds > settings.WORKER_HEARTBEAT_STALE_SECONDS:
                checks["worker"] = {
                    "status": "stale",
                    "last_heartbeat": worker_ts,
                    "age_seconds": round(age_seconds, 1),
                    "detail": (
                        f"Worker heartbeat is {age_seconds:.0f}s old "
                        f"(threshold {settings.WORKER_HEARTBEAT_STALE_SECONDS}s) — "
                        "worker may be down"
                    ),
                }
                ready = False
            else:
                checks["worker"] = {
                    "status": "ok",
                    "last_heartbeat": worker_ts,
                    "age_seconds": round(age_seconds, 1),
                }
        else:
            checks["worker"] = {
                "status": "unknown",
                "detail": "No worker heartbeat found — start the worker process"
            }
    except Exception as e:
        checks["redis"] = {"status": "error", "detail": str(e)}
        checks["worker"] = {"status": "unknown", "detail": "Redis unavailable"}
        ready = False

    return JSONResponse(
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "ready": ready,
            "checks": checks,
            "environment": settings.ENVIRONMENT,
        }
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    detail = getattr(exc, "detail", None) or "Resource not found"
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": detail},
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: Exception):
    logger.error(f"Internal server error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal server error occurred"},
    )
