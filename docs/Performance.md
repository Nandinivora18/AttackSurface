# Performance

## Overview

SentinelScan's performance characteristics are governed by three main factors:

1. **Network latency** to the target — the dominant cost for most scans
2. **Worker concurrency** — `WORKER_CONCURRENCY` controls parallel scan capacity
3. **Database query patterns** — all queries are indexed and bounded by ownership

---

## Scan Duration

Typical scan durations against public internet targets:

| Target Type | Duration |
|---|---|
| Fast CDN-hosted site (Cloudflare, Vercel) | 12–20 seconds |
| Standard web server (Apache/Nginx) | 20–35 seconds |
| Slow or rate-limiting server | 45–90 seconds |
| Site with many versioned technologies (CVE lookup) | 35–60 seconds |
| Maximum observed (complex + slow DNS) | ~120 seconds |
| Configured timeout | 600 seconds |

**Breakdown by stage (typical):**

| Stage | Duration |
|---|---|
| DNS Lookup | 0.3–1.5 seconds |
| SSL/TLS Analysis | 0.5–2.0 seconds |
| Header Analysis | 0.5–3.0 seconds |
| Technology Detection | 0.5–1.5 seconds |
| CVE Lookup (per technology) | 1.0–3.0 seconds (NVD API) |
| Content Analysis | 3–15 seconds (probes up to 15 paths) |
| Scoring + Persist | < 0.5 seconds |

The **content analysis stage** is the most variable because it makes up to 15 sequential HTTP probes. Against rate-limiting servers, this can take significantly longer.

---

## Worker Concurrency

**Default:** `WORKER_CONCURRENCY = 5` concurrent scan jobs per worker process

**Throughput estimation:**
- Average scan duration: ~30 seconds
- 5 concurrent workers
- Theoretical throughput: ~10 scans/minute per worker process

**Scaling:** Add more `worker` container replicas. Each replica can handle 5 concurrent scans. All workers share the same Redis job queue.

**Per-user limit:** `MAX_ACTIVE_SCANS_PER_USER = 2` prevents a single user from monopolizing the queue.

---

## Redis Performance

ARQ uses Redis as the job queue and pub/sub transport.

**Queue operations:**
- `LPUSH` (job enqueue): O(1), typically < 1ms
- `BRPOP` (job dequeue): O(1) blocking pop, wakes immediately when job available
- Poll delay: 0.5 seconds (time between empty polls)

**Progress pub/sub:**
- `PUBLISH` from worker: < 1ms
- `SUBSCRIBE` latency to API: < 1ms (same Redis instance)
- SSE delivery to browser: < 100ms total

**Heartbeat:** Written every 60 seconds, expires after 90 seconds.

---

## Database Performance

**Indexes defined:**

| Table | Indexed Columns |
|---|---|
| `users` | `email` (unique), `google_id` (unique) |
| `scans` | `user_id` |
| `reports` | `user_id` |
| `findings` | `report_id`, `cve_id` |
| `notifications` | `user_id` |
| `audit_logs` | `user_id` |

**Key query patterns:**
- List user scans: `WHERE user_id = $1 ORDER BY created_at DESC LIMIT 20` — uses `user_id` index
- Get report findings: `WHERE report_id = $1` — uses `report_id` index
- Dashboard summary: single query aggregating scan counts and latest score

**Query analysis:** All common queries hit an index. No full-table scans expected in normal operation.

---

## Async I/O

The FastAPI backend and ARQ worker are both fully async:

- **httpx** — all HTTP requests to target sites use async connections
- **asyncpg** — async PostgreSQL driver (no thread pool overhead)
- **redis-py** — async Redis client
- **dns.resolver** — DNS resolution runs in `run_in_executor` (blocking I/O off the event loop)
- **ssl module** — TLS handshake runs in `run_in_executor`

This means the Python event loop is never blocked by I/O, and each worker coroutine efficiently interleaves multiple concurrent scans.

---

## HTTP Client Tuning

The scanner uses `httpx` with:
- `timeout = 15s` for general requests (per-request timeout)
- `follow_redirects = True` (up to 10 redirects)
- `verify = True` (SSL verification enabled for scanner HTTP requests)
- `headers = {"User-Agent": "SentinelScan Security Scanner/1.0"}` (honest identification)

---

## CVE Lookup Performance

NVD API queries are the most latency-sensitive external calls:

- **Without API key:** 5 requests/30 seconds rate limit
- **With API key:** 50 requests/30 seconds rate limit
- **Per technology:** 1 NVD API call = 1–3 seconds
- **Skip condition:** If no versioned technologies are detected, the entire CVE stage is skipped

**Recommendation:** Set `NVD_API_KEY` in production to avoid rate limiting on scans of technology-rich sites.

---

## Content Analysis Probe Count

The content analyzer probes up to **15 sensitive paths**. Each probe is a sequential HTTP request. Total time = 15 × average_response_time.

**Optimization opportunities (not yet implemented):**
- Parallel probing (batch requests)
- Adaptive timeout based on target response time
- Probe skip list for known CDN patterns (Cloudflare blocks most probes anyway)

---

## Memory Usage

Typical memory usage per component:

| Component | Baseline | Per Scan |
|---|---|---|
| FastAPI API | ~80 MB | +~5 MB (SSE subscriber) |
| ARQ Worker | ~100 MB | +~30 MB (httpx + BS4 + findings) |
| PostgreSQL | ~100 MB | negligible |
| Redis | ~20 MB | +~1 KB per active scan (pub/sub + last event) |

---

## Optimization Checklist

- [x] All database queries hit indexes
- [x] Async I/O throughout (no blocking)
- [x] Gzip compression on API responses > 1000 bytes
- [x] Worker and API are separate processes (no GIL contention)
- [x] CVE stage skipped when no versioned technologies found
- [ ] Content probes run sequentially (not parallelized) — **future improvement**
- [ ] No response caching (scanner results are always fresh) — intentional
- [ ] No connection pooling for external httpx requests — httpx creates new connections per scan
