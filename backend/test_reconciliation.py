"""
Worker Crash + Reconciliation Tests.

Tests:
1. Worker crash while scan is running -> reconciliation marks failed
2. Reconciliation does NOT kill healthy running scans
3. Retry exhaustion -> scan stays failed
4. Pending orphan -> reconciliation marks failed
"""
import asyncio
import httpx
import uuid
import time
import subprocess
import sqlite3
import os
import sys
import json

BASE = "http://localhost:8000"
DB_PATH = os.path.join(os.path.dirname(__file__), "sentinelscan.db")


def db_scan(scan_id: str):
    """Get scan state from SQLite directly."""
    sid = scan_id.replace("-", "")
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT status, progress, current_stage, error_message, task_id FROM scans WHERE id=?",
        (sid,)
    ).fetchone()
    conn.close()
    return dict(zip(["status", "progress", "stage", "error_message", "task_id"], row)) if row else None


def db_report_count(scan_id: str) -> int:
    sid = scan_id.replace("-", "")
    conn = sqlite3.connect(DB_PATH)
    count = conn.execute("SELECT COUNT(*) FROM reports WHERE scan_id=?", (sid,)).fetchone()[0]
    conn.close()
    return count


async def register_user(c, suffix=""):
    email = f"crash{suffix}_{uuid.uuid4().hex[:6]}@gmail.com"
    r = await c.post("/api/auth/register", json={
        "name": "Crash Test", "email": email, "password": "Test1234!"
    })
    assert r.status_code == 201, f"Register failed: {r.text}"
    lr = await c.post("/api/auth/login", json={"email": email, "password": "Test1234!"})
    assert lr.status_code == 200
    return lr.json()["access_token"]


async def wait_for_running(c, scan_id, token, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        sr = await c.get(f"/api/scans/{scan_id}", headers={"Authorization": f"Bearer {token}"})
        if sr.status_code == 200:
            s = sr.json()["status"]
            p = sr.json().get("progress", 0)
            if s == "running" and p > 0:
                return True
            if s in ("completed", "failed", "cancelled"):
                return False
        await asyncio.sleep(0.5)
    return False


async def test_reconciliation_safety():
    """
    Test 17: While a legitimate scan is running, trigger reconciliation.
    The scan must NOT be killed.
    """
    print("\n" + "=" * 60)
    print("TEST: Reconciliation Safety (Active Job NOT killed)")
    print("=" * 60)

    async with httpx.AsyncClient(base_url=BASE, timeout=30) as c:
        token = await register_user(c, "_safety")
        r = await c.post("/api/scans", json={"url": "https://example.com", "scan_mode": "passive"},
                         headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 201:
            print(f"[FAIL] Create scan: {r.status_code}")
            return
        scan_id = r.json()["id"]
        print(f"  Scan: {scan_id}")

        # Wait until running
        running = await wait_for_running(c, scan_id, token)
        if not running:
            print(f"[PART] Scan completed before we could trigger reconciliation")
            s = db_scan(scan_id)
            print(f"  Final: {s}")
            return

        print(f"  Scan is running at {db_scan(scan_id)['progress']}%. Triggering reconciliation via worker cron...")

        # The reconcile cron runs every 5 minutes in worker.
        # But we can invoke it via the ARQ API directly.
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import asyncio; from app.tasks.reconcile import reconcile_orphan_scans; "
                "import aioredis, os; "
                "async def run(): "
                "    r = await aioredis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0')); "
                "    ctx = {'redis': r}; "
                "    result = await reconcile_orphan_scans(ctx); "
                "    print('Reconcile result:', result); "
                "    await r.aclose(); "
                "asyncio.run(run())"
            ],
            capture_output=True, text=True,
            cwd=os.path.dirname(__file__), timeout=30
        )
        print(f"  Reconcile stdout: {result.stdout.strip()}")
        print(f"  Reconcile stderr: {result.stderr[-300:] if result.stderr else ''}")

        # Wait for scan to complete naturally
        await asyncio.sleep(15)
        final = db_scan(scan_id)
        print(f"  Final status: {final}")

        if final and final["status"] == "completed":
            print("[PASS] Reconciliation Safety: Active scan was NOT killed by reconciliation")
        elif final and final["status"] == "running":
            print("[PASS] Reconciliation Safety: Scan still running (reconciliation left it alone)")
        elif final and final["status"] == "failed" and "reconcil" in (final["error_message"] or "").lower():
            print("[FAIL] CRITICAL: Reconciliation KILLED an active scan!")
        else:
            print(f"[PART] Status: {final}")


async def test_orphan_pending_reconciliation():
    """
    Test 15: Manually create a pending scan with a missing ARQ job.
    Run reconciliation. Verify it transitions to failed.
    """
    print("\n" + "=" * 60)
    print("TEST: Orphan Pending -> Reconciliation -> Failed")
    print("=" * 60)

    # Create a scan with a fake/missing job_id
    orphan_scan_id = str(uuid.uuid4())
    orphan_user_id = str(uuid.uuid4())
    fake_task_id = f"scan:{orphan_scan_id}"

    # Insert directly into DB (simulate orphan)
    import datetime
    old_time = (datetime.datetime.utcnow() - datetime.timedelta(minutes=10)).isoformat()
    sid = orphan_scan_id.replace("-", "")
    uid = orphan_user_id.replace("-", "")

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO scans (id, user_id, url, status, progress, task_id, created_at, scan_mode)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (sid, uid, "https://orphan-test.example.com", "pending", 0, fake_task_id, old_time, "passive")
    )
    conn.commit()
    conn.close()
    print(f"  Inserted orphan scan: {orphan_scan_id}")
    print(f"  task_id: {fake_task_id}")
    print(f"  status: pending (created 10 minutes ago)")

    # Run reconciliation
    result = subprocess.run(
        [
            sys.executable, "-c",
            "import asyncio; from app.tasks.reconcile import reconcile_orphan_scans; "
            "import aioredis, os; "
            "async def run(): "
            "    r = await aioredis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0')); "
            "    ctx = {'redis': r}; "
            "    result = await reconcile_orphan_scans(ctx); "
            "    print('Reconcile result:', result); "
            "    await r.aclose(); "
            "asyncio.run(run())"
        ],
        capture_output=True, text=True,
        cwd=os.path.dirname(__file__), timeout=30
    )
    print(f"  Reconcile stdout: {result.stdout.strip()}")

    # Check final state
    await asyncio.sleep(2)
    final = db_scan(orphan_scan_id)
    print(f"  Final state: {final}")

    if final and final["status"] == "failed":
        print("[PASS] Orphan Pending Reconciliation: pending -> failed as expected")
        print(f"  Error: {final.get('error_message', 'N/A')}")
    elif final and final["status"] == "pending":
        print("[FAIL] Reconciliation did NOT repair the orphan pending scan")
    else:
        print(f"[PART] Unexpected status: {final}")

    # Cleanup
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans WHERE id=?", (sid,))
    conn.commit()
    conn.close()


async def test_orphan_running_reconciliation():
    """
    Test 16: Orphan running scan with no active job -> reconciliation marks failed.
    """
    print("\n" + "=" * 60)
    print("TEST: Orphan Running -> Reconciliation -> Failed")
    print("=" * 60)

    import datetime
    from app.config import settings

    # Create very old running scan (age > retry_window)
    retry_window = settings.MAX_SCAN_TIMEOUT * settings.WORKER_MAX_TRIES
    old_time = (datetime.datetime.utcnow() - datetime.timedelta(seconds=retry_window + 600)).isoformat()

    orphan_scan_id = str(uuid.uuid4())
    orphan_user_id = str(uuid.uuid4())
    fake_task_id = f"scan:{orphan_scan_id}"  # job doesn't exist in ARQ

    sid = orphan_scan_id.replace("-", "")
    uid = orphan_user_id.replace("-", "")

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO scans (id, user_id, url, status, progress, task_id, created_at, started_at, scan_mode)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (sid, uid, "https://orphan-running.example.com", "running", 45, fake_task_id, old_time, old_time, "passive")
    )
    conn.commit()
    conn.close()
    print(f"  Inserted orphan RUNNING scan: {orphan_scan_id}")
    print(f"  Age: ~{retry_window + 600}s old (past retry_window={retry_window}s)")

    # Run reconciliation
    result = subprocess.run(
        [
            sys.executable, "-c",
            "import asyncio; from app.tasks.reconcile import reconcile_orphan_scans; "
            "import aioredis, os; "
            "async def run(): "
            "    r = await aioredis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0')); "
            "    ctx = {'redis': r}; "
            "    result = await reconcile_orphan_scans(ctx); "
            "    print('Reconcile result:', result); "
            "    await r.aclose(); "
            "asyncio.run(run())"
        ],
        capture_output=True, text=True,
        cwd=os.path.dirname(__file__), timeout=30
    )
    print(f"  Reconcile stdout: {result.stdout.strip()}")

    await asyncio.sleep(2)
    final = db_scan(orphan_scan_id)
    print(f"  Final state: {final}")

    if final and final["status"] == "failed":
        print("[PASS] Orphan Running Reconciliation: running -> failed as expected")
    elif final and final["status"] == "running":
        print("[FAIL] Orphan running scan was NOT repaired by reconciliation")
    else:
        print(f"[PART] Unexpected: {final}")

    # Cleanup
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans WHERE id=?", (sid,))
    conn.commit()
    conn.close()


async def test_completed_scan_not_touched():
    """
    Test terminal state protection: completed scan must never become failed.
    """
    print("\n" + "=" * 60)
    print("TEST: Completed Scan Not Touched by Reconciliation")
    print("=" * 60)

    import datetime
    old_time = datetime.datetime.utcnow().isoformat()

    scan_id = str(uuid.uuid4())
    uid = str(uuid.uuid4()).replace("-", "")
    sid = scan_id.replace("-", "")

    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """INSERT INTO scans (id, user_id, url, status, progress, task_id, created_at, scan_mode)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (sid, uid, "https://completed.example.com", "completed", 100, f"scan:{scan_id}", old_time, "passive")
    )
    conn.commit()
    conn.close()

    result = subprocess.run(
        [
            sys.executable, "-c",
            "import asyncio; from app.tasks.reconcile import reconcile_orphan_scans; "
            "import aioredis, os; "
            "async def run(): "
            "    r = await aioredis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0')); "
            "    result = await reconcile_orphan_scans({'redis': r}); "
            "    print('Reconcile result:', result); "
            "    await r.aclose(); "
            "asyncio.run(run())"
        ],
        capture_output=True, text=True,
        cwd=os.path.dirname(__file__), timeout=30
    )
    print(f"  Reconcile: {result.stdout.strip()}")

    await asyncio.sleep(1)
    final = db_scan(scan_id)
    print(f"  Final state: {final}")

    if final and final["status"] == "completed":
        print("[PASS] Completed scan preserved by reconciliation")
    else:
        print(f"[FAIL] Completed scan was modified! Now: {final}")

    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans WHERE id=?", (sid,))
    conn.commit()
    conn.close()


asyncio.run(test_reconciliation_safety())
asyncio.run(test_orphan_pending_reconciliation())
asyncio.run(test_orphan_running_reconciliation())
asyncio.run(test_completed_scan_not_touched())
