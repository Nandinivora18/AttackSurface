"""
Runtime tests for orphan reconciliation.
Tests 15, 16, 17 from the Phase 4 acceptance matrix.
"""
import asyncio
import sqlite3
import uuid
import os
import sys
import subprocess
import time
import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "sentinelscan.db")
SCRIPT_DIR = os.path.dirname(__file__)


def db_scan(scan_id: str):
    sid = scan_id.replace("-", "")
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT status, error_message FROM scans WHERE id=?", (sid,)
    ).fetchone()
    conn.close()
    return {"status": row[0], "error": row[1]} if row else None


def insert_orphan_scan(scan_id: str, status: str, age_seconds: int = 660):
    uid = uuid.uuid4().hex
    sid = scan_id.replace("-", "")
    task_id = f"scan:{scan_id}"
    old_time = (
        datetime.datetime.now(datetime.timezone.utc) -
        datetime.timedelta(seconds=age_seconds)
    ).isoformat()
    progress = 0 if status == "pending" else 45
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        INSERT INTO scans (id, user_id, url, status, progress, task_id, created_at, scan_mode)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (sid, uid, "https://orphan-test.example.com", status, progress, task_id, old_time, "passive"))
    conn.commit()
    conn.close()


def run_reconcile():
    result = subprocess.run(
        [sys.executable, "run_reconcile.py"],
        capture_output=True, text=True,
        cwd=SCRIPT_DIR
    )
    return result.stdout.strip()


def cleanup(scan_id: str):
    sid = scan_id.replace("-", "")
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM scans WHERE id=?", (sid,))
    conn.commit()
    conn.close()


# === TEST 15: Orphan Pending -> Reconciliation -> Failed ===
print("=" * 60)
print("TEST 15: Orphan Pending -> Failed")
print("=" * 60)
sid_pending = str(uuid.uuid4())
insert_orphan_scan(sid_pending, "pending", age_seconds=660)
print(f"  Inserted orphan pending: {sid_pending}")
print(f"  Before: {db_scan(sid_pending)}")

reconcile_out = run_reconcile()
print(f"  Reconcile: {reconcile_out}")
time.sleep(2)
final = db_scan(sid_pending)
print(f"  After: {final}")

if final and final["status"] == "failed":
    print("[PASS] Orphan Pending Reconciliation: pending -> failed")
else:
    print(f"[FAIL] Still: {final}")

cleanup(sid_pending)


# === TEST 16: Orphan Running -> Reconciliation -> Failed ===
print()
print("=" * 60)
print("TEST 16: Orphan Running -> Failed")
print("=" * 60)
sid_running = str(uuid.uuid4())
# retry_window = MAX_SCAN_TIMEOUT * WORKER_MAX_TRIES = 600*3 = 1800s
# Must be older than 1800s (30 min)
insert_orphan_scan(sid_running, "running", age_seconds=2400)
print(f"  Inserted orphan running: {sid_running}")
print(f"  Age: 2400s > retry_window=1800s")
print(f"  Before: {db_scan(sid_running)}")

reconcile_out = run_reconcile()
print(f"  Reconcile: {reconcile_out}")
time.sleep(2)
final = db_scan(sid_running)
print(f"  After: {final}")

if final and final["status"] == "failed":
    print("[PASS] Orphan Running Reconciliation: running -> failed")
else:
    print(f"[FAIL] Still: {final}")

cleanup(sid_running)


# === TEST 17: Completed Scan Protected from Reconciliation ===
print()
print("=" * 60)
print("TEST 17: Completed Scan Preserved")
print("=" * 60)
sid_completed = str(uuid.uuid4())
uid2 = uuid.uuid4().hex
sid2 = sid_completed.replace("-", "")
conn = sqlite3.connect(DB_PATH)
conn.execute("""
    INSERT INTO scans (id, user_id, url, status, progress, task_id, created_at, scan_mode)
    VALUES (?, ?, ?, 'completed', 100, ?, ?, 'passive')
""", (sid2, uid2, "https://completed.example.com", f"scan:{sid_completed}",
      datetime.datetime.now().isoformat()))
conn.commit()
conn.close()
print(f"  Inserted completed scan: {sid_completed}")

reconcile_out = run_reconcile()
print(f"  Reconcile: {reconcile_out}")
time.sleep(1)
final = db_scan(sid_completed)
print(f"  After: {final}")

if final and final["status"] == "completed":
    print("[PASS] Completed scan preserved - reconciliation left it alone")
else:
    print(f"[FAIL] Completed scan was modified: {final}")

cleanup(sid_completed)


# === TEST: Cancelled Scan Protected ===
print()
print("=" * 60)
print("TEST: Cancelled Scan Preserved")
print("=" * 60)
sid_cancelled = str(uuid.uuid4())
uid3 = uuid.uuid4().hex
sid3 = sid_cancelled.replace("-", "")
conn = sqlite3.connect(DB_PATH)
conn.execute("""
    INSERT INTO scans (id, user_id, url, status, progress, task_id, created_at, scan_mode, is_favourite)
    VALUES (?, ?, ?, 'cancelled', 30, ?, ?, 'passive', 0)
""".replace("is_favourite", "is_favorite"),
    (sid3, uid3, "https://cancelled.example.com", f"scan:{sid_cancelled}",
     datetime.datetime.now().isoformat()))
conn.commit()
conn.close()

reconcile_out = run_reconcile()
print(f"  Reconcile: {reconcile_out}")
time.sleep(1)
final = db_scan(sid_cancelled)
print(f"  After: {final}")

if final and final["status"] == "cancelled":
    print("[PASS] Cancelled scan preserved - reconciliation left it alone")
else:
    print(f"[FAIL] Cancelled scan was modified: {final}")

cleanup(sid_cancelled)

print("\nAll orphan reconciliation tests complete.")
