"""Test migration chain against a fresh SQLite database."""
import os
import sys
import subprocess
import sqlite3

BASE = os.path.dirname(os.path.abspath(__file__))
TEMP_DB = os.path.join(BASE, "test_migration_temp.db")

# Clean up any previous run
if os.path.exists(TEMP_DB):
    os.remove(TEMP_DB)

env = os.environ.copy()
env["SYNC_DATABASE_URL"] = f"sqlite:///{TEMP_DB}"

print("Running: alembic upgrade head (SQLite)")
result = subprocess.run(
    [sys.executable, "-m", "alembic", "upgrade", "head"],
    capture_output=True,
    text=True,
    env=env,
    cwd=BASE,
)
print(f"Return code: {result.returncode}")
if result.stdout:
    print(f"STDOUT: {result.stdout[:3000]}")
if result.stderr:
    print(f"STDERR: {result.stderr[:1000]}")

if result.returncode != 0:
    print("[FAIL] Migration failed!")
    sys.exit(1)

print("\n[PASS] Migration chain applied successfully to fresh SQLite DB.")

# Inspect the resulting schema
conn = sqlite3.connect(TEMP_DB)

tables = [
    r[0] for r in
    conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
]
print(f"\nTables created ({len(tables)}): {tables}")

# Required tables (active schema: 6 core tables + audit_logs)
required_tables = ["users", "scans", "reports", "findings", "notifications", "audit_logs"]
failures = []
for t in required_tables:
    status = "PASS" if t in tables else "FAIL"
    if status == "FAIL":
        failures.append(f"Table {t} missing")
    print(f"  [{status}] {t}")

# Check scans columns
print("\nscans columns:")
scans_cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
print(f"  {scans_cols}")
required_scan_cols = [
    "id", "user_id", "url", "status", "progress", "current_stage",
    "error_message", "cancellation_reason", "started_at",
    "completed_at", "scan_mode", "scope_config", "timeline", "created_at", "task_id"
]
for col in required_scan_cols:
    status = "PASS" if col in scans_cols else "FAIL"
    if status == "FAIL":
        failures.append(f"Scan col {col} missing")
    print(f"  [{status}] {col}")

# Check reports columns
print("\nreports columns:")
reports_cols = [r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()]
print(f"  {reports_cols}")
required_report_cols = [
    "id", "scan_id", "user_id", "overall_score", "grade", "risk_level",
    "summary", "tech_stack", "raw_headers", "ssl_info", "dns_info",
    "score_breakdown", "scan_mode", "executive_summary", "timeline", "created_at"
]
for col in required_report_cols:
    status = "PASS" if col in reports_cols else "FAIL"
    if status == "FAIL":
        failures.append(f"Report col {col} missing")
    print(f"  [{status}] {col}")

# Check users columns
print("\nusers columns:")
users_cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
print(f"  {users_cols}")
required_user_cols = [
    "id", "email", "name", "password_hash", "is_verified",
    "email_verification_token", "email_verification_expires",
    "created_at"
]
for col in required_user_cols:
    status = "PASS" if col in users_cols else "FAIL"
    if status == "FAIL":
        failures.append(f"User col {col} missing")
    print(f"  [{status}] {col}")

conn.close()

# Clean up
os.remove(TEMP_DB)
print("\n[OK] Temp DB cleaned up.")

if failures:
    print(f"\n[FAIL] Migration checks failed: {failures}")
    sys.exit(1)

print("\n[PASS] All migration checks complete.")
