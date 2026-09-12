"""Run brand new verification scan for goclasses.in and inspect findings."""
import asyncio
import httpx
import json

async def run_verification_scan():
    async with httpx.AsyncClient(base_url="http://localhost:8000", timeout=30) as c:
        # 1. Login
        r_login = await c.post("/api/auth/login", json={"email": "nandinivora245@gmail.com", "password": "Password123!"})
        print(f"Login: {r_login.status_code}")
        token = r_login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Create scan
        print("\nCreating new scan for https://www.goclasses.in/ ...")
        r_scan = await c.post("/api/scans", json={"url": "https://www.goclasses.in/"}, headers=headers)
        print(f"Create Scan Status: {r_scan.status_code}")
        scan_data = r_scan.json()
        scan_id = scan_data["id"]
        print(f"New Scan ID: {scan_id}")

        # 3. Poll status until completed
        for attempt in range(60):
            await asyncio.sleep(2)
            r_status = await c.get(f"/api/scans/{scan_id}", headers=headers)
            status_data = r_status.json()
            status = status_data["status"]
            progress = status_data["progress"]
            stage = status_data["current_stage"]
            print(f"  Attempt {attempt+1}: status={status} | progress={progress}% | stage={stage}")

            if status in ("completed", "failed", "cancelled"):
                break

        if status != "completed":
            print(f"[FAIL] Scan did not complete cleanly: {status}")
            return

        # 4. Fetch the report
        print("\nFetching Report...")
        r_rep = await c.get(f"/api/scans/{scan_id}/report", headers=headers)
        print(f"Report Status: {r_rep.status_code}")
        report = r_rep.json()
        print(f"Report ID: {report['id']}")
        print(f"Overall Score: {report['overall_score']}/100 (Grade: {report['grade']}) | Risk: {report['risk_level']}")

        findings = report.get("findings", [])
        print(f"\nTotal Findings in New Scan: {len(findings)}")

        exposed_file_findings = [
            f for f in findings if any(kw in f["title"] for kw in ["Exposed", "Config", "Backup", "Admin", "Swagger", "phpinfo"])
        ]
        print(f"\nExposed File / Admin Findings ({len(exposed_file_findings)}):")
        for f in exposed_file_findings:
            print(f"  - [{f['severity'].upper()}] {f['title']} (Confidence: {f.get('confidence', 'N/A')})")
            print(f"    Evidence: {f.get('evidence', '')[:140]}...")

asyncio.run(run_verification_scan())
