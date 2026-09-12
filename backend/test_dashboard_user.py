"""Test dashboard API calls for user nandinivora245@gmail.com."""
import asyncio
import httpx
import json

async def test_dashboard_api():
    async with httpx.AsyncClient(base_url="http://localhost:8000", timeout=10) as c:
        # Try login with password or reset password if needed
        # Check login for user
        r_login = await c.post("/api/auth/login", json={"email": "nandinivora245@gmail.com", "password": "Password123!"})
        print(f"Login status: {r_login.status_code}")
        if r_login.status_code != 200:
            print("Login response:", r_login.text)
            return

        token = r_login.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        endpoints = [
            "/api/scans?limit=10",
            "/api/reports?limit=20",
            "/api/reports/dashboard_stats",
        ]

        for ep in endpoints:
            print(f"\n--- GET {ep} ---")
            res = await c.get(ep, headers=headers)
            print(f"Status: {res.status_code}")
            if res.status_code == 200:
                data = res.json()
                print(f"Data type: {type(data)}")
                if isinstance(data, list):
                    print(f"List length: {len(data)}")
                    if data:
                        print("Sample item keys:", list(data[0].keys()))
                elif isinstance(data, dict):
                    print("Dict keys:", list(data.keys()))
                    print("Content preview:", json.dumps(data, indent=2)[:500])
            else:
                print(f"Error: {res.text}")

asyncio.run(test_dashboard_api())
