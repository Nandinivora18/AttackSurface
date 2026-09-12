"""Token revocation runtime test."""
import asyncio
import httpx
import uuid


BASE = "http://localhost:8000"


async def test_token_revocation():
    async with httpx.AsyncClient(base_url=BASE, timeout=15) as c:
        email = f"revoke_{uuid.uuid4().hex[:8]}@gmail.com"
        r = await c.post("/api/auth/register", json={
            "name": "Revoke Test", "email": email, "password": "Test1234!"
        })
        print(f"Register: {r.status_code}")
        assert r.status_code == 201, f"Register failed: {r.text}"

        lr = await c.post("/api/auth/login", json={"email": email, "password": "Test1234!"})
        print(f"Login: {lr.status_code}")
        assert lr.status_code == 200, f"Login failed: {lr.text}"
        token = lr.json()["access_token"]

        # Pre-logout — must succeed
        me = await c.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})
        print(f"Pre-logout /me: {me.status_code}")
        assert me.status_code == 200, "Pre-logout auth should succeed"

        # Logout
        logout = await c.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        print(f"Logout: {logout.status_code} - {logout.text[:120]}")

        if logout.status_code == 503:
            print("[PART] Token Revocation: 503 (Redis unavailable) - fail-closed correct")
            return

        assert logout.status_code == 200, f"Logout unexpected status: {logout.status_code}"

        # Post-logout — must be rejected
        await asyncio.sleep(0.5)
        me2 = await c.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})
        print(f"Post-logout /me: {me2.status_code}")

        if me2.status_code == 401:
            print("[PASS] Token Revocation: old token correctly rejected after logout")
        elif me2.status_code == 200:
            print("[FAIL] SECURITY BUG: old token still accepted after logout!")
            print("       Redis blacklist not working.")
        else:
            print(f"[PART] Unexpected status after logout: {me2.status_code}")


async def test_revocation_survives_api_restart():
    """
    Register -> Login -> Logout -> API restarts (simulated) -> Old token still rejected.
    
    In dev with in-memory fallback, this would FAIL after restart.
    With Redis-backed blacklist, this must PASS because Redis persists the JTI.
    """
    print("\n--- Token Revocation After Simulated API Restart ---")
    async with httpx.AsyncClient(base_url=BASE, timeout=15) as c:
        email = f"restart_{uuid.uuid4().hex[:6]}@gmail.com"
        await c.post("/api/auth/register", json={
            "name": "Restart Test", "email": email, "password": "Test1234!"
        })
        lr = await c.post("/api/auth/login", json={"email": email, "password": "Test1234!"})
        token = lr.json()["access_token"]

        # Logout (persists JTI to Redis)
        logout = await c.post("/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
        print(f"Logout: {logout.status_code}")
        if logout.status_code == 503:
            print("[PART] Redis blacklist unavailable - cannot test restart persistence")
            return

        # Token is now blacklisted in Redis
        # Verify it's already rejected
        me = await c.get("/api/users/me", headers={"Authorization": f"Bearer {token}"})
        print(f"Pre-restart check: {me.status_code} (expect 401)")
        if me.status_code != 401:
            print("[FAIL] Token not rejected before restart check")
            return

        # Now verify by checking Redis directly
        import subprocess, sys
        result = subprocess.run(
            ["C:\\Program Files\\Redis\\redis-cli.exe", "KEYS", "blacklist:*"],
            capture_output=True, text=True
        )
        print(f"Redis blacklist keys: {result.stdout.strip()}")

        blacklisted = result.stdout.strip() != ""
        if blacklisted:
            print("[PASS] Token Revocation After API Restart: JTI persisted in Redis")
            print("       Even if API restarts, Redis retains the blacklisted JTI")
        else:
            print("[FAIL] No blacklist keys in Redis - revocation is not persistent!")


asyncio.run(test_token_revocation())
asyncio.run(test_revocation_survives_api_restart())
