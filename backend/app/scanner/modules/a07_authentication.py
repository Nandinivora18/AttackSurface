"""
OWASP A07:2025 — Authentication Failures Assessment Module
==========================================================
Evaluates authentication mechanisms, session token cookie protection, login interface
transport security, and observable rate-limiting controls.

Safety Invariants:
- Zero credential brute forcing, dictionary attacks, or automated login guessing.
- Zero account lockout provocation.
- Passive inspection of discovered forms, session cookies, and login transport security.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)

# Common session identifier cookie names
SESSION_COOKIE_NAMES = {
    "session", "sessionid", "phpsessid", "jsessionid", "aspsessionid",
    "connect.sid", "laravel_session", "remember_token", "jwt", "auth_token",
    "access_token", "token", "sid", "user_session",
}

LOGIN_URL_PATTERNS = re.compile(r'/(login|signin|auth|account/login|user/login|admin/login)', re.IGNORECASE)


def _parse_cookie_attributes(raw_cookie: str) -> dict[str, Any]:
    """Parses a Set-Cookie header string into name, value, and attributes."""
    parts = [p.strip() for p in raw_cookie.split(";")]
    if not parts:
        return {}
    
    first = parts[0]
    eq_idx = first.find("=")
    if eq_idx != -1:
        name = first[:eq_idx].strip()
        val = first[eq_idx + 1:].strip()
    else:
        name = first
        val = ""

    attrs = {
        "name": name,
        "value": val,
        "secure": False,
        "httponly": False,
        "samesite": None,
        "raw": raw_cookie,
    }

    for part in parts[1:]:
        lower_p = part.lower()
        if lower_p == "secure":
            attrs["secure"] = True
        elif lower_p == "httponly":
            attrs["httponly"] = True
        elif lower_p.startswith("samesite="):
            attrs["samesite"] = part.split("=", 1)[1].strip()

    return attrs


async def assess_a07_authentication(
    target_url: str,
    raw_cookies: list[str] | list[dict[str, Any]],
    discovered_urls: list[str],
    crawled_forms: list[dict[str, Any]] | None = None,
    response_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Executes A07 Identification and Authentication Failures assessment.
    """
    findings: list[dict[str, Any]] = []
    status = "PASS"
    confidence = "HIGH"

    crawled_forms = crawled_forms or []
    response_headers = response_headers or {}
    is_target_https = target_url.lower().startswith("https://")

    # 1. Evaluate Session Cookie Security Flags
    parsed_cookies: list[dict[str, Any]] = []
    for c in raw_cookies:
        if isinstance(c, str):
            parsed_cookies.append(_parse_cookie_attributes(c))
        elif isinstance(c, dict):
            parsed_cookies.append({
                "name": c.get("name", ""),
                "value": c.get("value", ""),
                "secure": c.get("secure", False),
                "httponly": c.get("httponly", False),
                "samesite": c.get("samesite"),
                "raw": str(c),
            })

    for cookie in parsed_cookies:
        name = cookie.get("name", "")
        is_session = name.lower() in SESSION_COOKIE_NAMES or any(s in name.lower() for s in ["sess", "auth", "token"])
        
        # Missing HttpOnly on session cookie
        if is_session and not cookie.get("httponly"):
            status = "FAIL"
            findings.append({
                "category": "Session Management",
                "title": f"Session Cookie Missing HttpOnly Flag: {name}",
                "description": (
                    f"The cookie '{name}' appears to hold session state but lacks the 'HttpOnly' flag. "
                    "Scripts running in the browser can access this cookie via document.cookie, "
                    "enabling session hijacking if a Cross-Site Scripting (XSS) vulnerability exists."
                ),
                "severity": "medium",
                "confidence": "high",
                "cvss_score": 5.4,
                "recommendation": f"Add the 'HttpOnly' directive to the Set-Cookie header for '{name}'.",
                "references": [
                    "https://owasp.org/www-community/HttpOnly",
                    "https://owasp.org/Top10/A07_2025-Authentication_Failures/",
                ],
                "endpoint": target_url,
                "evidence": f"Set-Cookie: {cookie.get('raw', name)}",
            })

        # Missing Secure flag over HTTPS
        if is_target_https and not cookie.get("secure"):
            status = "FAIL"
            severity = "medium" if is_session else "low"
            findings.append({
                "category": "Session Management",
                "title": f"Cookie Missing Secure Flag over HTTPS: {name}",
                "description": (
                    f"The cookie '{name}' was set over HTTPS without the 'Secure' flag. "
                    "Browsers may transmit this cookie over unencrypted HTTP requests, allowing "
                    "interception on untrusted networks."
                ),
                "severity": severity,
                "confidence": "high",
                "cvss_score": 4.3 if is_session else None,
                "recommendation": f"Set the 'Secure' attribute on cookie '{name}'.",
                "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"],
                "endpoint": target_url,
                "evidence": f"Set-Cookie: {cookie.get('raw', name)}",
            })

        # Missing SameSite attribute
        samesite = cookie.get("samesite")
        if not samesite:
            findings.append({
                "category": "Session Management",
                "title": f"Cookie Missing SameSite Attribute: {name}",
                "description": (
                    f"The cookie '{name}' does not specify a SameSite attribute (Lax or Strict). "
                    "Without explicit SameSite configuration, modern browsers apply default behavior, "
                    "which may leave endpoints exposed to Cross-Site Request Forgery (CSRF)."
                ),
                "severity": "low",
                "confidence": "high",
                "cvss_score": None,
                "recommendation": f"Configure 'SameSite=Lax' or 'SameSite=Strict' for cookie '{name}'.",
                "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                "endpoint": target_url,
                "evidence": f"Set-Cookie: {cookie.get('raw', name)}",
            })

    # 2. Login Endpoint Discovery and Transport Security
    login_endpoints: list[str] = []
    for u in discovered_urls:
        if LOGIN_URL_PATTERNS.search(u):
            login_endpoints.append(u)

    for ep in login_endpoints:
        if ep.lower().startswith("http://"):
            status = "FAIL"
            findings.append({
                "category": "Authentication Transport",
                "title": f"Unencrypted Login Endpoint Discovered: {ep}",
                "description": (
                    f"The authentication endpoint '{ep}' is accessible over unencrypted HTTP. "
                    "User credentials entered on this page can be intercepted in transit via plaintext sniffing."
                ),
                "severity": "high",
                "confidence": "confirmed",
                "cvss_score": 7.4,
                "recommendation": "Enforce HTTPS redirect and strict transport security across all authentication endpoints.",
                "references": ["https://owasp.org/Top10/A07_2025-Authentication_Failures/"],
                "endpoint": ep,
                "evidence": f"Plain HTTP login URL: {ep}",
            })

    # 3. Analyze Crawled Login Forms
    for form in crawled_forms:
        inputs = [i.lower() for i in form.get("inputs", [])]
        action = form.get("action", "")
        # Identify login form by password or username input
        if any("pass" in inp or "pwd" in inp for inp in inputs):
            if action.lower().startswith("http://"):
                status = "FAIL"
                findings.append({
                    "category": "Authentication Transport",
                    "title": "Login Form Submits Credentials Over Insecure Plain HTTP",
                    "description": (
                        f"A login form on {form.get('source_page')} submits credential fields {inputs} "
                        f"to an insecure plain HTTP action ({action})."
                    ),
                    "severity": "critical",
                    "confidence": "confirmed",
                    "cvss_score": 8.1,
                    "recommendation": "Ensure form action attributes point exclusively to HTTPS endpoints.",
                    "references": ["https://owasp.org/Top10/A07_2025-Authentication_Failures/"],
                    "endpoint": form.get("source_page", target_url),
                    "evidence": f"Form action: {action}, Inputs: {', '.join(inputs)}",
                })

    # 4. Observable Rate-Limiting Indicators
    rate_limit_headers = [h for h in response_headers.keys() if "ratelimit" in h.lower() or h.lower() == "retry-after"]
    if rate_limit_headers:
        logger.debug(f"A07 Rate-limiting header indicators observed: {rate_limit_headers}")

    limitations = (
        "Evaluates cookie security attributes (HttpOnly, Secure, SameSite), login endpoint transport security, "
        "and form submission destinations. Does not execute credential stuffing, password spraying, or account lockout attacks."
    )

    return {
        "status": status,
        "method": "Passive Session Security, Login Transport & Cookie Attribute Analysis",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
