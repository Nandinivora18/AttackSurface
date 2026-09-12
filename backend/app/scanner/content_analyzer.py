"""
Content Analyzer
================
Fetches and parses sitemap.xml, sensitive HTML comments, and probes for exposed sensitive files
using soft-404 baseline detection and strict content validation.
"""
import re
import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import Any
import logging
from difflib import SequenceMatcher

from app.utils.safe_http import SafeFetchClient

logger = logging.getLogger(__name__)

# Sensitive files to probe
SENSITIVE_PATHS = [
    # Git/VCS exposure
    {"path": "/.git/HEAD", "severity": "critical", "title": "Exposed Git Repository",
     "description": "The .git directory is publicly accessible. Attackers can reconstruct the full source code.",
     "cvss": 9.8, "category": "Source Code Exposure",
     "rec": "Configure your web server to deny access to /.git/ directory"},

    # Environment files
    {"path": "/.env", "severity": "critical", "title": "Exposed .env File",
     "description": ".env file is publicly accessible and contains sensitive environment variables.",
     "cvss": 9.8, "category": "Credential Exposure",
     "rec": "Move .env outside the web root or block access via web server configuration"},

    {"path": "/.env.production", "severity": "critical", "title": "Exposed .env.production File",
     "description": "Production environment file is publicly accessible.",
     "cvss": 9.8, "category": "Credential Exposure",
     "rec": "Block access to all .env files via web server rules"},

    # Config files
    {"path": "/config.php", "severity": "high", "title": "Exposed config.php Source Code",
     "description": "Unparsed PHP configuration file is accessible as plain text.",
     "cvss": 7.5, "category": "Credential Exposure",
     "rec": "Ensure PHP files are executed by the interpreter, not served as plain text"},

    {"path": "/wp-config.php.bak", "severity": "critical", "title": "Exposed WordPress config backup",
     "description": "WordPress configuration backup file containing database credentials is publicly accessible.",
     "cvss": 9.8, "category": "Credential Exposure",
     "rec": "Remove backup files from web root immediately"},

    # Backup files
    {"path": "/backup.zip", "severity": "high", "title": "Exposed backup archive",
     "description": "A backup archive is publicly downloadable.", "cvss": 7.5,
     "category": "Data Exposure", "rec": "Remove backup files from web root"},

    {"path": "/backup.sql", "severity": "critical", "title": "Exposed SQL dump",
     "description": "A SQL database dump is publicly accessible.",
     "cvss": 9.8, "category": "Data Exposure",
     "rec": "Remove SQL dump files from web root immediately"},

    # API docs
    {"path": "/swagger.json", "severity": "medium", "title": "Exposed Swagger/OpenAPI Spec",
     "description": "API documentation JSON specification is publicly accessible.",
     "cvss": 5.3, "category": "Information Disclosure",
     "rec": "Restrict Swagger/OpenAPI docs to authenticated users in production"},

    {"path": "/swagger-ui.html", "severity": "medium", "title": "Exposed Swagger UI",
     "description": "Swagger UI interactive API documentation is publicly accessible.", "cvss": 5.3,
     "category": "Information Disclosure", "rec": "Restrict Swagger UI to authenticated internal users"},

    {"path": "/api/docs", "severity": "medium", "title": "Exposed API Documentation",
     "description": "API docs endpoint accessible without authentication.", "cvss": 5.3,
     "category": "Information Disclosure", "rec": "Require authentication for API documentation in production"},

    # Admin panels
    {"path": "/admin", "severity": "medium", "title": "Admin Panel Exposed",
     "description": "An administrative login interface was found at /admin.",
     "cvss": 5.3, "category": "Admin Exposure",
     "rec": "Restrict admin panel access by IP and ensure strong authentication"},

    {"path": "/wp-admin/", "severity": "medium", "title": "WordPress Admin Panel Exposed",
     "description": "WordPress admin login page is publicly accessible.",
     "cvss": 5.3, "category": "Admin Exposure",
     "rec": "Consider restricting wp-admin access by IP or adding a secondary auth layer"},

    {"path": "/phpmyadmin/", "severity": "high", "title": "phpMyAdmin Exposed",
     "description": "phpMyAdmin database management interface is publicly accessible.",
     "cvss": 8.8, "category": "Admin Exposure",
     "rec": "Restrict phpMyAdmin access by IP whitelist or move off public-facing server"},

    # Debug/diagnostic
    {"path": "/phpinfo.php", "severity": "high", "title": "PHP Info Page Exposed",
     "description": "phpinfo() page is publicly accessible, revealing PHP configuration, loaded modules, and server paths.",
     "cvss": 7.5, "category": "Information Disclosure",
     "rec": "Remove phpinfo() pages from production servers immediately"},

    {"path": "/server-status", "severity": "medium", "title": "Apache Server Status Exposed",
     "description": "Apache mod_status page reveals server activity and worker details.",
     "cvss": 5.3, "category": "Information Disclosure",
     "rec": "Restrict /server-status to localhost or internal IPs"},

    {"path": "/.DS_Store", "severity": "medium", "title": "Exposed .DS_Store File",
     "description": "macOS .DS_Store file is publicly accessible, revealing directory listing information.",
     "cvss": 5.3, "category": "Information Disclosure",
     "rec": "Block .DS_Store file access in web server configuration and add to .gitignore"},
]

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)


def _tokenize(text: str) -> set[str]:
    """Extract normalized word tokens for similarity comparisons."""
    clean = re.sub(r'[^a-z0-9]+', ' ', text.lower())
    return {w for w in clean.split() if len(w) >= 3}


def _extract_title(html: str) -> str:
    """Extract <title> tag from HTML content."""
    match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip().lower()
    return ""


async def _get_soft404_baseline(client: SafeFetchClient, base_url: str) -> dict[str, Any]:
    """
    Fetch baseline response for a non-existent path to detect Soft-404 behavior.
    """
    import uuid
    rand_path = f"/sentinelscan-nonexistent-{uuid.uuid4().hex[:10]}"
    target_url = urljoin(base_url, rand_path)

    baseline = {
        "status_code": 404,
        "final_url_path": "/sentinelscan-nonexistent",
        "content_type": "",
        "body_len": 0,
        "body_text": "",
        "title": "",
        "tokens": set(),
        "is_html": False,
    }

    try:
        r = await client.get(target_url)
        baseline["status_code"] = r.status_code
        baseline["final_url_path"] = urlparse(str(r.url)).path.lower().rstrip('/')
        baseline["content_type"] = r.headers.get("content-type", "").lower()
        baseline["body_len"] = len(r.content)
        baseline["body_text"] = r.text[:5000].lower()
        baseline["is_html"] = "text/html" in baseline["content_type"] or "<html" in baseline["body_text"]
        if baseline["is_html"]:
            baseline["title"] = _extract_title(r.text)
            baseline["tokens"] = _tokenize(r.text[:3000])
    except Exception as e:
        logger.debug(f"Soft-404 baseline fetch error: {e}")

    return baseline


def _is_soft_404_or_redirect(response: httpx.Response, baseline: dict[str, Any], path_info: dict) -> bool:
    """
    Determine if a candidate path response is a 404, Soft-404, or redirect to a non-target page.
    """
    # 1. Non-200 responses are not public disclosures
    if response.status_code != 200 and response.status_code != 206:
        return True

    final_url = str(response.url)
    final_path = urlparse(final_url).path.lower().rstrip('/')
    target_path = path_info["path"].lower().rstrip('/')

    # 2. Redirect checks
    if response.history:
        # Check if redirected to root, login, 404, or baseline final path
        if final_path in ("", "/", "/index.html", "/home", "/login", "/signin", "/auth", "/404", "/not-found", "/error"):
            return True
        if final_path == baseline.get("final_url_path") and final_path != target_path:
            return True

    # 3. Content-Type & HTML Error checks
    c_type = response.headers.get("content-type", "").lower()
    text = response.text[:4000].lower()
    is_html = "text/html" in c_type or "<html" in text or "<!doctype" in text

    # If file type is supposed to be data/config/binary but returned HTML (except UI paths)
    is_ui_path = path_info["path"] in ("/admin", "/wp-admin/", "/phpmyadmin/", "/swagger-ui.html", "/api/docs", "/server-status")
    if is_html and not is_ui_path:
        # Check title and error phrases in HTML
        title = _extract_title(response.text)
        error_keywords = ("404", "not found", "page not found", "error", "doesn't exist", "oops")

        if baseline.get("title") and title == baseline.get("title"):
            return True

        if any(kw in title for kw in error_keywords):
            return True

        error_phrases = (
            "page not found", "404 not found", "page does not exist",
            "the page you requested", "resource not found", "oops! page not found",
            "something went wrong", "error 404"
        )
        if any(phrase in text for phrase in error_phrases):
            return True

        # Token similarity with baseline soft-404 page
        if baseline.get("is_html") and baseline.get("tokens"):
            cand_tokens = _tokenize(text)
            if cand_tokens and baseline["tokens"]:
                intersection = cand_tokens & baseline["tokens"]
                union = cand_tokens | baseline["tokens"]
                similarity = len(intersection) / len(union)
                if similarity > 0.55:  # Over 55% similarity to baseline 404 page
                    return True

    return False


def _redact_secrets(text: str) -> str:
    """Redact actual credentials/secrets in evidence strings."""
    # Redact env assignments like PASS=xyz or SECRET=abc
    pattern = r'((?:PASS|PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|AUTH)[A-Z0-9_]*\s*=\s*)([^\s\n]+)'
    return re.sub(pattern, r'\1[REDACTED]', text, flags=re.IGNORECASE)


def _validate_content(path_info: dict, response: httpx.Response) -> tuple[bool, str, str]:
    """
    Perform strict content validation to confirm that candidate response contains
    affirmative evidence matching the claimed file type.
    Returns (is_valid, evidence_summary, confidence).
    """
    path = path_info["path"]
    text = response.text
    text_lower = text[:3000].lower()
    c_type = response.headers.get("content-type", "").lower()
    content_bytes = response.content

    is_html = "text/html" in c_type or "<html" in text_lower or "<!doctype" in text_lower

    # 1. Environment files (.env, .env.production)
    if path in ("/.env", "/.env.production"):
        if is_html:
            return False, "", "none"

        # Check key=value pattern
        lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith('#')]
        env_line_pattern = re.compile(r'^[A-Za-z0-9_]{2,}\s*=\s*.*$')
        valid_lines = [l for l in lines if env_line_pattern.match(l)]

        # Require at least 2 valid KEY=VALUE lines to confirm an env file.
        # A single-line non-HTML text file could coincidentally match the pattern.
        if len(valid_lines) < 2:
            return False, "", "none"

        known_sensitive_keys = (
            "DB_PASSWORD", "APP_KEY", "AWS_SECRET_ACCESS_KEY", "SECRET_KEY",
            "DATABASE_URL", "REDIS_PASSWORD", "POSTGRES_PASSWORD", "MONGO_URI",
            "JWT_SECRET", "API_KEY"
        )

        sensitive_lines = [l for l in valid_lines if any(k in l for k in known_sensitive_keys)]
        other_lines = [l for l in valid_lines if l not in sensitive_lines]
        sample_lines = (sensitive_lines + other_lines)[:5]
        redacted_sample = _redact_secrets("\n".join(sample_lines))
        return True, f"Verified environment file containing {len(valid_lines)} key=value pairs:\n{redacted_sample}", "high"

    # 2. Git HEAD (.git/HEAD)
    if path == "/.git/HEAD":
        if is_html:
            return False, "", "none"
        if text.startswith("ref: refs/") or re.match(r'^[0-9a-f]{40}', text.strip()):
            return True, f"Verified Git HEAD reference: {text.strip()[:60]}", "high"
        return False, "", "none"

    # 3. Config PHP (config.php)
    if path == "/config.php":
        if is_html:
            return False, "", "none"
        # Must contain unparsed PHP code
        if ("<?php" in text or "<?" in text) and any(kw in text for kw in ("$db", "define(", "$config")):
            return True, "Verified unparsed PHP configuration source code.", "high"
        return False, "", "none"

    # 4. WordPress config backup (wp-config.php.bak)
    if path == "/wp-config.php.bak":
        if is_html:
            return False, "", "none"
        if any(kw in text for kw in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "AUTH_KEY", "table_prefix")):
            return True, "Verified WordPress configuration backup with DB credentials.", "high"
        return False, "", "none"

    # 5. SQL Dump (backup.sql)
    if path == "/backup.sql":
        if is_html:
            return False, "", "none"
        sql_indicators = ("create table", "insert into", "mysql dump", "postgresql database dump", "drop table if exists", "engine=innodb")
        if any(kw in text_lower for kw in sql_indicators):
            return True, "Verified SQL database dump with DDL/DML statements.", "high"
        return False, "", "none"

    # 6. Backup archive (backup.zip)
    if path == "/backup.zip":
        if is_html:
            return False, "", "none"
        is_zip_type = any(t in c_type for t in ("application/zip", "application/x-zip-compressed", "application/octet-stream"))
        is_zip_magic = content_bytes.startswith(b"PK\x03\x04")
        if is_zip_magic or (is_zip_type and len(content_bytes) > 100):
            return True, f"Verified ZIP archive payload ({len(content_bytes)} bytes).", "high"
        return False, "", "none"

    # 7. Swagger JSON (swagger.json)
    if path == "/swagger.json":
        if any(kw in text_lower for kw in ("swagger", "openapi", "paths")):
            try:
                import json
                json.loads(text)
                return True, "Verified OpenAPI/Swagger JSON specification.", "high"
            except Exception:
                pass
        return False, "", "none"

    # 8. Swagger UI / API docs
    if path in ("/swagger-ui.html", "/api/docs"):
        if any(kw in text_lower for kw in ("swagger-ui", "redoc-container", "swaggeruibundle", "api documentation")):
            return True, "Verified interactive API documentation UI page.", "high"
        return False, "", "none"

    # 9. Admin panels (/admin, /wp-admin/, /phpmyadmin/)
    if path == "/admin":
        # Require a password input field AND a form action that targets admin/login.
        # Checking for the word 'login' alone is too broad — many pages include a
        # login link in the nav, causing false positives on non-admin pages.
        has_password_input = '<input type="password"' in text_lower or "type='password'" in text_lower
        has_admin_form = bool(re.search(r'action=["\'][^"\']*(admin|login|signin)[^"\']', text_lower))
        if is_html and has_password_input and has_admin_form:
            return True, "Administrative login interface accessible (password input + admin/login form action detected).", "medium"
        return False, "", "none"

    if path == "/wp-admin/":
        if is_html and any(kw in text_lower for kw in ("wp-login.php", "wordpress", "user_login", "loginform")):
            return True, "WordPress admin login page accessible.", "high"
        return False, "", "none"

    if path == "/phpmyadmin/":
        if is_html and any(kw in text_lower for kw in ("phpmyadmin", "pma_username", "pma_password", "input_username")):
            return True, "phpMyAdmin database administration interface accessible.", "high"
        return False, "", "none"

    # 10. phpinfo.php
    if path == "/phpinfo.php":
        if any(kw in text_lower for kw in ("phpinfo()", "php version", "configuration command", "build date")):
            return True, "Verified phpinfo() diagnostic page.", "high"
        return False, "", "none"

    # 11. .DS_Store
    if path == "/.DS_Store":
        if is_html:
            return False, "", "none"
        if content_bytes.startswith(b"\x00\x00\x00\x01\x42\x75\x64\x31") or content_bytes.startswith(b"Bud1"):
            return True, "Verified macOS .DS_Store directory metadata file.", "high"
        return False, "", "none"

    # 12. Server Status (/server-status)
    if path == "/server-status":
        if any(kw in text_lower for kw in ("apache server status", "apache status", "server version:")):
            return True, "Verified Apache mod_status server status page.", "high"
        return False, "", "none"

    return False, "", "none"


async def _probe_path(client: SafeFetchClient, base_url: str, path_info: dict, baseline: dict[str, Any]) -> dict | None:
    """Probe a single path using baseline Soft-404 comparison and strict content validation."""
    if path_info["title"] == "robots.txt Found":
        return None

    try:
        url = urljoin(base_url, path_info["path"])
        response = await client.get(url)

        # Check soft-404, non-200, or redirect to home/login
        if _is_soft_404_or_redirect(response, baseline, path_info):
            return None

        # Content validation
        is_valid, evidence_summary, confidence = _validate_content(path_info, response)
        if not is_valid:
            return None

        content_len = len(response.content)
        c_type = response.headers.get("content-type", "unknown")

        return {
            "category": path_info["category"],
            "title": path_info["title"],
            "description": path_info["description"],
            "severity": path_info["severity"],
            "cvss_score": path_info["cvss"],
            "endpoint": url,
            "recommendation": path_info["rec"],
            "confidence": confidence,
            "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
            "evidence": f"GET {url} returned HTTP {response.status_code} ({c_type}, {content_len} bytes).\n{evidence_summary}",
        }
    except Exception as e:
        logger.debug(f"Path probe error for {path_info['path']}: {e}")
        return None


async def analyze_content(url: str) -> dict[str, Any]:
    findings = []
    sitemap_analysis: dict = {}

    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    async with SafeFetchClient(
        timeout=10.0,
        headers={"User-Agent": "Mozilla/5.0 (SentinelScan Security Scanner / Educational)"},
    ) as client:

        # 1. Fetch Soft-404 Baseline
        baseline = await _get_soft404_baseline(client, base_url)

        # 2. Probe sensitive paths in parallel using baseline
        probe_tasks = [_probe_path(client, base_url, p, baseline) for p in SENSITIVE_PATHS]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)
        for result in probe_results:
            if isinstance(result, dict):
                findings.append(result)

        # 3. sitemap.xml analysis
        try:
            r = await client.get(f"{base_url}/sitemap.xml")
            if r.status_code == 200 and "<?xml" in r.text[:100].lower() and not _is_soft_404_or_redirect(r, baseline, {"path": "/sitemap.xml"}):
                soup = BeautifulSoup(r.text, "xml")
                locs = soup.find_all("loc")
                urls_in_sitemap = [l.text for l in locs[:50]]
                sitemap_analysis = {
                    "found": True,
                    "url_count": len(locs),
                    "sample_urls": urls_in_sitemap[:10],
                }
        except Exception:
            sitemap_analysis = {"found": False}

        # 4. Sensitive HTML comments check
        try:
            r = await client.get(url)
            if r.status_code == 200:
                html_source = r.text

                # Sensitive HTML comments check
                # Only flag comments containing genuine credential/secret keywords.
                # 'todo', 'fixme', 'hack' are standard developer annotations with
                # no security implication and are excluded to reduce noise.
                SECURITY_COMMENT_KEYWORDS = ["password", "api key", "secret", "token", "credential", "private key", "access key"]
                # Tighter pattern: require a credential keyword NAME to appear
                # immediately before the assignment operator (= or :).
                # This distinguishes actual credential leakage:
                #   <!-- db_password = correcthorsebatterystaple -->   → MATCH
                #   <!-- api_key: sk-abc123xyz -->                     → MATCH
                # from security-advisory developer comments:
                #   <!-- TODO: Remove hardcoded credentials before release --> → no match
                #   <!-- Don't store passwords in plain text -->             → no match
                _CREDENTIAL_ASSIGNMENT_RE = re.compile(
                    r'(?:password|passwd|pwd|secret|api[_\-]?key|token|'
                    r'credential|private[_\-]?key|access[_\-]?key)'
                    r'\s*[=:]\s*\S{4,}',
                    re.IGNORECASE,
                )
                comments = re.findall(r'<!--(.*?)-->', html_source, re.DOTALL)
                sensitive_comments = [
                    c.strip() for c in comments
                    if any(kw in c.lower() for kw in SECURITY_COMMENT_KEYWORDS)
                    and _CREDENTIAL_ASSIGNMENT_RE.search(c)
                ]
                if sensitive_comments:
                    # Build evidence showing a short redacted snippet from the first comment
                    first_snippet = _redact_secrets(sensitive_comments[0][:120])
                    findings.append({
                        "category": "Information Disclosure",
                        "title": "Sensitive Information in HTML Comments",
                        "description": "HTML comments containing credential or secret keywords were found in the page source.",
                        "severity": "medium",
                        "cvss_score": 5.3,
                        "confidence": "high",
                        "endpoint": url,
                        "recommendation": "Remove all comments referencing credentials, tokens, or secrets before deploying to production.",
                        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
                        "evidence": f"Found {len(sensitive_comments)} comment(s) with credential keywords. First match: {first_snippet!r}",
                    })

        except Exception as e:
            logger.error(f"Content analysis error for {url}: {e}")

    return {
        "findings": findings,
        "sitemap_analysis": sitemap_analysis,
    }
