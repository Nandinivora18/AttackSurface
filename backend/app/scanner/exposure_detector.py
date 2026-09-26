"""
External Exposure Detector
==========================
Passive external security assessment covering 12 detection domains:

1.  Web Security Configuration    - CORS policy, server leaks, debug endpoints
2.  Auth and Session Security     - Login surface, auth headers, session patterns
3.  API Exposure                  - GraphQL, REST docs, versioned API paths
4.  JavaScript Secret Detection   - Hardcoded keys/tokens in inline/external JS
5.  Source Map Exposure           - .map files revealing minified source
6.  Sensitive File Probing        - Robots.txt signals, well-known endpoints
7.  Cloud Storage Exposure        - S3/GCS/Azure bucket references in HTML/JS
8.  DNS Intelligence              - Wildcard DNS, dangling CNAMEs, SPF/DMARC
9.  TLS Deep Analysis             - Weak ciphers, CT logs, cert transparency
10. Mixed Content Detection       - HTTP resources on HTTPS pages
11. Third-Party and SRI           - External scripts lacking SRI hashes
12. Cache Exposure                - Cache-Control misconfig on sensitive responses

Design constraints:
- Passive-only. No active exploitation, no out-of-band callbacks, no fuzzing.
- All network I/O uses SafeFetchClient (SSRF-safe).
- Evidence is always grounded in observed response data.
"""
from __future__ import annotations

import re
import asyncio
import logging
from typing import Any
from urllib.parse import urlparse, urljoin

from app.utils.safe_http import SafeFetchClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _finding(**kwargs: Any) -> dict:
    base: dict[str, Any] = {
        "category": "",
        "title": "",
        "description": "",
        "severity": "medium",
        "confidence": "high",
        "cvss_score": None,
        "recommendation": "",
        "references": [],
        "endpoint": "",
        "evidence": "",
        "detector_id": "",
    }
    base.update(kwargs)
    return base


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _is_https(url: str) -> bool:
    return urlparse(url).scheme == "https"


def _truncate(s: str, limit: int = 300) -> str:
    return s[:limit] + "..." if len(s) > limit else s


# ---------------------------------------------------------------------------
# 1. Web Security Configuration
# ---------------------------------------------------------------------------

_CORS_DANGEROUS = [
    (re.compile(r"\*"), "Wildcard ACAO", "critical", 9.1),
    (re.compile(r"null", re.IGNORECASE), "Null-origin ACAO", "high", 7.5),
]

_DEBUG_PATHS = [
    ("/debug", "Debug endpoint"),
    ("/actuator", "Spring Boot Actuator"),
    ("/actuator/env", "Spring Boot Actuator env"),
    ("/actuator/health", "Spring Boot Actuator health"),
    ("/health", "Health check endpoint"),
    ("/_debug", "Debug endpoint"),
    ("/console", "Admin console"),
    ("/jolokia", "Jolokia JMX"),
    ("/metrics", "Metrics endpoint"),
    ("/trace", "Trace endpoint"),
    ("/dump", "Dump endpoint"),
    ("/heapdump", "Heap dump"),
    ("/threaddump", "Thread dump"),
]

_SERVER_VERSION_RE = re.compile(
    r"(?:Apache|nginx|IIS|lighttpd|Jetty|Tomcat|WEBrick|Caddy|Gunicorn|uvicorn)[/ ]\d[\d.]+",
    re.IGNORECASE,
)
_X_POWERED_RE = re.compile(
    r"(?:PHP|ASP\.NET|Express|Servlet|ColdFusion)[/ ]\d[\d.]+",
    re.IGNORECASE,
)


async def analyze_web_security_config(
    target_url: str,
    response_headers: dict,
    html_body: str = "",
) -> list:
    findings = []
    base = _base_url(target_url)

    # CORS
    acao = response_headers.get("access-control-allow-origin", "")
    acac = response_headers.get("access-control-allow-credentials", "").lower()
    if acao:
        for pattern, label, sev, cvss in _CORS_DANGEROUS:
            if pattern.search(acao):
                if acac == "true":
                    desc = (
                        f"Server responds with Access-Control-Allow-Origin: {acao} and "
                        "Access-Control-Allow-Credentials: true. Any origin can issue authenticated "
                        "requests and read sensitive responses."
                    )
                    sev = "critical"
                else:
                    desc = (
                        f"Server responds with Access-Control-Allow-Origin: {acao}. "
                        "Any external origin can read resource contents, bypassing the Same-Origin "
                        "Policy for unauthenticated requests."
                    )
                findings.append(_finding(
                    category="Web Security Configuration",
                    title=f"Dangerous CORS Policy: {label}",
                    description=desc,
                    severity=sev, cvss_score=cvss, confidence="high",
                    recommendation=(
                        "Restrict ACAO to an explicit allowlist. "
                        "Never combine wildcard with Allow-Credentials: true."
                    ),
                    references=[
                        "https://portswigger.net/web-security/cors",
                        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                    ],
                    endpoint=target_url,
                    evidence=f"Access-Control-Allow-Origin: {_truncate(acao)}",
                    detector_id="exposure.cors.misconfiguration",
                ))
                break

    # Server version disclosure
    server_hdr = response_headers.get("server", "")
    if _SERVER_VERSION_RE.search(server_hdr):
        findings.append(_finding(
            category="Web Security Configuration",
            title="Server Version Disclosed in Response Header",
            description=f"Server header reveals software version: '{server_hdr}'. Attackers use version strings to find exploits.",
            severity="medium", cvss_score=5.3, confidence="high",
            recommendation="Suppress version in Server header. For nginx: server_tokens off; For Apache: ServerTokens Prod.",
            references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
            endpoint=target_url,
            evidence=f"Server: {_truncate(server_hdr)}",
            detector_id="exposure.server.version_disclosure",
        ))

    xpb_hdr = response_headers.get("x-powered-by", "")
    if _X_POWERED_RE.search(xpb_hdr):
        findings.append(_finding(
            category="Web Security Configuration",
            title="X-Powered-By Reveals Technology Version",
            description=f"X-Powered-By discloses: '{xpb_hdr}'. Aids backend fingerprinting.",
            severity="low", cvss_score=3.1, confidence="high",
            recommendation="Remove the X-Powered-By header entirely.",
            references=["https://owasp.org/www-project-secure-headers/"],
            endpoint=target_url,
            evidence=f"X-Powered-By: {_truncate(xpb_hdr)}",
            detector_id="exposure.server.xpoweredby",
        ))

    # Debug endpoints
    async with SafeFetchClient(timeout=8.0) as client:
        for path, label in _DEBUG_PATHS:
            probe_url = urljoin(base + "/", path.lstrip("/"))
            try:
                resp = await client.get(probe_url)
                if resp.status_code == 200 and len(resp.text) > 50:
                    snippet = resp.text[:200].strip()
                    snippet_lower = snippet.lower()
                    if any(kw in snippet_lower for kw in ["login", "unauthorized", "forbidden", "redirect"]):
                        continue
                    # Filter legitimate public health-check responses
                    if any(kw in snippet_lower for kw in ['"status":"up"', '"status": "up"', '"status":"ok"', '"status": "ok"', '"healthy":true', '"healthy": true']) and len(resp.text) < 400:
                        continue
                    is_health = "health" in path
                    findings.append(_finding(
                        category="Web Security Configuration",
                        title=f"Exposed {label}",
                        description=f"{label} at {probe_url} is publicly accessible without authentication.",
                        severity="medium" if is_health else "high",
                        cvss_score=4.3 if is_health else 7.5,
                        confidence="high",
                        recommendation=f"Restrict {path} to internal networks or authenticated operators.",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        endpoint=probe_url,
                        evidence=f"HTTP 200 at {probe_url} — body: {_truncate(snippet, 200)}",
                        detector_id="exposure.debug.endpoint_exposed",
                    ))
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# 2. Auth and Session Security
# ---------------------------------------------------------------------------

_SESSION_COOKIE_RE = re.compile(
    r"(sess(ion)?id|jsessionid|phpsessid|aspsessionid|asp\.net_sessionid|connect\.sid)",
    re.IGNORECASE,
)


async def analyze_auth_session_security(
    target_url: str,
    response_headers: dict,
    cookies: list,
    html_body: str = "",
) -> list:
    findings = []
    is_https = _is_https(target_url)

    for raw_cookie in cookies:
        cookie_lower = raw_cookie.lower()
        name_match = re.match(r"([^=;]+)=", raw_cookie)
        cookie_name = name_match.group(1).strip() if name_match else "<unknown>"

        if not _SESSION_COOKIE_RE.search(cookie_name):
            continue

        issues = []
        if "httponly" not in cookie_lower:
            issues.append("missing HttpOnly (JS can steal token)")
        if is_https and "secure" not in cookie_lower:
            issues.append("missing Secure flag (transmitted over HTTP)")
        if "samesite" not in cookie_lower:
            issues.append("missing SameSite (CSRF risk)")
        elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
            issues.append("SameSite=None without Secure (cross-origin theft)")

        if issues:
            findings.append(_finding(
                category="Auth and Session Security",
                title=f"Insecure Session Cookie: {cookie_name}",
                description=f"Session cookie '{cookie_name}' issues: {'; '.join(issues)}.",
                severity="high", cvss_score=7.5, confidence="high",
                recommendation=f"Set {cookie_name} with HttpOnly; Secure; SameSite=Strict.",
                references=[
                    "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
                ],
                endpoint=target_url,
                evidence=f"Set-Cookie: {_truncate(raw_cookie)}",
                detector_id="exposure.auth.session_cookie_flags",
            ))

    # Login form over HTTP
    if not is_https and html_body and re.search(r'<input[^>]+type=["\']password["\']', html_body, re.IGNORECASE):
        findings.append(_finding(
            category="Auth and Session Security",
            title="Login Form Served Over Unencrypted HTTP",
            description="Password input found on HTTP page. Credentials transmitted in cleartext.",
            severity="critical", cvss_score=9.1, confidence="high",
            recommendation="Enforce HTTPS on all pages containing authentication forms.",
            references=["https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"],
            endpoint=target_url,
            evidence='<input type="password"> found on HTTP page',
            detector_id="exposure.auth.plaintext_login",
        ))

    # HTTP Basic Auth
    www_auth = response_headers.get("www-authenticate", "")
    if www_auth.lower().startswith("basic "):
        findings.append(_finding(
            category="Auth and Session Security",
            title="HTTP Basic Authentication Exposed",
            description="Server demands Basic auth. Credentials are base64-encoded, not encrypted, unless over TLS.",
            severity="medium" if is_https else "high",
            cvss_score=5.3 if is_https else 7.5, confidence="high",
            recommendation="Migrate to Bearer/OAuth2. If Basic must be used, enforce HTTPS.",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication"],
            endpoint=target_url,
            evidence=f"WWW-Authenticate: {_truncate(www_auth)}",
            detector_id="exposure.auth.basic_auth_exposed",
        ))

    return findings


# ---------------------------------------------------------------------------
# 3. API Exposure
# ---------------------------------------------------------------------------

_API_PATHS = [
    ("/graphql", "GraphQL endpoint", "medium", 5.3, "exposure.api.graphql_exposed",
     "GraphQL endpoint accessible without authentication.",
     "Require authentication for GraphQL queries in production."),
    ("/graphiql", "GraphiQL IDE", "high", 7.5, "exposure.api.graphql_exposed",
     "GraphiQL IDE exposed publicly; enables unauthenticated query execution.",
     "Disable GraphiQL in production."),
    ("/playground", "GraphQL Playground", "high", 7.5, "exposure.api.graphql_exposed",
     "GraphQL Playground exposed publicly; enables unauthenticated query execution.",
     "Disable GraphQL Playground in production."),
    ("/openapi.json", "OpenAPI 3 Spec", "medium", 5.3, "exposure.api.openapi_exposed",
     "OpenAPI 3 specification publicly accessible; reveals full API surface.",
     "Restrict OpenAPI docs to authenticated/internal users."),
    ("/openapi.yaml", "OpenAPI YAML Spec", "medium", 5.3, "exposure.api.openapi_exposed",
     "OpenAPI YAML specification publicly accessible; reveals full API surface.",
     "Restrict OpenAPI docs to authenticated/internal users."),
    ("/api-docs", "API Documentation", "medium", 5.3, "exposure.api.docs_exposed",
     "API documentation accessible without authentication.",
     "Require authentication to access API docs in production."),
    ("/redoc", "ReDoc API Documentation", "medium", 5.3, "exposure.api.docs_exposed",
     "ReDoc reference accessible without authentication.",
     "Restrict ReDoc to authenticated users in production."),
    ("/api/swagger", "Swagger API Docs", "medium", 5.3, "exposure.api.docs_exposed",
     "Swagger UI accessible without authentication.",
     "Require authentication for Swagger UI in production."),
    ("/api/v1", "REST API v1 root", "medium", 5.3, "exposure.api.rest_exposed",
     "Versioned REST API root is publicly accessible.",
     "Require API key or JWT for all API endpoints."),
    ("/api/v2", "REST API v2 root", "medium", 5.3, "exposure.api.rest_exposed",
     "Versioned REST API root is publicly accessible.",
     "Require API key or JWT for all API endpoints."),
    ("/v1", "REST API v1", "medium", 5.3, "exposure.api.rest_exposed",
     "API v1 root is publicly accessible.",
     "Require authentication and implement proper access control."),
]

_GQL_INTROSPECT_BODY = b'{"query":"{__schema{queryType{name}}}"}'


async def analyze_api_exposure(target_url: str) -> list:
    findings = []
    base = _base_url(target_url)

    async with SafeFetchClient(timeout=10.0) as client:
        for path, label, sev, cvss, det_id, desc, rec in _API_PATHS:
            probe_url = urljoin(base + "/", path.lstrip("/"))
            try:
                resp = await client.get(probe_url)
                if resp.status_code not in (200, 201):
                    continue
                body = resp.text
                if not body or len(body) < 20:
                    continue
                body_lower = body[:300].lower()
                if any(kw in body_lower for kw in ["unauthorized", "forbidden", "login required", "sign in"]):
                    continue

                # GraphQL introspection confirmation
                if "graphql" in path or "graphiql" in path or "playground" in path:
                    try:
                        post_resp = await client.post(
                            probe_url,
                            content=_GQL_INTROSPECT_BODY,
                            headers={"Content-Type": "application/json"},
                        )
                        if "__schema" in post_resp.text:
                            findings.append(_finding(
                                category="API Exposure",
                                title=f"GraphQL Introspection Enabled: {label}",
                                description=f"{label} at {probe_url} accepts introspection queries, exposing the full type system.",
                                severity="high", cvss_score=7.5, confidence="high",
                                recommendation="Disable GraphQL introspection in production environments.",
                                references=[
                                    "https://graphql.org/learn/introspection/",
                                    "https://owasp.org/www-project-api-security/",
                                ],
                                endpoint=probe_url,
                                evidence=f"POST {probe_url} returned __schema",
                                detector_id="exposure.api.graphql_introspection",
                            ))
                            continue
                    except Exception:
                        pass

                findings.append(_finding(
                    category="API Exposure",
                    title=f"Exposed {label}",
                    description=desc, severity=sev, cvss_score=cvss, confidence="medium",
                    recommendation=rec,
                    references=["https://owasp.org/www-project-api-security/"],
                    endpoint=probe_url,
                    evidence=f"HTTP {resp.status_code} at {probe_url}",
                    detector_id=det_id,
                ))
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# 4. JavaScript Secret Detection
# ---------------------------------------------------------------------------

_JS_SECRET_PATTERNS = [
    ("AWS Access Key ID",
     re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
     "critical", 9.8, "exposure.js.aws_key"),
    ("AWS Secret Access Key",
     re.compile(r"(?:aws[_\-.]?secret[_\-.]?(?:access[_\-.]?)?key|aws_secret)\s*[=:]\s*['\"]([A-Za-z0-9/+=]{40})['\"]", re.IGNORECASE),
     "critical", 9.8, "exposure.js.aws_secret"),
    ("Google API Key",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     "high", 8.8, "exposure.js.google_api_key"),
    ("GitHub Personal Access Token",
     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
     "critical", 9.8, "exposure.js.github_token"),
    ("Stripe Live Key",
     re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
     "critical", 9.8, "exposure.js.stripe_live_key"),
    ("Stripe Test Key",
     re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
     "medium", 4.3, "exposure.js.stripe_test_key"),
    ("Slack Token",
     re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
     "high", 8.1, "exposure.js.slack_token"),
    ("SendGrid API Key",
     re.compile(r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}"),
     "high", 8.1, "exposure.js.sendgrid_key"),
    ("JWT Secret",
     re.compile(r"(?:jwt[_\-.]?secret|token[_\-.]?secret)\s*[=:]\s*['\"](\S{16,})['\"]", re.IGNORECASE),
     "high", 8.8, "exposure.js.jwt_secret"),
    ("Generic API Key",
     re.compile(r"(?:api[_\-.]?key|apikey|client[_\-.]?secret)\s*[=:]\s*['\"]([A-Za-z0-9\-_]{20,60})['\"]", re.IGNORECASE),
     "medium", 5.3, "exposure.js.generic_api_key"),
    ("Private Key Header",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
     "critical", 9.8, "exposure.js.private_key"),
]

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
_INLINE_SCRIPT_RE = re.compile(r"<script(?:[^>]*)>(.*?)</script>", re.IGNORECASE | re.DOTALL)


async def analyze_js_secrets(target_url: str, html_body: str) -> list:
    findings = []
    seen: set = set()
    p = urlparse(target_url)
    origin = f"{p.scheme}://{p.netloc}"

    # Guard: bound HTML parsing length (1 MB max)
    html_bounded = html_body[:1_048_576] if html_body else ""

    def scan_content(content: str, src_url: str) -> None:
        bounded_content = content[:524_288]
        for name, pattern, sev, cvss, det_id in _JS_SECRET_PATTERNS:
            for match in pattern.findall(bounded_content):
                val = match if isinstance(match, str) else (match[0] if match else "")
                if not val:
                    continue
                # Skip known false positive stubs on generic API keys
                if det_id == "exposure.js.generic_api_key":
                    val_lower = val.lower()
                    if any(stub in val_lower for stub in ["test", "dummy", "example", "placeholder", "123456", "abcdef", "000000"]):
                        continue
                key = f"{det_id}:{val[:20]}"
                if key in seen:
                    continue
                seen.add(key)
                conf = "medium" if det_id in ("exposure.js.generic_api_key", "exposure.js.jwt_secret", "exposure.js.aws_secret") else "high"
                redacted = val[:4] + "****" + val[-4:] if len(val) > 8 else "****"
                findings.append(_finding(
                    category="JavaScript Secret Detection",
                    title=f"Hardcoded {name} in JavaScript",
                    description=f"{name} pattern detected in JS at {src_url}. Hardcoded secrets are accessible to any visitor.",
                    severity=sev, cvss_score=cvss, confidence=conf,
                    recommendation=f"Remove {name} from client-side JS. Revoke and rotate. Use server-side env vars.",
                    references=[
                        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
                        "https://cwe.mitre.org/data/definitions/798.html",
                    ],
                    endpoint=src_url,
                    evidence=f"Pattern '{name}' matched (redacted: {redacted})",
                    detector_id=det_id,
                ))

    # Inline scripts with length guard
    for inline in _INLINE_SCRIPT_RE.findall(html_bounded):
        scan_content(inline[:524_288], target_url)

    # Same-origin external scripts with bounded read
    srcs = _SCRIPT_SRC_RE.findall(html_bounded)
    same_origin = [s for s in srcs if not s.startswith("http") or s.startswith(origin)]

    async with SafeFetchClient(timeout=8.0) as client:
        for src in same_origin[:10]:
            full = src if src.startswith("http") else urljoin(origin + "/", src.lstrip("/"))
            try:
                r = await client.get(full)
                if r.status_code == 200:
                    scan_content(r.text[:524_288], full)
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# 5. Source Map Exposure
# ---------------------------------------------------------------------------

_SOURCEMAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+\.map)", re.IGNORECASE)


async def analyze_source_map_exposure(
    target_url: str, html_body: str, response_headers: dict
) -> list:
    findings = []
    p = urlparse(target_url)
    origin = f"{p.scheme}://{p.netloc}"
    candidate_maps: list = []

    sm_hdr = response_headers.get("sourcemap", "") or response_headers.get("x-sourcemap", "")
    if sm_hdr.strip().endswith(".map"):
        candidate_maps.append(sm_hdr.strip())

    srcs = _SCRIPT_SRC_RE.findall(html_body)
    same_origin_js = [s for s in srcs if not s.startswith("http") or s.startswith(origin)]

    async with SafeFetchClient(timeout=8.0) as client:
        for src in same_origin_js[:8]:
            full_js = src if src.startswith("http") else urljoin(origin + "/", src.lstrip("/"))
            try:
                r = await client.get(full_js)
                if r.status_code != 200:
                    continue
                for map_ref in _SOURCEMAP_COMMENT_RE.findall(r.text):
                    if map_ref.startswith("http"):
                        candidate_maps.append(map_ref)
                    else:
                        js_path = urlparse(full_js).path.rsplit("/", 1)[0]
                        candidate_maps.append(f"{origin}{js_path}/{map_ref}")
            except Exception:
                pass

        for map_url in candidate_maps[:5]:
            if not map_url.startswith("http"):
                map_url = urljoin(origin + "/", map_url.lstrip("/"))
            try:
                r = await client.get(map_url)
                if r.status_code == 200 and '"sources"' in r.text:
                    findings.append(_finding(
                        category="Source Map Exposure",
                        title="JavaScript Source Map Publicly Accessible",
                        description=f"Source map at {map_url} is publicly accessible, revealing unminified source code, internal paths, and comments.",
                        severity="medium", cvss_score=5.3, confidence="high",
                        recommendation="Remove .map files from production or block *.map via CDN/server config.",
                        references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage"],
                        endpoint=map_url,
                        evidence=f"HTTP 200 at {map_url} with 'sources' key",
                        detector_id="exposure.sourcemap.exposed",
                    ))
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# 6. Sensitive Files (robots.txt + security.txt)
# ---------------------------------------------------------------------------

_ROBOTS_DISALLOW_RE = re.compile(r"^Disallow:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_SENSITIVE_ROBOTS_RE = re.compile(
    r"/(admin|dashboard|internal|private|secret|staging|api|backup|config|wp-admin|cron|db|database)",
    re.IGNORECASE,
)


async def analyze_sensitive_files(target_url: str) -> list:
    findings = []
    base = _base_url(target_url)

    async with SafeFetchClient(timeout=8.0) as client:
        # robots.txt
        robots_url = urljoin(base + "/", "robots.txt")
        try:
            r = await client.get(robots_url)
            if r.status_code == 200 and "disallow" in r.text.lower():
                disallowed = _ROBOTS_DISALLOW_RE.findall(r.text)
                sensitive = [d.strip() for d in disallowed if _SENSITIVE_ROBOTS_RE.search(d)]
                if sensitive:
                    findings.append(_finding(
                        category="Sensitive File Exposure",
                        title="robots.txt Discloses Sensitive Internal Paths",
                        description="robots.txt exposes internal/admin paths via Disallow directives, signalling high-value targets.",
                        severity="low", cvss_score=3.1, confidence="high",
                        recommendation="Audit robots.txt. Do not rely on it to protect endpoints — use access controls.",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        endpoint=robots_url,
                        evidence=f"Sensitive Disallow entries: {', '.join(sensitive[:10])}",
                        detector_id="exposure.files.robots_sensitive_paths",
                    ))
        except Exception:
            pass

        # security.txt
        sectxt_url = urljoin(base + "/", ".well-known/security.txt")
        try:
            r = await client.get(sectxt_url)
            if r.status_code in (404, 405):
                findings.append(_finding(
                    category="Sensitive File Exposure",
                    title="Missing security.txt",
                    description="No security.txt at /.well-known/security.txt. Security researchers lack a standard contact channel.",
                    severity="info", cvss_score=None, confidence="high",
                    recommendation="Create /.well-known/security.txt per RFC 9116 with Contact and Expires fields.",
                    references=["https://securitytxt.org/", "https://www.rfc-editor.org/rfc/rfc9116"],
                    endpoint=sectxt_url,
                    evidence=f"HTTP {r.status_code} for /.well-known/security.txt",
                    detector_id="exposure.files.security_txt_missing",
                ))
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------------
# 7. Cloud Storage Exposure
# ---------------------------------------------------------------------------

_S3_RE = re.compile(
    r"(?:https?://)?([a-z0-9][a-z0-9\-]{1,61}[a-z0-9])"
    r"\.s3(?:[-.](?:us|eu|ap|sa|ca|me|af)[-.]?[a-z0-9-]*)?"
    r"\.amazonaws\.com",
    re.IGNORECASE,
)
_GCS_RE = re.compile(
    r"(?:https?://)?storage\.googleapis\.com/([a-z0-9][a-z0-9\-_.]{1,221}[a-z0-9])",
    re.IGNORECASE,
)
_AZURE_RE = re.compile(
    r"(?:https?://)?([a-z0-9]{3,24})\.blob\.core\.windows\.net/([a-z0-9\$][a-z0-9\-]{2,62})",
    re.IGNORECASE,
)


async def analyze_cloud_storage(target_url: str, html_body: str) -> list:
    findings = []
    buckets: dict = {}

    for m in _S3_RE.finditer(html_body):
        bname = m.group(1)
        burl = m.group(0) if m.group(0).startswith("http") else "https://" + m.group(0)
        buckets[burl.rstrip("/")] = ("AWS S3", bname)

    for m in _GCS_RE.finditer(html_body):
        bname = m.group(1)
        buckets[f"https://storage.googleapis.com/{bname}"] = ("Google Cloud Storage", bname)

    for m in _AZURE_RE.finditer(html_body):
        acc, cont = m.group(1), m.group(2)
        buckets[f"https://{acc}.blob.core.windows.net/{cont}"] = ("Azure Blob Storage", f"{acc}/{cont}")

    async with SafeFetchClient(timeout=10.0) as client:
        for burl, (provider, bname) in list(buckets.items())[:8]:
            try:
                r = await client.get(burl)
                body_snippet = r.text[:500]
                is_listing = r.status_code == 200 and any(kw in body_snippet for kw in [
                    "<ListBucketResult", "<Contents>", '"kind": "storage#objects"', "<EnumerationResults"
                ])
                if is_listing:
                    findings.append(_finding(
                        category="Cloud Storage Exposure",
                        title=f"Publicly Listable {provider} Bucket: {bname}",
                        description=f"{provider} bucket '{bname}' is publicly listable; all objects can be enumerated.",
                        severity="critical", cvss_score=9.1, confidence="high",
                        recommendation=f"Apply private ACL to {provider} bucket. Enable access logging and encryption.",
                        references=[
                            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                            "https://owasp.org/www-project-top-ten/",
                        ],
                        endpoint=burl,
                        evidence=f"HTTP 200 at {burl} with public listing response",
                        detector_id="exposure.cloud.bucket_public",
                    ))
                elif r.status_code == 200:
                    findings.append(_finding(
                        category="Cloud Storage Exposure",
                        title=f"{provider} Bucket Publicly Accessible: {bname}",
                        description=f"Reference to {provider} bucket '{bname}' found in source; HTTP 200 indicates public read.",
                        severity="medium", cvss_score=5.3, confidence="medium",
                        recommendation=f"Verify {provider} bucket '{bname}' exposes only intended objects.",
                        references=["https://owasp.org/www-project-top-ten/"],
                        endpoint=burl,
                        evidence=f"HTTP 200 at {burl}",
                        detector_id="exposure.cloud.bucket_accessible",
                    ))
                else:
                    findings.append(_finding(
                        category="Cloud Storage Exposure",
                        title=f"{provider} Bucket Reference in Page Source",
                        description=f"Reference to {provider} bucket '{bname}' found in client-facing HTML/JS source.",
                        severity="low", cvss_score=3.1, confidence="medium",
                        recommendation="Audit bucket references in client code; enforce private bucket ACLs.",
                        references=["https://owasp.org/www-project-top-ten/"],
                        endpoint=burl,
                        evidence=f"Bucket URL referenced in source: {burl} (HTTP {r.status_code})",
                        detector_id="exposure.cloud.bucket_reference",
                    ))
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# 8. DNS Intelligence (builds on dns_checker result)
# ---------------------------------------------------------------------------


async def analyze_dns_intelligence(hostname: str, dns_result: dict) -> list:
    findings = []
    records = dns_result.get("records", {})
    txt_records = records.get("TXT", [])

    # SPF analysis
    spf = next((r for r in txt_records if r.strip().lower().startswith("v=spf1")), None)
    if spf:
        if "+all" in spf or "?all" in spf:
            findings.append(_finding(
                category="DNS Intelligence",
                title="SPF Record Allows All Senders (pass-all)",
                description=f"SPF for {hostname} contains '+all' or '?all'; any sender can forge email from this domain.",
                severity="high", cvss_score=7.5, confidence="high",
                recommendation="Replace '+all'/'?all' with '-all' (hardfail). Audit all authorized mail senders.",
                references=["https://www.rfc-editor.org/rfc/rfc7208", "https://dmarcian.com/what-is-spf/"],
                endpoint=hostname,
                evidence=f"SPF: {_truncate(spf)}",
                detector_id="exposure.dns.spf_passall",
            ))
        elif "~all" in spf:
            findings.append(_finding(
                category="DNS Intelligence",
                title="SPF Record Uses Softfail (~all)",
                description=f"SPF for {hostname} uses '~all' (softfail); unauthorized senders marked but not rejected.",
                severity="medium", cvss_score=4.3, confidence="high",
                recommendation="Upgrade '~all' to '-all' once authorized senders are confirmed. Add DMARC p=reject.",
                references=["https://www.rfc-editor.org/rfc/rfc7208"],
                endpoint=hostname,
                evidence=f"SPF: {_truncate(spf)}",
                detector_id="exposure.dns.spf_softfail",
            ))

    # Wildcard DNS
    if dns_result.get("wildcard_dns"):
        findings.append(_finding(
            category="DNS Intelligence",
            title="Wildcard DNS Record Detected",
            description=f"Wildcard DNS (*.{hostname}) is configured. Combined with dangling CNAMEs, this creates subdomain takeover risk.",
            severity="medium", cvss_score=5.3, confidence="medium",
            recommendation="Audit all subdomain CNAMEs to third-party services. Remove dangling CNAMEs.",
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            endpoint=hostname,
            evidence=f"DNS wildcard detected for {hostname}",
            detector_id="exposure.dns.wildcard",
        ))

    # DMARC
    dmarc_recs = [r for r in txt_records if "v=dmarc1" in r.lower()]
    if not dmarc_recs:
        findings.append(_finding(
            category="DNS Intelligence",
            title="No DMARC Policy Found",
            description=f"No DMARC record for {hostname}. Receiving MTAs cannot reject spoofed email claiming this domain.",
            severity="medium", cvss_score=5.3, confidence="high",
            recommendation=f"Publish: _dmarc.{hostname} IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{hostname}\". Advance to p=reject.",
            references=["https://dmarc.org/overview/", "https://www.rfc-editor.org/rfc/rfc7489"],
            endpoint=hostname,
            evidence=f"No _dmarc.{hostname} TXT record",
            detector_id="exposure.dns.dmarc_missing",
        ))
    elif "p=none" in dmarc_recs[0].lower():
        findings.append(_finding(
            category="DNS Intelligence",
            title="DMARC Policy Set to None (Monitor Only)",
            description=f"DMARC for {hostname} uses p=none; unauthorized senders only reported, not blocked.",
            severity="low", cvss_score=3.1, confidence="high",
            recommendation="Review DMARC reports then advance to p=quarantine then p=reject.",
            references=["https://dmarc.org/"],
            endpoint=hostname,
            evidence=f"DMARC: {_truncate(dmarc_recs[0])}",
            detector_id="exposure.dns.dmarc_none_policy",
        ))

    return findings


# ---------------------------------------------------------------------------
# 9. TLS Deep Analysis (builds on ssl_checker result)
# ---------------------------------------------------------------------------


async def analyze_tls_deep(hostname: str, ssl_result: dict, target_url: str) -> list:
    findings = []
    if not _is_https(target_url):
        return findings

    proto_versions = ssl_result.get("protocol_versions", [])
    cipher_suites = ssl_result.get("cipher_suites", [])
    tls_info = ssl_result.get("tls_info", {})
    cert_info = ssl_result.get("cert_info", {})

    # CT logging (passive scan cannot verify CT logs; flagged as NOT_VERIFIABLE indicator)
    if cert_info and cert_info.get("ct_logged") is False:
        findings.append(_finding(
            category="TLS Analysis",
            title="Certificate Transparency Status Unverified",
            description=f"Certificate Transparency logging for {hostname} could not be verified passively. CT verification requires active log monitoring.",
            severity="info", cvss_score=None, confidence="low",
            recommendation="Verify certificate issuance in public Certificate Transparency logs (e.g. crt.sh).",
            references=["https://certificate.transparency.dev/", "https://developer.chrome.com/blog/ct-policy/"],
            endpoint=f"{hostname}:443",
            evidence="Passive handshake cannot verify SCT presence (NOT_VERIFIABLE)",
            detector_id="exposure.tls.ct_not_logged",
        ))

    # Weak protocols
    weak_protos = [v for v in proto_versions if v in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1")]
    if weak_protos:
        findings.append(_finding(
            category="TLS Analysis",
            title=f"Deprecated TLS Protocols Supported: {', '.join(weak_protos)}",
            description=f"Server supports deprecated TLS versions: {', '.join(weak_protos)}. Vulnerable to POODLE, BEAST.",
            severity="high", cvss_score=7.5, confidence="high",
            recommendation="Disable TLS 1.0/1.1. Support TLS 1.2 and TLS 1.3 only. nginx: ssl_protocols TLSv1.2 TLSv1.3;",
            references=["https://ssl-config.mozilla.org/", "https://datatracker.ietf.org/doc/rfc8996/"],
            endpoint=f"{hostname}:443",
            evidence=f"Weak protocols: {', '.join(weak_protos)}",
            detector_id="exposure.tls.weak_protocols",
        ))

    # Weak ciphers
    weak_kws = ["rc4", "des", "3des", "export", "null", "anon", "md5"]
    weak_ciphers = [c for c in cipher_suites if any(k in c.lower() for k in weak_kws)]
    if weak_ciphers:
        findings.append(_finding(
            category="TLS Analysis",
            title=f"Weak TLS Cipher Suites Supported ({len(weak_ciphers)} found)",
            description=f"Server supports weak ciphers: {', '.join(weak_ciphers[:4])}. Enables downgrade attacks.",
            severity="high", cvss_score=7.5, confidence="high",
            recommendation="Use only AEAD ciphers (AES-GCM, CHACHA20-POLY1305). Remove RC4, 3DES, NULL, EXPORT.",
            references=["https://ssl-config.mozilla.org/", "https://ciphersuite.info/"],
            endpoint=f"{hostname}:443",
            evidence=f"Weak ciphers: {', '.join(weak_ciphers[:4])}",
            detector_id="exposure.tls.weak_ciphers",
        ))

    # HSTS preload readiness
    if tls_info.get("hsts") and not tls_info.get("hsts_preload"):
        findings.append(_finding(
            category="TLS Analysis",
            title="HSTS Not Submitted to Preload List",
            description=f"HSTS configured for {hostname} but 'preload' directive missing. First-time visitors can be SSL-stripped.",
            severity="low", cvss_score=3.1, confidence="medium",
            recommendation="Add 'preload' to HSTS header and submit at https://hstspreload.org/",
            references=["https://hstspreload.org/", "https://www.rfc-editor.org/rfc/rfc6797"],
            endpoint=f"{hostname}:443",
            evidence="HSTS present but 'preload' directive absent",
            detector_id="exposure.tls.hsts_not_preloaded",
        ))

    return findings


# ---------------------------------------------------------------------------
# 10. Mixed Content Detection
# ---------------------------------------------------------------------------

_MIXED_ACTIVE_RE = re.compile(
    r"""(?:src)\s*=\s*["'](http://[^"']+\.js[^"']*)["']""",
    re.IGNORECASE,
)
_MIXED_FORM_RE = re.compile(
    r"""<form[^>]+action\s*=\s*["'](http://[^"']+)["']""",
    re.IGNORECASE,
)
_MIXED_PASSIVE_RE = re.compile(
    r"""(?:src|href|data-src)\s*=\s*["'](http://[^"']+)["']""",
    re.IGNORECASE,
)


async def analyze_mixed_content(target_url: str, html_body: str) -> list:
    findings = []
    if not _is_https(target_url):
        return findings

    scripts = _MIXED_ACTIVE_RE.findall(html_body)
    forms = _MIXED_FORM_RE.findall(html_body)
    active = list(dict.fromkeys(scripts + forms))
    other = [u for u in _MIXED_PASSIVE_RE.findall(html_body) if u not in active]

    if active:
        findings.append(_finding(
            category="Mixed Content",
            title=f"Active Mixed Content: HTTP Resource(s) on HTTPS Page ({len(active)} found)",
            description="HTTP-sourced scripts or form actions on HTTPS page. Active mixed content can compromise page execution or leak submitted credentials.",
            severity="high", cvss_score=7.5, confidence="high",
            recommendation="Update all script references and form actions to HTTPS. Add CSP: upgrade-insecure-requests.",
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                "https://developers.google.com/web/fundamentals/security/prevent-mixed-content/fixing-mixed-content",
            ],
            endpoint=target_url,
            evidence=f"HTTP active resource URLs: {'; '.join(active[:3])}",
            detector_id="exposure.mixed_content.active",
        ))

    if other:
        findings.append(_finding(
            category="Mixed Content",
            title=f"Passive Mixed Content: HTTP Resources on HTTPS Page ({len(other)} found)",
            description="HTTP images/stylesheets/iframes on HTTPS page. Can be intercepted to modify appearance or track users.",
            severity="medium", cvss_score=4.3, confidence="medium",
            recommendation="Update resource references to HTTPS. Use CSP: upgrade-insecure-requests.",
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
            endpoint=target_url,
            evidence=f"HTTP resource URLs: {'; '.join(other[:3])}",
            detector_id="exposure.mixed_content.passive",
        ))

    return findings


# ---------------------------------------------------------------------------
# 11. Third-Party Scripts and SRI
# ---------------------------------------------------------------------------

_KNOWN_CDNS = [
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "ajax.googleapis.com", "code.jquery.com", "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com", "cdn.datatables.net",
]


async def analyze_third_party_sri(target_url: str, html_body: str) -> list:
    findings = []
    p = urlparse(target_url)
    host = p.netloc

    ext_re = re.compile(
        r'<script[^>]+src=["\']((https?://(?!' + re.escape(host) + r')[^"\']+))["\']([^>]*)',
        re.IGNORECASE,
    )

    no_sri: list = []
    cdn_no_sri: list = []

    for m in ext_re.finditer(html_body):
        src = m.group(1)
        tag = m.group(3)
        if not re.search(r'integrity=["\']', tag, re.IGNORECASE):
            no_sri.append(src)
            if any(cdn in urlparse(src).netloc for cdn in _KNOWN_CDNS):
                cdn_no_sri.append(src)

    if cdn_no_sri:
        findings.append(_finding(
            category="Third-Party and SRI",
            title=f"CDN Scripts Without SRI Hashes ({len(cdn_no_sri)} found)",
            description="CDN scripts loaded without Subresource Integrity hashes. CDN compromise executes malicious code for all visitors.",
            severity="medium", cvss_score=5.3, confidence="high",
            recommendation="Add integrity and crossorigin attributes to all CDN script tags. Generate hashes at https://www.srihash.org/",
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                "https://owasp.org/www-project-top-ten/",
            ],
            endpoint=target_url,
            evidence=f"CDN scripts without SRI: {'; '.join(cdn_no_sri[:3])}",
            detector_id="exposure.sri.cdn_missing",
        ))
    elif no_sri:
        findings.append(_finding(
            category="Third-Party and SRI",
            title=f"External Scripts Without SRI Hashes ({len(no_sri)} found)",
            description="External scripts loaded without SRI hashes, trusting external host security entirely.",
            severity="low", cvss_score=3.1, confidence="medium",
            recommendation="Add integrity attributes to external script tags. Consider self-hosting critical scripts.",
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
            endpoint=target_url,
            evidence=f"External scripts without SRI: {'; '.join(no_sri[:3])}",
            detector_id="exposure.sri.external_missing",
        ))

    return findings


# ---------------------------------------------------------------------------
# 12. Cache Exposure
# ---------------------------------------------------------------------------

_SENSITIVE_CACHE_API_PATHS = [
    "/api/user", "/api/profile", "/api/account",
    "/api/settings", "/api/me", "/user/profile",
    "/account", "/profile",
]
_SENSITIVE_RESP_PATTERNS = [
    (re.compile(r'"token"\s*:', re.IGNORECASE), "API token"),
    (re.compile(r'"password"\s*:', re.IGNORECASE), "password field"),
    (re.compile(r'"secret"\s*:', re.IGNORECASE), "secret field"),
    (re.compile(r'"credit_card|card_number|cvv"', re.IGNORECASE), "payment card data"),
    (re.compile(r'"ssn|social_security"', re.IGNORECASE), "SSN"),
    (re.compile(r'"private_key|privatekey"', re.IGNORECASE), "private key"),
]


async def analyze_cache_exposure(
    target_url: str,
    response_headers: dict,
    html_body: str = "",
) -> list:
    findings = []
    base = _base_url(target_url)

    # Main page cache check if auth response
    cc = response_headers.get("cache-control", "").lower()
    is_auth_resp = bool(response_headers.get("www-authenticate") or response_headers.get("authorization"))
    is_html = "text/html" in response_headers.get("content-type", "")
    is_cacheable = not any(kw in cc for kw in ["no-store", "no-cache", "private"])

    if is_html and is_auth_resp and is_cacheable:
        findings.append(_finding(
            category="Cache Exposure",
            title="Authenticated Page May Be Cached by Intermediaries",
            description="Authenticated response lacks no-store/private Cache-Control. Shared caches may serve authenticated data to others.",
            severity="medium", cvss_score=5.3, confidence="medium",
            recommendation="Set Cache-Control: no-store on all authenticated responses. Use Vary: Cookie, Authorization.",
            references=[
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching",
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
            endpoint=target_url,
            evidence=f"Cache-Control: {cc or 'absent'} | Auth header present",
            detector_id="exposure.cache.authenticated_cacheable",
        ))

    # Sensitive API endpoints cache audit
    async with SafeFetchClient(timeout=8.0) as client:
        for path in _SENSITIVE_CACHE_API_PATHS[:6]:
            probe_url = urljoin(base + "/", path.lstrip("/"))
            try:
                r = await client.get(probe_url)
                if r.status_code not in (200, 201):
                    continue
                resp_cc = r.headers.get("cache-control", "").lower()
                resp_ct = r.headers.get("content-type", "")
                is_json = "json" in resp_ct
                is_no_cache = any(kw in resp_cc for kw in ["no-store", "no-cache", "private"])

                if is_json and not is_no_cache and len(r.text) > 20:
                    for pattern, label in _SENSITIVE_RESP_PATTERNS:
                        if pattern.search(r.text):
                            findings.append(_finding(
                                category="Cache Exposure",
                                title=f"Potentially Sensitive API Response Cacheable: {label} at {path}",
                                description=f"API at {probe_url} returns {label} without Cache-Control: no-store. Intermediate caches may store sensitive data.",
                                severity="high", cvss_score=7.5, confidence="medium",
                                recommendation="Add Cache-Control: no-store, private to all API responses with credentials or personal data.",
                                references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/06-Testing_for_Browser_Cache_Weaknesses"],
                                endpoint=probe_url,
                                evidence=f"HTTP {r.status_code} | Cache-Control: {resp_cc or 'absent'} | {label} in response",
                                detector_id="exposure.cache.sensitive_api_cacheable",
                            ))
                            break
                    else:
                        if not resp_cc:
                            findings.append(_finding(
                                category="Cache Exposure",
                                title=f"API Endpoint Has No Cache-Control Header: {path}",
                                description=f"JSON API at {probe_url} has no Cache-Control header; browser/proxy may cache response indefinitely.",
                                severity="low", cvss_score=3.1, confidence="medium",
                                recommendation="Add Cache-Control: no-store to sensitive API endpoints.",
                                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching"],
                                endpoint=probe_url,
                                evidence=f"HTTP {r.status_code} | Cache-Control: absent",
                                detector_id="exposure.cache.no_cache_control",
                            ))
            except Exception:
                pass

    return findings


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


async def run_exposure_detection(
    target_url: str,
    response_headers: dict,
    html_body: str,
    cookies: list,
    dns_result: dict,
    ssl_result: dict,
    hostname: str,
) -> list:
    """
    Run all 12 external exposure detection domains in parallel.

    All network I/O uses SafeFetchClient (SSRF-safe).
    Exceptions in individual domains are logged and swallowed so one domain
    failure never aborts the entire pass.

    Returns:
        List of finding dicts in the standard SentinelScan finding schema.
    """
    domain_coros = [
        analyze_web_security_config(target_url, response_headers, html_body),
        analyze_auth_session_security(target_url, response_headers, cookies, html_body),
        analyze_api_exposure(target_url),
        analyze_js_secrets(target_url, html_body),
        analyze_source_map_exposure(target_url, html_body, response_headers),
        analyze_sensitive_files(target_url),
        analyze_cloud_storage(target_url, html_body),
        analyze_dns_intelligence(hostname, dns_result),
        analyze_tls_deep(hostname, ssl_result, target_url),
        analyze_mixed_content(target_url, html_body),
        analyze_third_party_sri(target_url, html_body),
        analyze_cache_exposure(target_url, response_headers, html_body),
    ]

    domain_names = [
        "Web Security Config", "Auth/Session Security", "API Exposure",
        "JS Secret Detection", "Source Map Exposure", "Sensitive Files",
        "Cloud Storage", "DNS Intelligence", "TLS Deep Analysis",
        "Mixed Content", "Third-Party SRI", "Cache Exposure",
    ]

    results = await asyncio.gather(*domain_coros, return_exceptions=True)
    all_findings: list = []
    for result, name in zip(results, domain_names):
        if isinstance(result, Exception):
            logger.warning(f"ExposureDetector domain '{name}' raised: {result}")
        elif isinstance(result, list):
            all_findings.extend(result)

    return all_findings
