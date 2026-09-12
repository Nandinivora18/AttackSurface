"""
HTTP Security Header Analyzer
Fetches actual HTTP response headers and evaluates the presence,
correctness, and configuration of all standard security headers.

False-Positive Policy
---------------------
1. HSTS is only meaningful on HTTPS — suppressed for plain-HTTP targets.
2. HTML-only headers (CSP, XFO, X-XSS-Protection, COEP) are only checked
   when the response Content-Type is text/html. JSON/XML API endpoints are
   excluded — missing browser-rendering directives on a JSON API is not a
   vulnerability.
3. X-Frame-Options is suppressed when CSP already contains frame-ancestors,
   since frame-ancestors is the modern W3C replacement and takes precedence
   in all modern browsers.
4. CSP wildcard detection uses word-boundary regex — 'script-src *.example.com'
   is a subdomain whitelist, not a full wildcard, and must NOT be flagged.
5. Server header benign-list covers all major CDN/proxy vendors so that
   CDN-assigned values don't trigger spurious version-disclosure findings.
"""
import re
from typing import Any
import httpx
import logging

logger = logging.getLogger(__name__)

SECURITY_HEADERS_SPEC = {
    "strict-transport-security": {
        "name": "HTTP Strict Transport Security (HSTS)",
        "category": "Transport Security",
        "missing_severity": "high",
        "missing_cvss": 6.5,
        "html_only": False,  # Applies to all content types over HTTPS
        "description": "HSTS forces browsers to use HTTPS for all future requests, preventing SSL stripping attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
    },
    "content-security-policy": {
        "name": "Content Security Policy (CSP)",
        "category": "Injection Prevention",
        "missing_severity": "high",
        "missing_cvss": 6.1,
        "html_only": True,  # Only meaningful for HTML documents
        "description": "CSP restricts which resources can be loaded, preventing XSS and data injection attacks.",
        "recommendation": "Implement a strict CSP policy. Start with: Content-Security-Policy: default-src 'self'",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "category": "Clickjacking Protection",
        "missing_severity": "medium",
        "missing_cvss": 4.3,
        "html_only": True,  # Only meaningful for HTML documents
        "description": "Prevents the page from being embedded in iframes, protecting against clickjacking attacks.",
        "recommendation": "Add: X-Frame-Options: DENY (or SAMEORIGIN if framing is needed from same origin)",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "category": "MIME Sniffing Prevention",
        "missing_severity": "low",
        "missing_cvss": 3.1,
        "html_only": False,  # Applies to all responses (browsers sniff MIME on any response)
        "description": "Prevents browsers from MIME-sniffing the content type, reducing drive-by download risk.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "category": "Privacy",
        "missing_severity": "low",
        "missing_cvss": 2.6,
        "html_only": False,
        "description": "Controls how much referrer information is sent with requests, protecting user privacy.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "category": "Feature Control",
        "missing_severity": "low",
        "missing_cvss": 2.1,
        "html_only": True,  # Only controls browser features in HTML contexts
        "description": "Controls access to browser features (camera, microphone, geolocation) for the page and iframes.",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "category": "XSS Protection (Legacy)",
        "missing_severity": "info",
        "missing_cvss": 0.0,
        "html_only": True,  # Browser XSS filter — HTML only
        "description": "Legacy XSS filter for older browsers. Modern browsers use CSP instead.",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block (or rely on CSP for modern browsers)",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"],
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy (COOP)",
        "category": "Isolation",
        "missing_severity": "low",
        "missing_cvss": 2.5,
        "html_only": True,
        "description": "Isolates browsing context from cross-origin windows, preventing Spectre-style attacks.",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"],
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy (COEP)",
        "category": "Isolation",
        "missing_severity": "info",
        "missing_cvss": 0.0,
        "html_only": True,
        "description": "Requires opt-in from all embedded cross-origin resources, enabling high-resolution timers safely.",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"],
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy (CORP)",
        "category": "Isolation",
        "missing_severity": "info",
        "missing_cvss": 0.0,
        "html_only": False,
        "description": "Controls which origins can read the response using no-cors fetches.",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"],
    },
}


def _is_html_response(content_type: str, body_preview: str) -> bool:
    """Determine whether the response is an HTML document."""
    ct = content_type.lower()
    if "text/html" in ct:
        return True
    # Fallback: inspect first 512 bytes for HTML markers (handles missing/wrong CT)
    preview = body_preview[:512].lower()
    return "<!doctype html" in preview or "<html" in preview


def _analyze_hsts(value: str) -> list[dict]:
    issues = []
    if not value or not str(value).strip():
        return issues
    lower = value.lower()
    if "max-age" not in lower:
        issues.append({"severity": "high", "message": "HSTS header missing max-age directive"})
    else:
        try:
            max_age = int([p for p in lower.split(";") if "max-age" in p][0].split("=")[1].strip())
            if max_age < 15768000:
                issues.append({"severity": "medium", "message": f"HSTS max-age too short ({max_age}s). Recommended: 31536000"})
        except (IndexError, ValueError):
            issues.append({"severity": "low", "message": "HSTS max-age could not be parsed"})
    if "includesubdomains" not in lower:
        # Downgraded to info: includeSubDomains is optional and may be intentionally
        # omitted when the organisation has subdomains it does not fully control.
        issues.append({"severity": "info", "message": "HSTS missing includeSubDomains directive (optional — omit if subdomains are not fully managed)"})
    if "preload" not in lower:
        issues.append({"severity": "info", "message": "HSTS missing preload directive (required for HSTS preload list)"})
    return issues


# ── CSP wildcard detection ────────────────────────────────────────────────────
# These patterns match a STANDALONE '*' token in the directive value, i.e.:
#   script-src *          — matches (full wildcard — policy is ineffective)
#   default-src *         — matches
#   script-src *.cdn.com  — does NOT match (subdomain whitelist — legitimate)
#
# The regex uses negative lookahead (?![.\w]) to ensure '*' is not immediately
# followed by a dot or word character (which would indicate a glob like *.foo.com).
_CSP_WILDCARD_SCRIPT = re.compile(r'\bscript-src\s+[^;]*(?<![.\w])\*(?![.\w])', re.IGNORECASE)
_CSP_WILDCARD_DEFAULT = re.compile(r'\bdefault-src\s+[^;]*(?<![.\w])\*(?![.\w])', re.IGNORECASE)


def _analyze_csp(value: str) -> list[dict]:
    issues = []
    lower = value.lower()

    # unsafe-inline in script-src or default-src
    if "'unsafe-inline'" in lower:
        issues.append({"severity": "high", "message": "CSP allows 'unsafe-inline' scripts — XSS protection bypassed"})
    if "'unsafe-eval'" in lower:
        issues.append({"severity": "medium", "message": "CSP allows 'unsafe-eval' — code injection risk"})

    # Full wildcard check — standalone * only, not *.example.com
    if _CSP_WILDCARD_DEFAULT.search(value) or _CSP_WILDCARD_SCRIPT.search(value):
        issues.append({"severity": "high", "message": "CSP uses a full wildcard (*) in default-src or script-src — policy is effectively disabled"})

    if "default-src" not in lower:
        issues.append({"severity": "medium", "message": "CSP missing default-src fallback directive"})

    return issues


def _csp_has_frame_ancestors(csp_value: str) -> bool:
    """Return True if the CSP header contains a frame-ancestors directive."""
    return bool(re.search(r'\bframe-ancestors\b', csp_value, re.IGNORECASE))


def _analyze_cors(headers: dict) -> list[dict]:
    issues = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*":
        if acac == "true":
            # This is an actively exploitable misconfiguration.
            # Both header values are embedded in the finding so the evidence chain
            # is complete and the finding can be independently verified.
            issues.append({
                "severity": "critical",
                "message": "CORS misconfiguration: Access-Control-Allow-Origin: * combined with credentials=true is a critical security flaw",
                "cvss": 9.1,
                # Store both values for use in the evidence field at call site
                "_acao": acao,
                "_acac": headers.get("access-control-allow-credentials", ""),
            })
        else:
            # ACAO: * without credentials is acceptable for public APIs — report as info only
            issues.append({"severity": "info", "message": "CORS allows all origins (*) — acceptable for public APIs, verify this is intentional"})
    elif acao and acao != "null":
        issues.append({"severity": "info", "message": f"CORS allows specific origin: {acao}"})
    return issues


def _check_server_disclosure(headers: dict) -> list[dict]:
    """
    Check Server, X-Powered-By, and X-AspNet-Version headers for version disclosure.

    Version disclosure is only reported when the header value matches a clear
    software/version pattern such as:
        Apache/2.4.58    nginx/1.26.1    OpenResty/1.25.3.1    IIS/10.0
    Format: <word>/<digits>  (at least one digit component after the slash)

    A plain hostname like 'github.com' does NOT match this pattern and will be
    reported as a lower-severity software name disclosure instead, not version
    disclosure.  This prevents false positives on load-balancers and CDNs that
    use their own hostname as the Server header value.

    CDN / proxy servers that set their own Server header are silently skipped —
    they are informational infrastructure headers, not version disclosures.
    """
    import re

    # Matches: SoftwareName/1  SoftwareName/1.2  SoftwareName/1.2.3.4
    _VERSION_PATTERN = re.compile(r"\w[\w\-]*/\d[\d.]*", re.IGNORECASE)

    # Server header values that are intentionally generic / non-revealing.
    # These are silently skipped (no finding emitted).
    # Includes exact values AND prefix patterns for CDN edge nodes (e.g. "ECS (fra/...)").
    _BENIGN_EXACT = {
        "", "cloudflare", "awselb/2.0", "aws", "google frontend",
        "jsdelivr", "netlify", "vercel", "fastly", "akamai",
        "zendesk", "squarespace", "wix", "shopify", "sucuri/cloudproxy",
        "amazons3", "amazoncf", "amazondax",
    }
    # Prefix patterns for CDN edge node identifiers like "ECS (fra/279C)" or "AkamaiGHost"
    _BENIGN_PREFIXES = (
        "ecs ", "ecs(", "akamaiGhost", "akamaighost",
        "awselb", "cloudfront", "sucuri", "imperva",
    )

    issues = []
    server = headers.get("server", "").strip()
    x_powered = headers.get("x-powered-by", "").strip()
    x_aspnet = headers.get("x-aspnet-version", "").strip()

    if server:
        server_lower = server.lower()
        is_benign_exact = server_lower in _BENIGN_EXACT
        is_benign_prefix = any(server_lower.startswith(p.lower()) for p in _BENIGN_PREFIXES)

        if not is_benign_exact and not is_benign_prefix:
            if _VERSION_PATTERN.search(server):
                # Contains a clear product/version string → medium severity
                issues.append({
                    "severity": "medium",
                    "message": f"Server header discloses version: '{server}' — version information should be removed",
                    "cvss": 5.3,
                })
            else:
                # Discloses software name only (no version) → low severity
                issues.append({
                    "severity": "low",
                    "message": f"Server header discloses software: '{server}'",
                    "cvss": 3.1,
                })

    if x_powered:
        issues.append({
            "severity": "medium",
            "message": f"X-Powered-By header discloses technology: '{x_powered}' — this header should be removed",
            "cvss": 5.3,
        })

    if x_aspnet:
        issues.append({
            "severity": "medium",
            "message": f"X-AspNet-Version header discloses framework version: '{x_aspnet}'",
            "cvss": 5.3,
        })

    return issues


async def analyze_headers(url: str) -> dict[str, Any]:
    """
    Analyze HTTP security response headers for a given URL.

    Standards reviewed:
      - OWASP Secure Headers Project (https://owasp.org/www-project-secure-headers/)
      - Mozilla Observatory grading methodology
      - RFC 6797 (HSTS)
      - RFC 7034 (X-Frame-Options)
      - RFC 7230 §7.1.4 (Server header)
      - W3C CSP Level 3
      - W3C Permissions Policy
      - W3C CORS (https://fetch.spec.whatwg.org/)
      - OWASP ASVS v4.0 Chapter 14 (HTTP Security Controls)
    """
    findings = []
    raw_headers: dict[str, str] = {}
    header_grades: dict[str, str] = {}

    try:
        from app.utils.safe_http import SafeFetchClient
        async with SafeFetchClient(
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (SentinelScan Security Scanner / Educational)"},
        ) as client:
            response = await client.get(url)
            raw_headers = dict(response.headers)
            headers_lower = {k.lower(): v for k, v in response.headers.items()}

            # ── Content-type awareness ────────────────────────────────────────
            # HTML-only headers (CSP, XFO, etc.) are only meaningful when the
            # response serves an HTML document. JSON/XML API endpoints are excluded.
            content_type = headers_lower.get("content-type", "")
            is_html = _is_html_response(content_type, response.text)

            # ── Retrieve CSP value early (needed for frame-ancestors check) ───
            csp_value = headers_lower.get("content-security-policy", "")

            # Check each required security header
            for header_key, spec in SECURITY_HEADERS_SPEC.items():
                header_value = headers_lower.get(header_key)

                # Skip HTML-only headers for non-HTML responses
                if spec.get("html_only") and not is_html:
                    header_grades[header_key] = "not_applicable"
                    continue

                # Special case: X-Frame-Options is redundant when CSP frame-ancestors is present
                # Ref: W3C CSP Level 3 §8.4 — frame-ancestors supersedes X-Frame-Options
                if header_key == "x-frame-options" and csp_value and _csp_has_frame_ancestors(csp_value):
                    header_grades[header_key] = "superseded_by_csp"
                    findings.append({
                        "category": spec["category"],
                        "title": "X-Frame-Options Superseded by CSP frame-ancestors",
                        "description": (
                            "The site uses CSP frame-ancestors to control framing, which is the "
                            "modern W3C replacement for X-Frame-Options. All modern browsers respect "
                            "frame-ancestors over XFO. No action required."
                        ),
                        "severity": "info",
                        "cvss_score": None,
                        "confidence": "high",
                        "recommendation": "Good. CSP frame-ancestors is the recommended approach.",
                        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"],
                        "evidence": f"CSP header contains frame-ancestors directive: {csp_value[:120]}",
                    })
                    continue

                is_missing = header_value is None or (isinstance(header_value, str) and not header_value.strip())

                if is_missing:
                    # HSTS is only meaningful on HTTPS sites (RFC 6797 §8.1)
                    effective_severity = spec["missing_severity"]
                    if header_key == "strict-transport-security" and url.startswith("http://"):
                        effective_severity = "info"  # suppressed — covered by No HTTPS redirect

                    findings.append({
                        "category": spec["category"],
                        "title": f"Missing {spec['name']}",
                        "description": spec["description"],
                        "severity": effective_severity,
                        "cvss_score": spec["missing_cvss"] if effective_severity != "info" else 0.0,
                        "confidence": "high",
                        "recommendation": spec["recommendation"],
                        "references": spec["references"],
                        "evidence": (
                            f"Header '{header_key}' not present in response"
                            if header_value is None
                            else f"Header '{header_key}' present with empty value in response"
                        ),
                    })
                    header_grades[header_key] = "missing"
                else:
                    header_grades[header_key] = "present"
                    # Deeper analysis for certain headers
                    extra_issues = []
                    if header_key == "strict-transport-security":
                        extra_issues = _analyze_hsts(header_value)
                    elif header_key == "content-security-policy":
                        extra_issues = _analyze_csp(header_value)

                    for issue in extra_issues:
                        findings.append({
                            "category": spec["category"],
                            "title": issue["message"],
                            "description": f"Misconfigured {spec['name']} header",
                            "severity": issue["severity"],
                            "cvss_score": issue.get("cvss"),
                            "confidence": "high",
                            "recommendation": spec["recommendation"],
                            "references": spec["references"],
                            "evidence": f"{header_key}: {header_value}",
                        })

            # CORS analysis
            # Ref: W3C CORS §3.2.2; OWASP ASVS 14.5.3; CWE-346
            cors_issues = _analyze_cors(headers_lower)
            for issue in cors_issues:
                # For the critical CORS misconfiguration, build evidence from both headers
                _acao_val = issue.pop("_acao", None)
                _acac_val = issue.pop("_acac", None)
                if _acao_val is not None:
                    evidence_str = (
                        f"Access-Control-Allow-Origin: {_acao_val}\n"
                        f"Access-Control-Allow-Credentials: {_acac_val}\n"
                        "Both headers together allow any origin to read credentialed "
                        "responses — an actively exploitable CORS misconfiguration."
                    )
                else:
                    evidence_str = f"access-control-allow-origin: {headers_lower.get('access-control-allow-origin', 'not set')}"
                findings.append({
                    "category": "CORS",
                    "title": issue["message"],
                    "description": "Cross-Origin Resource Sharing (CORS) policy evaluation",
                    "severity": issue["severity"],
                    "cvss_score": issue.get("cvss"),
                    "confidence": "high",
                    "recommendation": "Set Access-Control-Allow-Origin to a specific trusted origin instead of '*'",
                    "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                    "evidence": evidence_str,
                })

            # Server/technology disclosure
            # Ref: RFC 7230 §7.1.4; OWASP ASVS 14.3.3; CWE-200
            server_issues = _check_server_disclosure(headers_lower)
            for issue in server_issues:
                findings.append({
                    "category": "Information Disclosure",
                    "title": issue["message"],
                    "description": "Server response headers reveal software versions or technology information.",
                    "severity": issue["severity"],
                    "cvss_score": issue.get("cvss"),
                    "confidence": "high",
                    "recommendation": "Configure your web server to suppress or modify version-revealing headers",
                    "references": ["https://owasp.org/www-project-secure-headers/"],
                    "evidence": f"server: {headers_lower.get('server', '')}; x-powered-by: {headers_lower.get('x-powered-by', '')}",
                })

            # Check for HTTP to HTTPS redirect
            if url.startswith("http://"):
                if str(response.url).startswith("https://"):
                    findings.append({
                        "category": "Transport Security",
                        "title": "HTTP to HTTPS redirect in place",
                        "description": "The server correctly redirects HTTP traffic to HTTPS.",
                        "severity": "info",
                        "cvss_score": None,
                        "recommendation": "Good. Ensure HSTS is also configured.",
                        "references": [],
                        "evidence": f"Redirected from {url} to {response.url}",
                    })
                else:
                    findings.append({
                        "category": "Transport Security",
                        "title": "No HTTPS redirect — site accessible over plain HTTP",
                        "description": "The site serves content over insecure HTTP without redirecting to HTTPS.",
                        "severity": "high",
                        "cvss_score": 7.5,
                        "recommendation": "Configure your web server to redirect all HTTP traffic to HTTPS (301)",
                        "references": ["https://web.dev/uses-https/"],
                        "evidence": f"GET {url} returned HTTP {response.status_code} without redirect",
                    })

        # Calculate SecurityHeaders.com style grade
        headers_audit = []
        pass_count = 0
        total_headers = len(SECURITY_HEADERS_SPEC)

        for h_key, spec in SECURITY_HEADERS_SPEC.items():
            grade_status = header_grades.get(h_key)
            curr_val = raw_headers.get(h_key)

            if grade_status == "not_applicable":
                total_headers -= 1  # Don't count inapplicable headers
                continue
            if grade_status == "superseded_by_csp":
                pass_count += 1
                headers_audit.append({
                    "header": spec["name"],
                    "key": h_key,
                    "current_value": "Superseded by CSP frame-ancestors",
                    "expected_value": "N/A — CSP frame-ancestors in use",
                    "risk": "Low / Secure",
                    "recommendation": "CSP frame-ancestors provides equivalent protection.",
                    "grade": "PASS",
                })
            elif curr_val and str(curr_val).strip():
                pass_count += 1
                headers_audit.append({
                    "header": spec["name"],
                    "key": h_key,
                    "current_value": curr_val,
                    "expected_value": spec["recommendation"].replace("Add: ", "").replace("Implement a strict CSP policy. Start with: ", ""),
                    "risk": "Low / Secure",
                    "recommendation": "Configured correctly. Monitor for policy updates.",
                    "grade": "PASS",
                })
            else:
                headers_audit.append({
                    "header": spec["name"],
                    "key": h_key,
                    "current_value": "Missing / Not Set" if curr_val is None else "Empty / Invalid",
                    "expected_value": spec["recommendation"].replace("Add: ", "").replace("Implement a strict CSP policy. Start with: ", ""),
                    "risk": f"{spec['missing_severity'].capitalize()} Risk",
                    "recommendation": spec["recommendation"],
                    "grade": "FAIL" if spec["missing_severity"] in ("high", "critical") else "WARN",
                })

        overall_header_score = round((pass_count / max(total_headers, 1)) * 100)
        header_grade = "A+" if overall_header_score >= 90 else "A" if overall_header_score >= 75 else "B" if overall_header_score >= 60 else "C" if overall_header_score >= 45 else "D" if overall_header_score >= 30 else "F"

        return {
            "findings": findings,
            "raw_headers": raw_headers,
            "headers": headers_lower,
            "cookies": response.headers.get_list("set-cookie"),
            "headers_audit": headers_audit,
            "overall_header_score": overall_header_score,
            "header_grade": header_grade,
        }
    except httpx.ConnectError:
        findings.append({
            "category": "Connectivity",
            "title": "Could not connect to target",
            "description": "The scanner was unable to establish a connection to the target URL.",
            "severity": "info",
            "cvss_score": None,
            "recommendation": "Verify the URL is accessible and the server is running.",
            "references": [],
            "evidence": f"Connection refused or DNS resolution failed for {url}",
        })
        return {"findings": findings, "raw_headers": {}, "headers": {}, "cookies": [], "headers_audit": [], "overall_header_score": 0, "header_grade": "F"}
    except httpx.TimeoutException:
        findings.append({
            "category": "Connectivity",
            "title": "Connection timed out",
            "description": "The server did not respond within the timeout period.",
            "severity": "info",
            "cvss_score": None,
            "recommendation": "Check server availability.",
            "references": [],
            "evidence": f"Timeout after 15 seconds connecting to {url}",
        })
        return {"findings": findings, "raw_headers": {}, "headers": {}, "cookies": [], "headers_audit": [], "overall_header_score": 0, "header_grade": "F"}
    except Exception as e:
        logger.error(f"Header analysis error for {url}: {e}")
        return {"findings": findings, "raw_headers": {}, "headers": {}, "cookies": [], "headers_audit": [], "overall_header_score": 0, "header_grade": "F"}


# ─────────────────────────────────────────────────────────────────────────────
# Public test-surface wrapper
# ─────────────────────────────────────────────────────────────────────────────

def _check_server_version_disclosure(server_value: str) -> dict | None:
    """
    Testable single-value wrapper: given a Server header string, returns the
    first finding dict if version disclosure is detected, or None if safe.

    This exposes the core version-detection heuristic as a named, testable
    function so benchmark/regression tests can call it in isolation without
    needing to build a full headers dict or run a live HTTP request.

    Rationale for what triggers a finding:
      - 'Apache/2.4.51' → finding (version string present)
      - 'nginx/1.20.1'  → finding (version string present)
      - 'nginx'         → None (vendor name only — no version; FP regression)
      - 'cloudflare'    → None (CDN banner in benign allowlist)
      - 'Apache'        → None (vendor name only; FP regression)

    Standard: RFC 7230 §7.1.4 recommends against disclosing detailed version
    information in the Server header. OWASP ASVS 14.3.3 requires suppression.
    CWE-200: Exposure of Sensitive Information to an Unauthorized Actor.
    """
    issues = _check_server_disclosure({"server": server_value})
    # Filter to only version-disclosure findings (medium+), not name-only disclosures
    version_issues = [
        i for i in issues
        if "version" in i.get("message", "").lower() and i.get("severity") in ("medium", "high", "critical")
    ]
    return version_issues[0] if version_issues else None

