"""
Technology and CMS Fingerprinting
Analyzes HTTP headers, HTML content, meta tags, script/link tags,
and cookie names to identify the technology stack with confidence scoring.

False-Positive Policy
---------------------
Every pattern must have a specific, unambiguous signal.
Generic class names (flex, grid, container), tokens shared across frameworks,
and patterns that cannot distinguish the target technology from others are
NOT included regardless of how widely the technology is used.
"""
import re
from typing import Any
import httpx
from bs4 import BeautifulSoup
import logging

logger = logging.getLogger(__name__)

# Signature database: {tech_name: {category, patterns: [{source, pattern, confidence}]}}
#
# Confidence scale (60 = detection threshold):
#   99 — definitive (dedicated header, unique token with no other user)
#   90 — highly specific (meta generator, unique cookie name)
#   80 — specific (file path unique to the framework)
#   70 — probable (URL extension, known cookie with caveats)
#   60 — possible (pattern shared by a small set of techs)
#  <60 — suppressed (too ambiguous to report)
TECH_SIGNATURES: dict[str, dict] = {
    "WordPress": {
        "category": "CMS",
        "icon": "wordpress",
        "patterns": [
            # wp-content/ and wp-includes/ are unique to WordPress
            {"source": "html", "pattern": r"wp-content/", "confidence": 90},
            {"source": "html", "pattern": r"wp-includes/", "confidence": 90},
            # X-Powered-By: WordPress is definitive
            {"source": "header_x-powered-by", "pattern": r"WordPress", "confidence": 95},
            # Generator meta tag is definitive
            {"source": "html", "pattern": r'<meta name="generator" content="WordPress', "confidence": 95},
            # wordpress_ cookie prefix is unique to WordPress
            {"source": "cookie", "pattern": r"wordpress_", "confidence": 85},
        ],
        "version_pattern": r'<meta name="generator" content="WordPress ([0-9.]+)"',
    },
    "Drupal": {
        "category": "CMS",
        "icon": "drupal",
        "patterns": [
            {"source": "html", "pattern": r"/sites/default/files/", "confidence": 85},
            {"source": "html", "pattern": r'<meta name="Generator" content="Drupal', "confidence": 95},
            {"source": "header_x-generator", "pattern": r"Drupal", "confidence": 95},
            # SESS[hex] is the Drupal session cookie naming convention
            {"source": "cookie", "pattern": r"SESS[a-f0-9]{32}", "confidence": 75},
        ],
        "version_pattern": r'Drupal ([0-9]+)',
    },
    "Joomla": {
        "category": "CMS",
        "icon": "joomla",
        "patterns": [
            # /media/jui/ and /components/com_* are Joomla-specific paths
            {"source": "html", "pattern": r"/media/jui/", "confidence": 85},
            {"source": "html", "pattern": r"/components/com_", "confidence": 80},
            {"source": "html", "pattern": r'<meta name="generator" content="Joomla', "confidence": 95},
        ],
        "version_pattern": r'Joomla! ([0-9.]+)',
    },
    "Shopify": {
        "category": "E-Commerce",
        "icon": "shopify",
        "patterns": [
            # cdn.shopify.com is definitive — only Shopify serves from this CDN
            {"source": "html", "pattern": r"cdn\.shopify\.com", "confidence": 95},
            {"source": "header_x-shopify-stage", "pattern": r".*", "confidence": 95},
            {"source": "cookie", "pattern": r"_shopify_", "confidence": 90},
        ],
    },
    "Magento": {
        "category": "E-Commerce",
        "icon": "magento",
        "patterns": [
            # Mage.Cookies and /skin/frontend/ are Magento-specific
            {"source": "html", "pattern": r"Mage\.Cookies", "confidence": 90},
            {"source": "html", "pattern": r"/skin/frontend/", "confidence": 85},
            # frontend= cookie is used by Magento 1.x — moderately specific
            {"source": "cookie", "pattern": r"frontend=", "confidence": 70},
        ],
    },
    "React": {
        "category": "JavaScript Framework",
        "icon": "react",
        "patterns": [
            # react.js script reference is specific enough
            {"source": "html", "pattern": r"react(?:\.min)?\.js", "confidence": 80},
            # data-reactroot is added by React's server-side rendering
            {"source": "html", "pattern": r"data-reactroot", "confidence": 90},
            # __REACT_DEVTOOLS_GLOBAL_HOOK__ is injected by React in development builds
            {"source": "html", "pattern": r"__REACT_DEVTOOLS_GLOBAL_HOOK__", "confidence": 85},
            # NOTE: _next/static is intentionally EXCLUDED — it is a Next.js
            # signal, not a generic React signal. Next.js detects itself below.
        ],
    },
    "Next.js": {
        "category": "JavaScript Framework",
        "icon": "nextjs",
        "patterns": [
            # _next/static is the Next.js CDN asset path — definitive
            {"source": "html", "pattern": r"_next/static", "confidence": 95},
            {"source": "header_x-powered-by", "pattern": r"Next\.js", "confidence": 99},
            # __NEXT_DATA__ is the hydration script injected by Next.js SSR
            {"source": "html", "pattern": r"__NEXT_DATA__", "confidence": 95},
        ],
    },
    "Vue.js": {
        "category": "JavaScript Framework",
        "icon": "vue",
        "patterns": [
            {"source": "html", "pattern": r"vue(?:\.min)?\.js", "confidence": 80},
            # data-v-[hex] are Vue.js scoped CSS attribute markers
            {"source": "html", "pattern": r"data-v-[0-9a-f]{7,8}", "confidence": 85},
            # __vue_app__ is Vue 3's global instance identifier
            {"source": "html", "pattern": r"__vue_app__", "confidence": 90},
        ],
    },
    "Angular": {
        "category": "JavaScript Framework",
        "icon": "angular",
        "patterns": [
            # ng-version is injected by Angular on the root component element
            {"source": "html", "pattern": r"ng-version=", "confidence": 95},
            {"source": "html", "pattern": r"angular(?:\.min)?\.js", "confidence": 80},
            # [ng-app] is AngularJS (v1.x) specific
            {"source": "html", "pattern": r"\[ng-app\]", "confidence": 75},
        ],
    },
    "Nuxt.js": {
        "category": "JavaScript Framework",
        "icon": "nuxt",
        "patterns": [
            # _nuxt/ is the Nuxt.js asset path — definitive
            {"source": "html", "pattern": r"_nuxt/", "confidence": 95},
            # __NUXT__ is the hydration object injected by Nuxt SSR
            {"source": "html", "pattern": r"__NUXT__", "confidence": 95},
        ],
    },
    "jQuery": {
        "category": "JavaScript Library",
        "icon": "jquery",
        "patterns": [
            {"source": "html", "pattern": r"jquery(?:\.min)?\.js", "confidence": 80},
            # jquery-3.x.x.min.js filename with version is specific
            {"source": "html", "pattern": r"jquery-([0-9.]+)", "confidence": 85},
        ],
        "version_pattern": r"jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)",
    },
    "Bootstrap": {
        "category": "CSS Framework",
        "icon": "bootstrap",
        "patterns": [
            # bootstrap.min.css / bootstrap.min.js filenames are specific
            {"source": "html", "pattern": r"bootstrap(?:\.min)?\.css", "confidence": 80},
            {"source": "html", "pattern": r"bootstrap(?:\.min)?\.js", "confidence": 80},
            # NOTE: class="container" and class="navbar" are intentionally EXCLUDED.
            # These class names are used by Bulma, Foundation, custom CSS, and dozens
            # of other frameworks — they cannot uniquely identify Bootstrap.
        ],
        "version_pattern": r"bootstrap[/-]([0-9]+\.[0-9]+\.[0-9]+)",
    },
    "Tailwind CSS": {
        "category": "CSS Framework",
        "icon": "tailwind",
        "patterns": [
            # The literal string 'tailwindcss' in a script/link is definitive
            {"source": "html", "pattern": r"tailwindcss", "confidence": 85},
            # NOTE: class="flex", class="grid", class="text-blue-500" etc. are
            # intentionally EXCLUDED. 'flex' and 'grid' are native CSS display
            # values widely used as class names in custom stylesheets. The
            # color/size pattern is also used by other utility frameworks.
            # Reporting Tailwind without a clear file reference creates false positives.
        ],
    },
    "Nginx": {
        "category": "Web Server",
        "icon": "nginx",
        "patterns": [
            # Server: nginx is definitive — masked by Cloudflare/CDNs (handled in detect_technologies)
            {"source": "header_server", "pattern": r"nginx", "confidence": 99},
        ],
        "version_pattern": r"nginx/([0-9.]+)",
    },
    "Apache": {
        "category": "Web Server",
        "icon": "apache",
        "patterns": [
            {"source": "header_server", "pattern": r"Apache", "confidence": 99},
        ],
        "version_pattern": r"Apache/([0-9.]+)",
    },
    "IIS": {
        "category": "Web Server",
        "icon": "iis",
        "patterns": [
            {"source": "header_server", "pattern": r"Microsoft-IIS", "confidence": 99},
        ],
        "version_pattern": r"Microsoft-IIS/([0-9.]+)",
    },
    "Cloudflare": {
        "category": "CDN / Proxy",
        "icon": "cloudflare",
        "patterns": [
            {"source": "header_server", "pattern": r"cloudflare", "confidence": 99},
            # cf-ray header is always present on Cloudflare-proxied responses
            {"source": "header_cf-ray", "pattern": r".*", "confidence": 99},
        ],
    },
    "PHP": {
        "category": "Programming Language",
        "icon": "php",
        "patterns": [
            # X-Powered-By: PHP/x.y.z is definitive and includes version
            {"source": "header_x-powered-by", "pattern": r"PHP/([0-9.]+)", "confidence": 99},
            # .php URL extension is a moderate signal
            {"source": "url", "pattern": r"\.php", "confidence": 70},
            # PHPSESSID is unique to PHP's native session handling
            {"source": "cookie", "pattern": r"PHPSESSID", "confidence": 90},
        ],
        "version_pattern": r"PHP/([0-9.]+)",
    },
    "Django": {
        "category": "Web Framework",
        "icon": "django",
        "patterns": [
            # csrftoken is Django's default CSRF cookie, but Flask-WTF, custom
            # CSRF implementations, and some Rails configurations use the same name.
            # Confidence is 55 — BELOW the detection threshold (60) — so csrftoken
            # alone does NOT report Django. This prevents false positives on
            # non-Django sites that happen to use a cookie named 'csrftoken'.
            # Django is only reliably detectable when a stronger/additional signal
            # is present (e.g. X-Django-Debug header in debug mode, or Django's
            # DjangoSession cookie variant). Passive scanning cannot distinguish
            # Django from Flask-WTF on cookie names alone.
            {"source": "cookie", "pattern": r"^csrftoken$", "confidence": 55},
            # sessionid is Django's default session cookie, but it is also a common
            # name in other frameworks. Confidence 55 — same rationale as above.
            {"source": "cookie", "pattern": r"^sessionid$", "confidence": 55},
        ],
    },
    "Laravel": {
        "category": "Web Framework",
        "icon": "laravel",
        "patterns": [
            # laravel_session is the definitive Laravel session cookie name
            {"source": "cookie", "pattern": r"laravel_session", "confidence": 95},
            # XSRF-TOKEN is intentionally set to confidence 50 (BELOW the 60 threshold).
            # Angular's HttpClient also automatically sets XSRF-TOKEN for CSRF protection.
            # Standalone XSRF-TOKEN cannot distinguish Laravel from Angular SPAs.
            # This pattern is kept as a record but will NOT trigger detection alone.
            {"source": "cookie", "pattern": r"XSRF-TOKEN", "confidence": 50},
        ],
    },
    "ASP.NET": {
        "category": "Web Framework",
        "icon": "dotnet",
        "patterns": [
            {"source": "header_x-powered-by", "pattern": r"ASP\.NET", "confidence": 99},
            {"source": "header_x-aspnet-version", "pattern": r".*", "confidence": 99},
            # ASP.NET_SessionId is the definitive ASP.NET session cookie name
            {"source": "cookie", "pattern": r"ASP\.NET_SessionId", "confidence": 95},
        ],
        "version_pattern": r"ASP\.NET Version:([0-9.]+)",
    },
    "Wix": {
        "category": "Website Builder",
        "icon": "wix",
        "patterns": [
            {"source": "html", "pattern": r"static\.wixstatic\.com", "confidence": 99},
            {"source": "html", "pattern": r"wixsite\.com", "confidence": 95},
        ],
    },
    "Squarespace": {
        "category": "Website Builder",
        "icon": "squarespace",
        "patterns": [
            {"source": "html", "pattern": r"static1\.squarespace\.com", "confidence": 99},
            {"source": "header_server", "pattern": r"Squarespace", "confidence": 99},
        ],
    },
}

# Known vulnerable versions database (simplified passive supplement — cve_checker.py performs live NVD lookups)
# Source: NVD CVE data at https://nvd.nist.gov/vuln/detail/<CVE-ID>
# All version thresholds are "version_lt" (exclusive upper bound for vulnerable range).
# Only included when a reliable version string is passively extractable from HTTP headers/HTML.
VULNERABLE_VERSIONS: dict[str, list[dict]] = {
    "WordPress": [
        # CVE-2024-6386: CVSS 9.9 — Template injection RCE in Gutenberg via mlp plugin
        {"version_lt": "6.4", "cve": "CVE-2024-6386", "severity": "high", "description": "Remote code execution via template injection"},
        # CVE-2023-5561: CVSS 5.3 — Username disclosure via REST API
        {"version_lt": "6.3", "cve": "CVE-2023-5561", "severity": "medium", "description": "Username disclosure via REST API"},
    ],
    "jQuery": [
        # CVE-2020-11022: CVSS 6.1 — XSS via HTML injection in jQuery.htmlPrefilter; fixed in 3.5.0
        {"version_lt": "3.5.0", "cve": "CVE-2020-11022", "severity": "medium", "description": "XSS via HTML injection in jQuery.htmlPrefilter"},
        # CVE-2019-11358: CVSS 6.1 — Prototype pollution via jQuery.extend; fixed in 3.4.0
        {"version_lt": "3.4.0", "cve": "CVE-2019-11358", "severity": "medium", "description": "Prototype pollution via jQuery.extend"},
    ],
    "Drupal": [
        # CVE-2024-45440: CVSS 5.3 — Info disclosure via URL traversal; fixed in 10.2.9 / 10.3.2
        {"version_lt": "10.2", "cve": "CVE-2024-45440", "severity": "medium", "description": "Information disclosure via URL traversal"},
        # CVE-2023-31250: CVSS 9.8 — Unsupported file upload bypass; fixed in 10.0.18 / 9.5.16
        {"version_lt": "9.5", "cve": "CVE-2023-31250", "severity": "critical", "description": "File upload bypass leading to code execution"},
    ],
    "Apache": [
        # CVE-2021-41773: CVSS 7.5 — Path traversal and RCE; Apache 2.4.49 only
        {"version_lt": "2.4.50", "cve": "CVE-2021-41773", "severity": "critical", "description": "Path traversal and potential RCE (Apache 2.4.49 only)"},
        # CVE-2021-42013: CVSS 9.8 — Improved path traversal bypass; fixed in 2.4.51
        {"version_lt": "2.4.51", "cve": "CVE-2021-42013", "severity": "critical", "description": "Path traversal bypass; fixed in Apache 2.4.51"},
        # CVE-2024-38475: CVSS 9.1 — URL encoding bypass in mod_rewrite; fixed in 2.4.60
        {"version_lt": "2.4.60", "cve": "CVE-2024-38475", "severity": "high", "description": "URL encoding bypass in mod_rewrite (mod_rewrite + mod_proxy)"},
    ],
    "PHP": [
        # CVE-2024-8929: CVSS 6.5 — MySQLi integer overflow; fixed in 8.1.31 / 8.2.26 / 8.3.14
        {"version_lt": "8.1.31", "cve": "CVE-2024-8929", "severity": "medium", "description": "MySQLi integer overflow in fetch_assoc"},
        # CVE-2024-2961: CVSS 9.4 — OOB write in iconv; fixed in 8.3.8 / 8.2.21 / 8.1.29
        {"version_lt": "8.1.29", "cve": "CVE-2024-2961", "severity": "high", "description": "Out-of-bounds write in iconv() with glibc; GLIBC-dependent"},
    ],
    "Nginx": [
        # CVE-2013-2028: CVSS 7.5 — Stack buffer overflow in chunked transfer encoding; < 1.4.1 / 1.5.0
        {"version_lt": "1.4.1", "cve": "CVE-2013-2028", "severity": "high", "description": "Stack buffer overflow in chunked transfer encoding handler"},
        # CVE-2022-41741: CVSS 7.8 — Memory corruption in ngx_http_mp4_module; < 1.23.2
        {"version_lt": "1.23.2", "cve": "CVE-2022-41741", "severity": "high", "description": "Memory corruption in ngx_http_mp4_module (if enabled)"},
    ],
    "IIS": [
        # CVE-2017-7269: CVSS 9.8 — Buffer overflow in WebDAV ScStoragePathFromUrl; IIS 6.0 (Windows 2003)
        {"version_lt": "7.0", "cve": "CVE-2017-7269", "severity": "critical", "description": "Buffer overflow in WebDAV ScStoragePathFromUrl (IIS 6.0 only)"},
        # CVE-2021-31166: CVSS 9.8 — HTTP Protocol Stack RCE; patched May 2021 Patch Tuesday
        {"version_lt": "10.0", "cve": "CVE-2021-31166", "severity": "critical", "description": "HTTP Protocol Stack remote code execution (IIS on Windows 10/2019 < May 2021 patches)"},
    ],
}

# Web server technology names — used to downgrade confidence when a CDN is detected
_WEB_SERVER_TECHS = {"Nginx", "Apache", "IIS"}


def normalize_version(version: str) -> str:
    """
    Strips non-numeric build/release suffixes from a version string for reliable comparison.

    Examples:
        '2.4.51-debian'  → '2.4.51'
        '8.2.26-0ubuntu1' → '8.2.26'
        '1.24.0-r0'     → '1.24.0'
        '6.4.0'         → '6.4.0'
    """
    import re as _re
    m = _re.match(r'^([0-9]+(?:\.[0-9]+)*)', version.strip())
    return m.group(1) if m else version


def _version_lt(detected_version: str, threshold: str) -> bool:
    """Returns True if detected_version < threshold (simple numeric comparison after normalization)."""
    try:
        def to_tuple(v: str):
            return tuple(int(x) for x in normalize_version(v).split(".")[:3])
        return to_tuple(detected_version) < to_tuple(threshold)
    except (ValueError, AttributeError):
        return False


async def detect_technologies(url: str) -> dict[str, Any]:
    detected: dict[str, dict] = {}
    findings = []

    try:
        from app.utils.safe_http import SafeFetchClient
        async with SafeFetchClient(
            timeout=15.0,
            headers={"User-Agent": "Mozilla/5.0 (SentinelScan Security Scanner / Educational)"},
        ) as client:
            response = await client.get(url)
            html_content = response.text
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            cookies_str = " ".join(
                f"{c}={response.cookies.get(c)}" for c in response.cookies.keys()
            )

            for tech_name, spec in TECH_SIGNATURES.items():
                max_confidence = 0
                detected_version: str | None = None

                for pattern_def in spec["patterns"]:
                    source = pattern_def["source"]
                    pat = pattern_def["pattern"]
                    confidence = pattern_def["confidence"]

                    target_text = ""
                    if source == "html":
                        target_text = html_content
                    elif source == "url":
                        target_text = str(response.url)
                    elif source.startswith("header_"):
                        header_name = source[7:]
                        target_text = headers_lower.get(header_name, "")
                    elif source == "cookie":
                        target_text = cookies_str

                    if target_text and re.search(pat, target_text, re.IGNORECASE):
                        max_confidence = max(max_confidence, confidence)

                        # Extract version if pattern exists
                        version_pat = spec.get("version_pattern")
                        if version_pat and not detected_version:
                            vm = re.search(version_pat, target_text, re.IGNORECASE)
                            if vm:
                                detected_version = vm.group(1)

                # Threshold: 60+ to report a technology
                if max_confidence >= 60:
                    # Normalise the detected version string (e.g. strip OS-specific build suffixes)
                    if detected_version:
                        detected_version = normalize_version(detected_version)

                    detected[tech_name] = {
                        "category": spec["category"],
                        "confidence": max_confidence,
                        "version": detected_version,
                        "icon": spec.get("icon", ""),
                    }

                    # Check for known vulnerabilities (only when version is confirmed)
                    if tech_name in VULNERABLE_VERSIONS and detected_version:
                        for vuln in VULNERABLE_VERSIONS[tech_name]:
                            if _version_lt(detected_version, vuln["version_lt"]):
                                findings.append({
                                    "category": "Outdated Software / CVE",
                                    "title": f"{tech_name} {detected_version} — {vuln['cve']}",
                                    "description": f"Detected {tech_name} version {detected_version} is affected by {vuln['cve']}: {vuln['description']}",
                                    "severity": vuln["severity"],
                                    "cvss_score": None,
                                    "confidence": "high",
                                    "recommendation": f"Update {tech_name} to the latest stable version immediately. Current: {detected_version}",
                                    "references": [f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}"],
                                    "evidence": f"Detected {tech_name} version {detected_version} via HTML/headers",
                                })

                    # Lifecycle / EOL assessment (only when version is confirmed)
                    if detected_version:
                        from app.scanner.lifecycle import get_lifecycle_status, build_lifecycle_finding
                        lc = get_lifecycle_status(tech_name, detected_version)
                        if lc:
                            lc_finding = build_lifecycle_finding(tech_name, detected_version, lc)
                            if lc_finding:
                                # Tag with lifecycle metadata for frontend display
                                lc_finding["lifecycle_status"] = lc["status"]
                                lc_finding["lifecycle_eol_date"] = lc.get("eol_date")
                                findings.append(lc_finding)

            # ── CDN / Proxy awareness ─────────────────────────────────────────────
            # If any CDN is detected, web server technology detected from response
            # headers (Nginx, Apache, IIS) may actually reflect the CDN's headers,
            # not the origin server. Downgrade web server confidence and add a note.
            cdn_detected = any(cdn in detected for cdn in (
                "Cloudflare", "Fastly", "Akamai",  # explicit CDN tech detections
            ))
            # Also check for CDN signals in response headers directly
            if not cdn_detected:
                via_header = headers_lower.get("via", "").lower()
                x_cache = headers_lower.get("x-cache", "").lower()
                cdn_detected = (
                    "cloudfront" in via_header or "cloudfront" in x_cache
                    or "varnish" in x_cache or "fastly" in x_cache
                    or "akamai" in via_header
                    or "vercel" in headers_lower.get("server", "").lower()
                    or "netlify" in headers_lower.get("server", "").lower()
                )
            if cdn_detected:
                for tech_name in _WEB_SERVER_TECHS:
                    if tech_name in detected:
                        detected[tech_name]["confidence"] = min(detected[tech_name]["confidence"], 60)
                        detected[tech_name]["cdn_note"] = (
                            "Cloudflare is active. This server header may reflect the CDN's "
                            "edge configuration rather than the origin server software."
                        )

            # Cookie analysis
            cookie_findings = _analyze_cookies(response)
            findings.extend(cookie_findings)

    except Exception as e:
        logger.error(f"Technology detection error for {url}: {e}")

    return {"detected_technologies": detected, "findings": findings}


def _analyze_cookies(response: httpx.Response) -> list[dict]:
    """
    Analyze cookie security attributes per-cookie by matching each Set-Cookie
    header to its corresponding cookie name.

    httpx stores multiple Set-Cookie headers separately. Using
    response.headers.get("set-cookie") returns only the FIRST header,
    causing incorrect flag analysis for later cookies. We use get_list() to
    retrieve all Set-Cookie headers and match each one by cookie name prefix.
    """
    findings = []

    # Collect all Set-Cookie header strings
    set_cookie_headers: list[str] = response.headers.get_list("set-cookie")

    # Build a map: cookie_name (lowercased) → raw Set-Cookie header string
    cookie_header_map: dict[str, str] = {}
    for raw_header in set_cookie_headers:
        # The cookie name is the part before the first '=' in the first segment
        first_segment = raw_header.split(";")[0].strip()
        if "=" in first_segment:
            name = first_segment.split("=", 1)[0].strip().lower()
            cookie_header_map[name] = raw_header

    for cookie_name in response.cookies.keys():
        cookie_name_lower = cookie_name.lower()

        # Find the matching Set-Cookie header for this cookie
        raw_cookie_header = cookie_header_map.get(cookie_name_lower, "")
        parts = [p.strip().lower() for p in raw_cookie_header.split(";")]

        is_secure = "secure" in parts
        is_httponly = "httponly" in parts
        samesite_val = next(
            (p.split("=", 1)[1].strip() if "=" in p else None
             for p in parts if p.startswith("samesite")),
            None,
        )

        is_session_cookie = any(
            kw in cookie_name_lower for kw in ["session", "sess", "auth", "token", "jwt", "login"]
        )

        # Evidence snippet: show the raw Set-Cookie header (truncated)
        evidence_header = raw_cookie_header[:200] if raw_cookie_header else f"Cookie: {cookie_name} (Set-Cookie header not found)"

        if is_session_cookie and not is_secure:
            findings.append({
                "category": "Cookie Security",
                "title": f"Session Cookie '{cookie_name}' Missing Secure Flag",
                "description": (
                    f"The session cookie '{cookie_name}' does not have the Secure flag set, "
                    "allowing it to be transmitted over unencrypted HTTP connections."
                ),
                "severity": "high",
                "cvss_score": 5.9,
                "confidence": "high",
                "recommendation": "Set the Secure flag on all session cookies: Set-Cookie: session=value; Secure; HttpOnly; SameSite=Strict",
                "references": ["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                "evidence": f"Cookie: {cookie_name} — missing Secure flag\nSet-Cookie: {evidence_header}",
            })

        if is_session_cookie and not is_httponly:
            findings.append({
                "category": "Cookie Security",
                "title": f"Session Cookie '{cookie_name}' Missing HttpOnly Flag",
                "description": (
                    f"Cookie '{cookie_name}' is accessible via JavaScript. "
                    "If an XSS vulnerability exists, this cookie can be stolen."
                ),
                "severity": "medium",
                "cvss_score": 4.7,
                "confidence": "high",
                "recommendation": "Add HttpOnly flag to all session cookies.",
                "references": ["https://owasp.org/www-community/HttpOnly"],
                "evidence": f"Cookie: {cookie_name} — missing HttpOnly flag\nSet-Cookie: {evidence_header}",
            })

        if is_session_cookie and samesite_val in (None, "none"):
            findings.append({
                "category": "Cookie Security",
                "title": f"Session Cookie '{cookie_name}' Missing SameSite Attribute",
                "description": (
                    f"Cookie '{cookie_name}' lacks SameSite attribute, making it "
                    "vulnerable to CSRF attacks."
                ),
                "severity": "medium",
                "cvss_score": 4.3,
                "confidence": "high",
                "recommendation": "Set SameSite=Strict or SameSite=Lax on session cookies.",
                "references": ["https://web.dev/samesite-cookies-explained/"],
                "evidence": f"Cookie: {cookie_name} — SameSite not set or 'None'\nSet-Cookie: {evidence_header}",
            })

    return findings
