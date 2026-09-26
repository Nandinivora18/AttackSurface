"""
Detector Metadata Registry
==========================
Central registry of every detector in SentinelScan.

Each entry documents:
  - id            Stable dot-namespaced identifier
  - version       Semver version of the detector implementation
  - author        Who wrote / owns this detector
  - category      Grouping for coverage reports and UI
  - description   One-line description of what the detector checks
  - standards     Authoritative references (RFC, OWASP, CWE, NIST…)
  - min_confidence  Minimum evidence reliability required to emit a finding
  - content_types   HTTP Content-Types this detector applies to
                   (None = applies to all)
  - owasp_top10   Primary OWASP Top 10 (2025) category

This registry is used to:
  1. Log detector inventory at scan startup for observability
  2. Validate that every emitted finding has a registered detector_id

Usage
-----
    from app.scanner.metadata import DETECTOR_REGISTRY, get_detector

    meta = get_detector("header.hsts.missing")
    print(meta["standards"])   # ['RFC 6797', 'OWASP ASVS 9.1.3']
"""
from __future__ import annotations
from typing import Any

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

DETECTOR_REGISTRY: dict[str, dict[str, Any]] = {

    # ── Security Headers ───────────────────────────────────────────────────
    "header.hsts.missing": {
        "id":           "header.hsts.missing",
        "version":      "2.1.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Checks for the absence of the Strict-Transport-Security (HSTS) response header on HTTPS targets.",
        "standards":    ["RFC 6797", "OWASP ASVS 9.1.3", "OWASP Secure Headers Project", "Mozilla Observatory"],
        "owasp_top10":  "A04",
        "min_confidence": 0.9,
        "content_types": None,  # applies to all HTTPS responses
    },
    "header.hsts.value": {
        "id":           "header.hsts.value",
        "version":      "2.1.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Validates HSTS max-age, includeSubDomains, and preload directives.",
        "standards":    ["RFC 6797 §6.1", "OWASP ASVS 9.1.3", "HSTS Preload List Requirements"],
        "owasp_top10":  "A04",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "header.csp.missing": {
        "id":           "header.csp.missing",
        "version":      "2.2.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Checks for the absence of Content-Security-Policy on HTML responses.",
        "standards":    ["W3C CSP Level 3", "OWASP ASVS 14.4.6", "Mozilla Observatory"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": ["text/html"],
    },
    "header.csp.value": {
        "id":           "header.csp.value",
        "version":      "2.2.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Validates CSP for unsafe-inline, unsafe-eval, and standalone wildcard (*) directives.",
        "standards":    ["W3C CSP Level 3 §4.2.1", "OWASP ASVS 14.4.6"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": ["text/html"],
    },
    "header.xfo.missing": {
        "id":           "header.xfo.missing",
        "version":      "2.0.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Checks for the absence of X-Frame-Options on HTML responses not covered by CSP frame-ancestors.",
        "standards":    ["RFC 7034", "OWASP ASVS 14.4.3"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": ["text/html"],
    },
    "header.xcto.missing": {
        "id":           "header.xcto.missing",
        "version":      "2.0.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Checks for the absence of X-Content-Type-Options: nosniff.",
        "standards":    ["OWASP ASVS 14.4.1", "WHATWG Fetch §4.4"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "header.referrer_policy.missing": {
        "id":           "header.referrer_policy.missing",
        "version":      "1.1.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Checks for the absence of Referrer-Policy.",
        "standards":    ["W3C Referrer Policy", "OWASP ASVS 14.4.4"],
        "owasp_top10":  "A02",
        "min_confidence": 0.8,
        "content_types": None,
    },
    "header.permissions_policy.missing": {
        "id":           "header.permissions_policy.missing",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Checks for the absence of Permissions-Policy (formerly Feature-Policy) on HTML responses.",
        "standards":    ["W3C Permissions Policy", "OWASP ASVS 14.4.6"],
        "owasp_top10":  "A02",
        "min_confidence": 0.7,
        "content_types": ["text/html"],
    },
    "header.cors.wildcard": {
        "id":           "header.cors.wildcard",
        "version":      "2.1.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Detects CORS misconfiguration: Access-Control-Allow-Origin: * or reflective origin with credentials.",
        "standards":    ["W3C CORS §3.2.2", "OWASP ASVS 14.5.3", "CWE-346"],
        "owasp_top10":  "A01",
        "min_confidence": 0.85,
        "content_types": None,
    },
    "header.server.version": {
        "id":           "header.server.version",
        "version":      "1.3.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Detects version disclosure in the Server header, excluding CDN/proxy banners.",
        "standards":    ["OWASP ASVS 14.3.3", "CWE-200"],
        "owasp_top10":  "A02",
        "min_confidence": 0.75,
        "content_types": None,
    },
    "header.xpoweredby.present": {
        "id":           "header.xpoweredby.present",
        "version":      "1.2.0",
        "author":       "SentinelScan Core",
        "category":     "Security Headers",
        "description":  "Detects technology disclosure via X-Powered-By, X-Generator, or X-AspNet-Version headers.",
        "standards":    ["OWASP ASVS 14.3.3", "CWE-200"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "header.cookie.security": {
        "id":           "header.cookie.security",
        "version":      "2.0.0",
        "author":       "SentinelScan Core",
        "category":     "Cookie Security",
        "description":  "Checks Set-Cookie headers for missing Secure, HttpOnly, and SameSite attributes.",
        "standards":    ["RFC 6265bis", "OWASP ASVS 3.4.1–3.4.5", "CWE-614", "CWE-1004"],
        "owasp_top10":  "A07",
        "min_confidence": 0.95,
        "content_types": None,
    },

    # ── SSL/TLS ────────────────────────────────────────────────────────────
    "ssl.cert.expired": {
        "id":           "ssl.cert.expired",
        "version":      "2.2.0",
        "author":       "SentinelScan Core",
        "category":     "SSL/TLS",
        "description":  "Detects an expired TLS certificate via live TLS handshake.",
        "standards":    ["RFC 5280 §4.1.2.5", "CA/Browser Forum Baseline Requirements"],
        "owasp_top10":  "A04",
        "min_confidence": 1.0,
        "content_types": None,
    },
    "ssl.cert.expiring_soon": {
        "id":           "ssl.cert.expiring_soon",
        "version":      "2.2.0",
        "author":       "SentinelScan Core",
        "category":     "SSL/TLS",
        "description":  "Warns when a TLS certificate expires within 30 days.",
        "standards":    ["CA/Browser Forum Baseline Requirements"],
        "owasp_top10":  "A04",
        "min_confidence": 1.0,
        "content_types": None,
    },
    "ssl.protocol.weak": {
        "id":           "ssl.protocol.weak",
        "version":      "2.2.0",
        "author":       "SentinelScan Core",
        "category":     "SSL/TLS",
        "description":  "Detects negotiated TLS protocol versions below TLS 1.2 (SSLv2, SSLv3, TLS 1.0, TLS 1.1).",
        "standards":    ["RFC 8996 (Deprecating TLS 1.0/1.1)", "NIST SP 800-52 Rev 2", "OWASP ASVS 9.2.1"],
        "owasp_top10":  "A04",
        "min_confidence": 1.0,
        "content_types": None,
    },
    "ssl.cipher.weak": {
        "id":           "ssl.cipher.weak",
        "version":      "2.2.0",
        "author":       "SentinelScan Core",
        "category":     "SSL/TLS",
        "description":  "Detects weak cipher suites (RC4, 3DES, EXPORT, NULL, ANON) in TLS negotiation.",
        "standards":    ["RFC 9325", "NIST SP 800-52 Rev 2", "OWASP ASVS 9.2.3"],
        "owasp_top10":  "A04",
        "min_confidence": 1.0,
        "content_types": None,
    },
    "ssl.cert.self_signed": {
        "id":           "ssl.cert.self_signed",
        "version":      "2.0.0",
        "author":       "SentinelScan Core",
        "category":     "SSL/TLS",
        "description":  "Detects self-signed certificates not issued by a trusted CA.",
        "standards":    ["CA/Browser Forum Baseline Requirements", "RFC 5280"],
        "owasp_top10":  "A04",
        "min_confidence": 0.95,
        "content_types": None,
    },
    "ssl.unavailable": {
        "id":           "ssl.unavailable",
        "version":      "2.0.0",
        "author":       "SentinelScan Core",
        "category":     "SSL/TLS",
        "description":  "Detects HTTPS targets that have no valid TLS endpoint.",
        "standards":    ["RFC 2818", "OWASP ASVS 9.1.1"],
        "owasp_top10":  "A04",
        "min_confidence": 0.9,
        "content_types": None,
    },

    # ── DNS ───────────────────────────────────────────────────────────────
    "dns.spf.missing": {
        "id":           "dns.spf.missing",
        "version":      "1.3.0",
        "author":       "SentinelScan Core",
        "category":     "DNS Security",
        "description":  "Checks for the absence of a valid SPF TXT record.",
        "standards":    ["RFC 7208", "OWASP ASVS 14.6.1"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "dns.dmarc.missing": {
        "id":           "dns.dmarc.missing",
        "version":      "1.3.0",
        "author":       "SentinelScan Core",
        "category":     "DNS Security",
        "description":  "Checks for the absence of a DMARC policy at _dmarc.<domain>.",
        "standards":    ["RFC 7489", "OWASP ASVS 14.6.1"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "dns.dmarc.weak_policy": {
        "id":           "dns.dmarc.weak_policy",
        "version":      "1.3.0",
        "author":       "SentinelScan Core",
        "category":     "DNS Security",
        "description":  "Detects DMARC records with p=none (monitor-only, no enforcement).",
        "standards":    ["RFC 7489 §6.3", "CISA Email Security Best Practices"],
        "owasp_top10":  "A02",
        "min_confidence": 0.95,
        "content_types": None,
    },
    "dns.mx.missing": {
        "id":           "dns.mx.missing",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "DNS Security",
        "description":  "Detects domains with no MX records that have an SPF record referencing mail.",
        "standards":    ["RFC 5321", "RFC 7208"],
        "owasp_top10":  "A02",
        "min_confidence": 0.6,
        "content_types": None,
    },

    # ── Technology Detection ───────────────────────────────────────────────
    "tech.fingerprint": {
        "id":           "tech.fingerprint",
        "version":      "3.1.0",
        "author":       "SentinelScan Core",
        "category":     "Technology Detection",
        "description":  "Multi-signal technology fingerprinting from headers, cookies, HTML markers, and response body patterns.",
        "standards":    ["OWASP WSTG-INFO-02", "CWE-200"],
        "owasp_top10":  "A03",
        "min_confidence": 0.6,
        "content_types": None,
    },
    "tech.version_disclosure": {
        "id":           "tech.version_disclosure",
        "version":      "3.1.0",
        "author":       "SentinelScan Core",
        "category":     "Technology Detection",
        "description":  "Detects explicit version information disclosed via headers or HTML meta tags.",
        "standards":    ["OWASP ASVS 14.3.3", "CWE-200"],
        "owasp_top10":  "A02",
        "min_confidence": 0.7,
        "content_types": None,
    },
    "tech.cve_match": {
        "id":           "tech.cve_match",
        "version":      "2.0.0",
        "author":       "SentinelScan Core",
        "category":     "CVE Detection",
        "description":  "Queries NIST NVD for CVEs matching the detected technology name and version. Requires x.y.z semver version.",
        "standards":    ["OWASP Top 10 A03", "CWE-1035", "NIST NVD"],
        "owasp_top10":  "A03",
        "min_confidence": 0.7,
        "content_types": None,
    },

    # ── Content Analysis ──────────────────────────────────────────────────
    "content.exposed_file": {
        "id":           "content.exposed_file",
        "version":      "2.3.0",
        "author":       "SentinelScan Core",
        "category":     "Content Exposure",
        "description":  "Probes for exposed sensitive files (.env, .git/HEAD, backup.sql, wp-config.php.bak, etc.) with soft-404 baseline detection and content validation.",
        "standards":    ["OWASP WSTG-CONF-05", "OWASP Top 10 A02", "CWE-538"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": None,
    },

    # ── Active OWASP Top 10:2025 Assessment Detectors ─────────────────────
    "active.cors.wildcard_credentials": {
        "id":           "active.cors.wildcard_credentials",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Access Control",
        "description":  "Flags CORS policies that combine wildcard Access-Control-Allow-Origin with credentials allowed.",
        "standards":    ["OWASP Top 10 A01", "W3C CORS", "CWE-942"],
        "owasp_top10":  "A01",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "active.sensitive_path.exposed": {
        "id":           "active.sensitive_path.exposed",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Access Control",
        "description":  "Discovers publicly exposed administrative endpoints and source-control files without authentication.",
        "standards":    ["OWASP Top 10 A01", "CWE-284", "CWE-538"],
        "owasp_top10":  "A01",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "active.crypto.mixed_content": {
        "id":           "active.crypto.mixed_content",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Cryptographic Failures",
        "description":  "Detects unencrypted HTTP scripts, stylesheets, and images embedded on HTTPS pages.",
        "standards":    ["OWASP Top 10 A04", "W3C Mixed Content", "CWE-311"],
        "owasp_top10":  "A04",
        "min_confidence": 0.9,
        "content_types": ["text/html"],
    },
    "active.injection.differential": {
        "id":           "active.injection.differential",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Injection",
        "description":  "Performs controlled differential baseline-vs-canary analysis for SQLi, XSS context reflection, and path traversal.",
        "standards":    ["OWASP Top 10 A05", "CWE-89", "CWE-79", "CWE-22"],
        "owasp_top10":  "A05",
        "min_confidence": 0.85,
        "content_types": None,
    },
    "active.insecure_design.evaluation": {
        "id":           "active.insecure_design.evaluation",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Insecure Design",
        "description":  "Evaluates architectural threat models, rate limit design, and OpenAPI security definitions.",
        "standards":    ["OWASP Top 10 A06", "NIST SP 800-160", "CWE-1059"],
        "owasp_top10":  "A06",
        "min_confidence": 0.8,
        "content_types": None,
    },
    "active.misconfig.options_methods": {
        "id":           "active.misconfig.options_methods",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Security Misconfiguration",
        "description":  "Probes HTTP OPTIONS for enabled TRACE/TRACK methods and dangerous mutating verbs.",
        "standards":    ["OWASP Top 10 A02", "RFC 7231 §4.3", "CWE-16"],
        "owasp_top10":  "A02",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "active.components.lifecycle": {
        "id":           "active.components.lifecycle",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Outdated Components",
        "description":  "Correlates normalized technology versions with vendor lifecycle and end-of-life status.",
        "standards":    ["OWASP Top 10 A03", "CWE-1104", "endoflife.date API"],
        "owasp_top10":  "A03",
        "min_confidence": 0.85,
        "content_types": None,
    },
    "active.auth.session_flags": {
        "id":           "active.auth.session_flags",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Authentication Failures",
        "description":  "Evaluates HttpOnly, Secure, and SameSite attributes on session cookies and login interfaces.",
        "standards":    ["OWASP Top 10 A07", "RFC 6265bis", "CWE-614", "CWE-1004"],
        "owasp_top10":  "A07",
        "min_confidence": 0.9,
        "content_types": None,
    },
    "active.integrity.sri": {
        "id":           "active.integrity.sri",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Software Supply Chain",
        "description":  "Verifies Subresource Integrity (SRI) hashes on third-party CDN scripts.",
        "standards":    ["OWASP Top 10 A03", "W3C SRI", "CWE-353"],
        "owasp_top10":  "A03",
        "min_confidence": 0.9,
        "content_types": ["text/html"],
    },
    "active.logging.observability": {
        "id":           "active.logging.observability",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Security Logging & Alerting",
        "description":  "Audits response correlation headers, verbose exception leaks, and exposed log files.",
        "standards":    ["OWASP Top 10 A09", "CWE-778", "CWE-209"],
        "owasp_top10":  "A09",
        "min_confidence": 0.8,
        "content_types": None,
    },
    "passive.ssrf.parameter_surface": {
        "id":           "passive.ssrf.parameter_surface",
        "version":      "1.0.0",
        "author":       "SentinelScan Core",
        "category":     "Access Control",
        "description":  "Evaluates crawled URL-accepting and redirection parameters for potential SSRF attack surface without out-of-band callbacks.",
        "standards":    ["OWASP Top 10 A01", "CWE-918"],
        "owasp_top10":  "A01",
        "min_confidence": 0.7,
        "content_types": None,
    },

    # ── External Exposure Detection (12 Domains) ───────────────────────────

    # Domain 1: Web Security Configuration
    "exposure.cors.misconfiguration": {
        "id": "exposure.cors.misconfiguration", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Web Security Configuration",
        "description": "Detects dangerous CORS policy (wildcard ACAO, null-origin, or credentials+wildcard).",
        "standards": ["OWASP Top 10 A04", "CWE-942"], "owasp_top10": "A04",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.server.version_disclosure": {
        "id": "exposure.server.version_disclosure", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Web Security Configuration",
        "description": "Detects software version strings in the Server HTTP response header.",
        "standards": ["OWASP ASVS 14.3.3", "CWE-200", "RFC 7230 §7.1.4"], "owasp_top10": "A04",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.server.xpoweredby": {
        "id": "exposure.server.xpoweredby", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Web Security Configuration",
        "description": "Detects technology/version disclosure in the X-Powered-By header.",
        "standards": ["OWASP Secure Headers Project", "CWE-200"], "owasp_top10": "A04",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.debug.endpoint_exposed": {
        "id": "exposure.debug.endpoint_exposed", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Web Security Configuration",
        "description": "Probes for publicly accessible debug, actuator, and management endpoints.",
        "standards": ["OWASP Top 10 A04", "CWE-489"], "owasp_top10": "A04",
        "min_confidence": 0.85, "content_types": None,
    },

    # Domain 2: Auth and Session Security
    "exposure.auth.session_cookie_flags": {
        "id": "exposure.auth.session_cookie_flags", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Auth and Session Security",
        "description": "Checks session cookies for missing HttpOnly, Secure, and SameSite attributes.",
        "standards": ["OWASP Top 10 A07", "CWE-614", "RFC 6265"], "owasp_top10": "A07",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.auth.plaintext_login": {
        "id": "exposure.auth.plaintext_login", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Auth and Session Security",
        "description": "Detects password input fields served over unencrypted HTTP.",
        "standards": ["OWASP Top 10 A02", "CWE-319"], "owasp_top10": "A02",
        "min_confidence": 0.95, "content_types": ["text/html"],
    },
    "exposure.auth.basic_auth_exposed": {
        "id": "exposure.auth.basic_auth_exposed", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Auth and Session Security",
        "description": "Detects HTTP Basic authentication challenges in WWW-Authenticate responses.",
        "standards": ["OWASP Top 10 A07", "CWE-522", "RFC 7617"], "owasp_top10": "A07",
        "min_confidence": 0.9, "content_types": None,
    },

    # Domain 3: API Exposure
    "exposure.api.graphql_exposed": {
        "id": "exposure.api.graphql_exposed", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "API Exposure",
        "description": "Detects publicly accessible GraphQL endpoints, GraphiQL IDE, and Playground.",
        "standards": ["OWASP API Security Top 10", "CWE-284"], "owasp_top10": "A01",
        "min_confidence": 0.85, "content_types": None,
    },
    "exposure.api.graphql_introspection": {
        "id": "exposure.api.graphql_introspection", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "API Exposure",
        "description": "Confirms GraphQL introspection is enabled via a live __schema query.",
        "standards": ["OWASP API Security Top 10 API7", "CWE-284"], "owasp_top10": "A01",
        "min_confidence": 0.95, "content_types": None,
    },
    "exposure.api.openapi_exposed": {
        "id": "exposure.api.openapi_exposed", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "API Exposure",
        "description": "Detects publicly accessible OpenAPI/Swagger specification files.",
        "standards": ["OWASP API Security Top 10 API9", "CWE-200"], "owasp_top10": "A04",
        "min_confidence": 0.85, "content_types": None,
    },
    "exposure.api.docs_exposed": {
        "id": "exposure.api.docs_exposed", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "API Exposure",
        "description": "Detects publicly accessible API documentation endpoints (ReDoc, Swagger UI, api-docs).",
        "standards": ["OWASP API Security Top 10 API9", "CWE-200"], "owasp_top10": "A04",
        "min_confidence": 0.8, "content_types": None,
    },
    "exposure.api.rest_exposed": {
        "id": "exposure.api.rest_exposed", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "API Exposure",
        "description": "Detects publicly accessible versioned REST API roots without authentication.",
        "standards": ["OWASP API Security Top 10 API1", "CWE-284"], "owasp_top10": "A01",
        "min_confidence": 0.75, "content_types": None,
    },

    # Domain 4: JavaScript Secret Detection
    "exposure.js.aws_key": {
        "id": "exposure.js.aws_key", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded AWS Access Key IDs (AKIA...) in inline or same-origin JavaScript.",
        "standards": ["CWE-798", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.95, "content_types": None,
    },
    "exposure.js.aws_secret": {
        "id": "exposure.js.aws_secret", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded AWS Secret Access Keys in JavaScript source.",
        "standards": ["CWE-798", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.js.google_api_key": {
        "id": "exposure.js.google_api_key", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded Google API Keys (AIza...) in JavaScript source.",
        "standards": ["CWE-798", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.js.github_token": {
        "id": "exposure.js.github_token", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded GitHub Personal Access Tokens in JavaScript.",
        "standards": ["CWE-798", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.95, "content_types": None,
    },
    "exposure.js.stripe_live_key": {
        "id": "exposure.js.stripe_live_key", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded Stripe live secret keys (sk_live_...) in JavaScript.",
        "standards": ["CWE-798", "PCI DSS 6.5.3"], "owasp_top10": "A02",
        "min_confidence": 0.95, "content_types": None,
    },
    "exposure.js.stripe_test_key": {
        "id": "exposure.js.stripe_test_key", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded Stripe test secret keys (sk_test_...) in JavaScript.",
        "standards": ["CWE-798"], "owasp_top10": "A02",
        "min_confidence": 0.85, "content_types": None,
    },
    "exposure.js.slack_token": {
        "id": "exposure.js.slack_token", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded Slack API/Bot tokens (xox...) in JavaScript.",
        "standards": ["CWE-798", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.js.sendgrid_key": {
        "id": "exposure.js.sendgrid_key", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded SendGrid API keys in JavaScript.",
        "standards": ["CWE-798", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.js.jwt_secret": {
        "id": "exposure.js.jwt_secret", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects hardcoded JWT signing secrets in JavaScript source.",
        "standards": ["CWE-798", "CWE-522", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.85, "content_types": None,
    },
    "exposure.js.generic_api_key": {
        "id": "exposure.js.generic_api_key", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects generic api_key/apikey/client_secret assignments in JavaScript source.",
        "standards": ["CWE-798", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.75, "content_types": None,
    },
    "exposure.js.private_key": {
        "id": "exposure.js.private_key", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "JavaScript Secret Detection",
        "description": "Detects PEM private key headers in JavaScript or HTML source.",
        "standards": ["CWE-321", "CWE-798", "OWASP Top 10 A02"], "owasp_top10": "A02",
        "min_confidence": 0.98, "content_types": None,
    },

    # Domain 5: Source Map Exposure
    "exposure.sourcemap.exposed": {
        "id": "exposure.sourcemap.exposed", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Source Map Exposure",
        "description": "Confirms .map files are publicly accessible, enabling source code reconstruction.",
        "standards": ["CWE-200", "OWASP WSTG-INFO-05"], "owasp_top10": "A04",
        "min_confidence": 0.9, "content_types": None,
    },

    # Domain 6: Sensitive File Exposure
    "exposure.files.robots_sensitive_paths": {
        "id": "exposure.files.robots_sensitive_paths", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Sensitive File Exposure",
        "description": "Detects sensitive internal path disclosure via robots.txt Disallow directives.",
        "standards": ["OWASP WSTG-INFO-01", "CWE-200"], "owasp_top10": "A04",
        "min_confidence": 0.85, "content_types": None,
    },
    "exposure.files.security_txt_missing": {
        "id": "exposure.files.security_txt_missing", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Sensitive File Exposure",
        "description": "Checks for the absence of a security.txt file per RFC 9116.",
        "standards": ["RFC 9116", "securitytxt.org"], "owasp_top10": "A04",
        "min_confidence": 0.9, "content_types": None,
    },

    # Domain 7: Cloud Storage Exposure
    "exposure.cloud.bucket_public": {
        "id": "exposure.cloud.bucket_public", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Cloud Storage Exposure",
        "description": "Confirms cloud storage bucket (S3/GCS/Azure) is publicly listable.",
        "standards": ["CWE-284", "OWASP Top 10 A01"], "owasp_top10": "A01",
        "min_confidence": 0.95, "content_types": None,
    },
    "exposure.cloud.bucket_accessible": {
        "id": "exposure.cloud.bucket_accessible", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Cloud Storage Exposure",
        "description": "Detects cloud storage bucket referenced in source that returns HTTP 200 (public read).",
        "standards": ["CWE-284", "OWASP Top 10 A01"], "owasp_top10": "A01",
        "min_confidence": 0.8, "content_types": None,
    },
    "exposure.cloud.bucket_reference": {
        "id": "exposure.cloud.bucket_reference", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Cloud Storage Exposure",
        "description": "Detects cloud storage bucket URL references in client-facing HTML/JS source.",
        "standards": ["CWE-200", "OWASP Top 10 A04"], "owasp_top10": "A04",
        "min_confidence": 0.75, "content_types": None,
    },

    # Domain 8: DNS Intelligence
    "exposure.dns.spf_passall": {
        "id": "exposure.dns.spf_passall", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "DNS Intelligence",
        "description": "Detects SPF records with +all or ?all allowing any sender to pass SPF.",
        "standards": ["RFC 7208", "OWASP Email Security"], "owasp_top10": "A04",
        "min_confidence": 0.95, "content_types": None,
    },
    "exposure.dns.spf_softfail": {
        "id": "exposure.dns.spf_softfail", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "DNS Intelligence",
        "description": "Detects SPF records using ~all softfail which does not reject unauthorized senders.",
        "standards": ["RFC 7208"], "owasp_top10": "A04",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.dns.wildcard": {
        "id": "exposure.dns.wildcard", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "DNS Intelligence",
        "description": "Detects wildcard DNS records that may enable subdomain takeover attacks.",
        "standards": ["CWE-350", "OWASP Top 10 A04"], "owasp_top10": "A04",
        "min_confidence": 0.8, "content_types": None,
    },
    "exposure.dns.dmarc_missing": {
        "id": "exposure.dns.dmarc_missing", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "DNS Intelligence",
        "description": "Detects absence of DMARC policy record at _dmarc.hostname.",
        "standards": ["RFC 7489", "DMARC.org"], "owasp_top10": "A04",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.dns.dmarc_none_policy": {
        "id": "exposure.dns.dmarc_none_policy", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "DNS Intelligence",
        "description": "Detects DMARC policy set to p=none (monitor only, does not block spoofed email).",
        "standards": ["RFC 7489", "DMARC.org"], "owasp_top10": "A04",
        "min_confidence": 0.9, "content_types": None,
    },

    # Domain 9: TLS Analysis
    "exposure.tls.ct_not_logged": {
        "id": "exposure.tls.ct_not_logged", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "TLS Analysis",
        "description": "Checks whether the TLS certificate has been logged to Certificate Transparency.",
        "standards": ["RFC 9162", "Chrome CT Policy"], "owasp_top10": "A02",
        "min_confidence": 0.8, "content_types": None,
    },
    "exposure.tls.weak_protocols": {
        "id": "exposure.tls.weak_protocols", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "TLS Analysis",
        "description": "Detects support for deprecated TLS protocol versions (TLS 1.0, 1.1, SSLv3, SSLv2).",
        "standards": ["RFC 8996", "NIST SP 800-52r2", "PCI DSS 6.5.4"], "owasp_top10": "A02",
        "min_confidence": 0.95, "content_types": None,
    },
    "exposure.tls.weak_ciphers": {
        "id": "exposure.tls.weak_ciphers", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "TLS Analysis",
        "description": "Detects weak TLS cipher suites (RC4, 3DES, NULL, EXPORT, ANON).",
        "standards": ["RFC 7465", "NIST SP 800-52r2", "PCI DSS 4.2.1"], "owasp_top10": "A02",
        "min_confidence": 0.9, "content_types": None,
    },
    "exposure.tls.hsts_not_preloaded": {
        "id": "exposure.tls.hsts_not_preloaded", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "TLS Analysis",
        "description": "Checks if HSTS is configured but not submitted to the HSTS preload list.",
        "standards": ["RFC 6797", "hstspreload.org"], "owasp_top10": "A02",
        "min_confidence": 0.75, "content_types": None,
    },

    # Domain 10: Mixed Content
    "exposure.mixed_content.active": {
        "id": "exposure.mixed_content.active", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Mixed Content",
        "description": "Detects active mixed content (HTTP scripts) on HTTPS pages.",
        "standards": ["W3C Mixed Content Level 2", "CWE-319"], "owasp_top10": "A02",
        "min_confidence": 0.9, "content_types": ["text/html"],
    },
    "exposure.mixed_content.passive": {
        "id": "exposure.mixed_content.passive", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Mixed Content",
        "description": "Detects passive mixed content (HTTP images/stylesheets) on HTTPS pages.",
        "standards": ["W3C Mixed Content Level 2", "CWE-319"], "owasp_top10": "A02",
        "min_confidence": 0.85, "content_types": ["text/html"],
    },

    # Domain 11: Third-Party and SRI
    "exposure.sri.cdn_missing": {
        "id": "exposure.sri.cdn_missing", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Third-Party and SRI",
        "description": "Detects CDN-hosted scripts loaded without Subresource Integrity hashes.",
        "standards": ["W3C SRI", "OWASP Top 10 A08", "CWE-353"], "owasp_top10": "A08",
        "min_confidence": 0.9, "content_types": ["text/html"],
    },
    "exposure.sri.external_missing": {
        "id": "exposure.sri.external_missing", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Third-Party and SRI",
        "description": "Detects external scripts loaded without SRI integrity attributes.",
        "standards": ["W3C SRI", "OWASP Top 10 A08", "CWE-353"], "owasp_top10": "A08",
        "min_confidence": 0.8, "content_types": ["text/html"],
    },

    # Domain 12: Cache Exposure
    "exposure.cache.authenticated_cacheable": {
        "id": "exposure.cache.authenticated_cacheable", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Cache Exposure",
        "description": "Detects authenticated responses lacking Cache-Control: no-store/private directives.",
        "standards": ["OWASP WSTG-ATHN-06", "CWE-524", "RFC 7234"], "owasp_top10": "A02",
        "min_confidence": 0.75, "content_types": None,
    },
    "exposure.cache.sensitive_api_cacheable": {
        "id": "exposure.cache.sensitive_api_cacheable", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Cache Exposure",
        "description": "Detects sensitive API responses (tokens, passwords, PII) without Cache-Control: no-store.",
        "standards": ["OWASP WSTG-ATHN-06", "CWE-524", "PCI DSS 3.4"], "owasp_top10": "A02",
        "min_confidence": 0.85, "content_types": None,
    },
    "exposure.cache.no_cache_control": {
        "id": "exposure.cache.no_cache_control", "version": "1.0.0",
        "author": "SentinelScan Core", "category": "Cache Exposure",
        "description": "Detects JSON API endpoints returning no Cache-Control header at all.",
        "standards": ["RFC 7234", "OWASP WSTG-ATHN-06"], "owasp_top10": "A04",
        "min_confidence": 0.7, "content_types": None,
    },
}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def get_detector(detector_id: str) -> dict[str, Any]:
    """Return metadata for a detector by ID, or an empty dict if not registered."""
    return DETECTOR_REGISTRY.get(detector_id, {})


def detectors_by_category() -> dict[str, list[dict[str, Any]]]:
    """Return the registry grouped by category."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for entry in DETECTOR_REGISTRY.values():
        cat = entry["category"]
        groups.setdefault(cat, []).append(entry)
    return groups


def all_owasp_mappings() -> dict[str, list[str]]:
    """Return a mapping of OWASP ID → list of detector IDs that cover it."""
    result: dict[str, list[str]] = {}
    for entry in DETECTOR_REGISTRY.values():
        owasp = entry.get("owasp_top10")
        if owasp:
            result.setdefault(owasp, []).append(entry["id"])
    return result


def all_standards() -> set[str]:
    """Return the set of all referenced standards across all detectors."""
    refs: set[str] = set()
    for entry in DETECTOR_REGISTRY.values():
        refs.update(entry.get("standards", []))
    return refs


# ---------------------------------------------------------------------------
# Confidence mapping
# ---------------------------------------------------------------------------

# Maps min_confidence (0.0–1.0 from the registry) to the Finding Confidence enum.
# Used as a fallback when a detector output dict does not include a confidence field.
_CONFIDENCE_THRESHOLDS = [
    (0.85, "high"),
    (0.65, "medium"),
    (0.0, "low"),
]


def detector_confidence(detector_id: str) -> str:
    """Return the default Confidence level for a detector based on its registry metadata.

    Looks up the detector's ``min_confidence`` and maps it to a Confidence enum
    value (``"high"``, ``"medium"``, ``"low"``).  If the detector is not registered,
    returns ``"high"`` as a safe default (most detectors produce deterministic
    evidence).
    """
    meta = DETECTOR_REGISTRY.get(detector_id, {})
    min_conf = meta.get("min_confidence", 0.9)
    for threshold, level in _CONFIDENCE_THRESHOLDS:
        if min_conf >= threshold:
            return level
    return "low"
