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
