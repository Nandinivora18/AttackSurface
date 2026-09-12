"""
CVE Database Integration — NIST NVD API v2.0
============================================
Queries the National Vulnerability Database for CVEs matching
detected technology versions.

API docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limits:
  - Without API key: 5 requests / 30 seconds
  - With API key:   50 requests / 30 seconds (free key at nvd.nist.gov)

Set NVD_API_KEY in .env for higher throughput (optional but recommended).
"""
import asyncio
import json
import logging
import re
from typing import Any, Optional


import httpx

from app.config import settings
from app.utils.cache import cache_get, cache_set

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CACHE_TTL = 86400          # 24 hours — CVE data is stable
NVD_REQUEST_DELAY = 6.5        # seconds between requests without API key
NVD_REQUEST_DELAY_KEYED = 0.7  # seconds between requests with API key
NVD_TIMEOUT = 20.0             # seconds per request
NVD_MAX_RESULTS = 10           # cap CVEs per technology


# ─────────────────────────────────────────────────────────────────────────────
# CPE Name Mapping
# Maps our internal tech names to NVD CPE 2.3 vendor:product strings.
# Format: "vendor:product" (version added dynamically)
# Browse CPEs at: https://nvd.nist.gov/products/cpe/search
# ─────────────────────────────────────────────────────────────────────────────
CPE_MAPPING: dict[str, str] = {
    "Apache":       "apache:http_server",
    "Nginx":        "nginx:nginx",
    "IIS":          "microsoft:internet_information_services",
    "PHP":          "php:php",
    "WordPress":    "wordpress:wordpress",
    "Drupal":       "drupal:drupal",
    "Joomla":       "joomla:joomla",
    "jQuery":       "jquery:jquery",
    "Bootstrap":    "twitter:bootstrap",
    "Magento":      "magento:magento",
    "Laravel":      "laravel:laravel",
    "Django":       "djangoproject:django",
    "ASP.NET":      "microsoft:asp.net",
    "OpenSSL":      "openssl:openssl",
    "Node.js":      "nodejs:node.js",
    "Tomcat":       "apache:tomcat",
    "Spring":       "vmware:spring_framework",
    # NOTE: React, Angular, and Vue.js are intentionally excluded.
    # CVEs for these frameworks in NVD are nearly non-existent at the framework
    # level (vulnerabilities are in plugins/dependencies). Including them wastes
    # rate-limit budget and risks returning unrelated results for these
    # high-profile names. Component-level CVEs require knowing specific package
    # versions (e.g. via package-lock.json), which passive scanning cannot provide.
}

# Severity thresholds based on CVSS v3 score
CVSS_SEVERITY_MAP = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "info"),
]


def _cvss_to_severity(score: Optional[float]) -> str:
    """Map a CVSS v3 numeric score to a severity label."""
    if score is None:
        return "medium"
    for threshold, label in CVSS_SEVERITY_MAP:
        if score >= threshold:
            return label
    return "info"


def _build_cpe_name(tech_name: str, version: str) -> Optional[str]:
    """Build a CPE 2.3 URI for the given technology and version."""
    mapping = CPE_MAPPING.get(tech_name)
    if not mapping:
        return None
    vendor, product = mapping.split(":", 1)
    # CPE format: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def _parse_cve_item(item: dict, tech_name: str, version: str) -> Optional[dict]:
    """
    Parse a single CVE item from NVD API response into our finding structure.
    Returns None if the CVE lacks sufficient data.
    """
    try:
        cve_id = item.get("id", "")
        if not cve_id:
            return None

        # ── Description ────────────────────────────────────────────────────
        descriptions = item.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available.",
        )
        # Truncate very long descriptions
        if len(description) > 800:
            description = description[:797] + "…"

        # ── CVSS Score & Severity ───────────────────────────────────────────
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        metrics = item.get("metrics", {})

        # Prefer CVSS v3.1 > v3.0 > v2.0
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                m = metric_list[0]
                cvss_data = m.get("cvssData", {})
                score_key = "baseScore"
                cvss_score = cvss_data.get(score_key)
                cvss_vector = cvss_data.get("vectorString")
                break

        severity = _cvss_to_severity(cvss_score)

        # ── Published Date ──────────────────────────────────────────────────
        published_str = item.get("published", "")
        published_date: Optional[str] = None
        if published_str:
            try:
                published_date = published_str[:10]  # "YYYY-MM-DD"
            except Exception:
                pass

        # ── References ─────────────────────────────────────────────────────
        refs = item.get("references", [])
        reference_urls = [
            r["url"] for r in refs if r.get("url")
        ][:5]  # cap at 5
        # Always include the NVD detail page
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        if nvd_url not in reference_urls:
            reference_urls.insert(0, nvd_url)

        # ── Weakness (CWE) ──────────────────────────────────────────────────
        weaknesses = item.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwe_ids.append(desc["value"])

        # ── Recommendation ─────────────────────────────────────────────────
        recommendation = (
            f"Update {tech_name} to the latest patched version immediately. "
            f"{cve_id} affects version {version}. "
            f"Check the vendor's security advisory and apply available patches. "
            f"If an update is not immediately possible, apply available mitigations "
            f"and restrict access to vulnerable components."
        )

        # ── Evidence ───────────────────────────────────────────────────────
        evidence_parts = [f"Detected {tech_name}/{version}"]
        if cvss_vector:
            evidence_parts.append(f"CVSS Vector: {cvss_vector}")
        if cwe_ids:
            evidence_parts.append(f"CWE: {', '.join(cwe_ids)}")
        evidence = " | ".join(evidence_parts)

        return {
            "category": "CVE",
            "title": f"{tech_name} {version} — {cve_id}",
            "description": description,
            "severity": severity,
            "cvss_score": float(cvss_score) if cvss_score is not None else None,
            "cve_id": cve_id,
            "published_date": published_date,
            # medium confidence: NVD CPE version-range matching is imprecise.
            # A CVE affecting 'product <= 2.4' may appear for 'product 5.x' if
            # NVD CPE data uses broad ranges. Operators should verify the
            # detected version against the CVE's affected-version range directly.
            "confidence": "medium",
            "recommendation": recommendation,
            "references": reference_urls,
            "evidence": evidence,
        }

    except Exception as e:
        logger.warning(f"Failed to parse CVE item {item.get('id', '?')}: {e}")
        return None


async def _fetch_nvd_cves(cpe_name: str) -> list[dict]:
    """
    Query NVD API v2.0 for CVEs matching the given CPE name.
    Returns raw CVE item dicts from the API.
    """
    headers = {"Accept": "application/json"}
    api_key = getattr(settings, "NVD_API_KEY", None)
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "cpeName": cpe_name,
        "resultsPerPage": NVD_MAX_RESULTS,
        "startIndex": 0,
    }

    try:
        async with httpx.AsyncClient(timeout=NVD_TIMEOUT) as client:
            response = await client.get(NVD_API_BASE, params=params, headers=headers)

        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            # Each item has a "cve" sub-key
            return [v.get("cve", v) for v in vulnerabilities if v.get("cve")]
        elif response.status_code == 403:
            logger.warning("NVD API rate limited — consider adding NVD_API_KEY to .env")
            return []
        elif response.status_code == 404:
            return []  # No CVEs for this CPE — normal
        else:
            logger.warning(f"NVD API returned {response.status_code} for CPE: {cpe_name}")
            return []

    except httpx.TimeoutException:
        logger.warning(f"NVD API timeout for CPE: {cpe_name}")
        return []
    except Exception as e:
        logger.error(f"NVD API request failed for CPE {cpe_name}: {e}")
        return []


# Strict semantic version pattern: accepts 1.2, 1.2.3, 1.2.3.4 but NOT
# '3.x', 'latest', 'stable', single-digit-only '3', or versions with
# non-numeric suffixes like '3.5.0-beta'. Such versions would produce
# invalid CPE URIs or incorrect NVD matches.
_VALID_VERSION_RE = re.compile(r'^\d+\.\d[\d.]*$')


async def check_cves_for_tech(
    tech_name: str,
    version: str,
    request_delay: float = NVD_REQUEST_DELAY,
) -> list[dict]:
    """
    Look up CVEs for a detected technology version.

    Args:
        tech_name: e.g. "Apache", "jQuery", "WordPress"
        version:   e.g. "2.4.49", "3.4.1", "6.1.1"
        request_delay: seconds to wait before querying (rate limit compliance)

    Returns:
        List of finding dicts with CVE data, ready to be stored as Findings.
    """
    if not tech_name or not version:
        return []

    # Validate version format before building a CPE URI
    if not _VALID_VERSION_RE.match(version.strip()):
        logger.debug(f"Skipping CVE lookup for {tech_name}: invalid version format '{version}'")
        return []

    cpe_name = _build_cpe_name(tech_name, version)
    if not cpe_name:
        logger.debug(f"No CPE mapping for {tech_name} — skipping CVE lookup")
        return []

    # ── Cache check ─────────────────────────────────────────────────────────
    cache_key = f"cve:{tech_name.lower()}:{version}"
    cached_str = await cache_get(cache_key)
    if cached_str is not None:
        try:
            cached = json.loads(cached_str)
            logger.debug(f"CVE cache hit for {tech_name} {version} ({len(cached)} CVEs)")
            return cached
        except (json.JSONDecodeError, TypeError):
            pass  # stale/corrupt cache — re-fetch

    # ── Rate limit compliance ────────────────────────────────────────────────
    api_key = getattr(settings, "NVD_API_KEY", None)
    delay = NVD_REQUEST_DELAY_KEYED if api_key else request_delay
    if delay > 0:
        await asyncio.sleep(delay)

    logger.info(f"Querying NVD for {tech_name} {version} (CPE: {cpe_name})")
    raw_items = await _fetch_nvd_cves(cpe_name)

    # ── Parse results ────────────────────────────────────────────────────────
    findings = []
    for item in raw_items:
        parsed = _parse_cve_item(item, tech_name, version)
        if parsed:
            findings.append(parsed)

    # Sort by CVSS score descending (most critical first)
    findings.sort(key=lambda f: f.get("cvss_score") or 0, reverse=True)
    findings = findings[:NVD_MAX_RESULTS]

    # ── Cache results ────────────────────────────────────────────────────────
    await cache_set(cache_key, json.dumps(findings), expire=NVD_CACHE_TTL)
    logger.info(f"Found {len(findings)} CVEs for {tech_name} {version}")
    return findings


async def check_all_technologies(
    detected_technologies: dict[str, dict],
    progress_callback=None,
) -> list[dict]:
    """
    Run CVE checks for all detected technologies that have a version.

    Args:
        detected_technologies: dict from tech_detector, e.g.:
            {"Apache": {"version": "2.4.49", "category": "Web Server", ...}}
        progress_callback: optional async callable(message: str) for progress updates

    Returns:
        Combined list of all CVE findings across all technologies.
    """
    all_cve_findings: list[dict] = []

    # Only check technologies where we have a version AND a CPE mapping
    checkable = [
        (name, info["version"])
        for name, info in detected_technologies.items()
        if info.get("version") and CPE_MAPPING.get(name)
    ]

    if not checkable:
        logger.info("No technologies with known versions + CPE mappings — skipping CVE lookup")
        return []

    logger.info(f"Running CVE lookup for {len(checkable)} technologies: {[n for n, _ in checkable]}")

    api_key = getattr(settings, "NVD_API_KEY", None)
    # First request has no delay (caller may have already waited)
    delay = NVD_REQUEST_DELAY_KEYED if api_key else NVD_REQUEST_DELAY

    for i, (tech_name, version) in enumerate(checkable):
        if progress_callback:
            await progress_callback(f"Checking CVEs for {tech_name} {version}…")

        # Add delay between requests (not before the first)
        request_delay = delay if i > 0 else 0.5
        cves = await check_cves_for_tech(tech_name, version, request_delay=request_delay)
        all_cve_findings.extend(cves)

    return all_cve_findings
