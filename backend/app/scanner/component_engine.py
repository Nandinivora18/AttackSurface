"""
Component Intelligence & Lifecycle Engine for SentinelScan
==========================================================
Provides multi-signal technology analysis, version normalization,
upstream lifecycle provider integration with Redis caching & local fallback,
and structured component inventory generation.

Guarantees:
- Zero fabricated versions or lifecycle dates.
- Missing vendor data remains None / UNKNOWN.
- EOL status is strictly separated from CVE findings.
- Vendor-backported patch limitations are explicitly surfaced.
"""
from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from typing import Any, Optional
import httpx

from app.scanner.lifecycle import _LIFECYCLE_DB, _EOL_WARNING_DAYS

logger = logging.getLogger(__name__)

# Standard Component States
STATE_SUPPORTED = "SUPPORTED"
STATE_UPDATE_AVAILABLE = "UPDATE_AVAILABLE"
STATE_SECURITY_SUPPORT_ENDED = "SECURITY_SUPPORT_ENDED"
STATE_END_OF_LIFE = "END_OF_LIFE"
STATE_LIFECYCLE_UNKNOWN = "LIFECYCLE_UNKNOWN"
STATE_VERSION_UNKNOWN = "VERSION_UNKNOWN"

# Standard Confidence Levels
CONF_CONFIRMED = "CONFIRMED"
CONF_HIGH = "HIGH"
CONF_MEDIUM = "MEDIUM"
CONF_LOW = "LOW"
CONF_UNKNOWN = "UNKNOWN"

# Product slug mappings for endoflife.date API
EOL_API_PRODUCT_MAP = {
    "apache": "apache",
    "nginx": "nginx",
    "php": "php",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "nodejs": "nodejs",
    "node.js": "nodejs",
    "python": "python",
    "django": "django",
    "laravel": "laravel",
    "bootstrap": "bootstrap",
    "jquery": "jquery",
    "react": "react",
    "vue.js": "vue",
    "angular": "angular",
}

# Regex to identify semantic version numbers and vendor/distribution suffixes
# Matches: 8.2.26-0ubuntu1, 2.4.52 (Unix), v1.2.3, 10.0.18-MariaDB, 7.4.33-1+deb.sury.org
_SEMVER_REGEX = re.compile(r'^[vV]?(\d+(?:\.\d+)+(?:[a-zA-Z0-9_]*))')
_VENDOR_SUFFIX_REGEX = re.compile(
    r'[-_+](ubuntu|debian|el\d|redhat|centos|alpine|sury|amzn|arch|freebsd|unix|win32|win64).*$',
    re.IGNORECASE
)


@dataclass
class NormalizedVersion:
    raw_version: str
    normalized_version: str | None
    vendor_suffix: str | None
    confidence: str
    is_semantic: bool


@dataclass
class ComponentAssessment:
    technology: str
    category: str
    raw_version: str | None
    normalized_version: str | None
    vendor_suffix: str | None
    version_confidence: str
    source: str
    evidence: str
    lifecycle_status: str
    eol_date: str | None
    latest_version: str | None
    cves: list[dict[str, Any]] = field(default_factory=list)
    cve_count: int = 0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_component_version(raw_version: str | None, source: str = "") -> NormalizedVersion:
    """
    Normalizes a detected raw version string into a clean semantic version,
    isolating vendor/distribution suffixes and assigning an evidence confidence score.
    """
    if not raw_version or not raw_version.strip():
        return NormalizedVersion(
            raw_version="",
            normalized_version=None,
            vendor_suffix=None,
            confidence=CONF_UNKNOWN,
            is_semantic=False,
        )

    clean_raw = raw_version.strip().lstrip("vV")

    # Extract base semantic version digits
    semver_match = re.match(r'^(\d+(?:\.\d+)+)', clean_raw)
    if semver_match:
        norm_v = semver_match.group(1)
        remainder = clean_raw[semver_match.end():].strip()
        vendor_suffix = None

        if remainder:
            # Check for (Unix) or (Win32) or similar in parentheses
            paren_match = re.search(r'\(([^)]+)\)', remainder)
            if paren_match:
                vendor_suffix = paren_match.group(1).strip()
            else:
                # Strip leading dash, plus, underscore
                clean_rem = re.sub(r'^[-+_]+', '', remainder)
                # If 0ubuntu..., remove leading 0 for canonical distro naming
                clean_rem = re.sub(r'^0(?=ubuntu)', '', clean_rem)
                clean_rem = clean_rem.split()[0]
                if any(k in clean_rem.lower() for k in ["ubuntu", "debian", "deb", "el", "redhat", "centos", "alpine", "sury", "amzn", "arch", "freebsd", "unix", "win"]):
                    vendor_suffix = clean_rem

        parts = norm_v.split(".")
        is_semantic = len(parts) >= 2

        # Confidence heuristic based on source and specificity
        source_lower = source.lower()
        if any(h in source_lower for h in ["server", "x-powered-by", "x-aspnet", "generator", "meta"]):
            conf = CONF_HIGH
        elif "script" in source_lower or "asset" in source_lower or "url" in source_lower:
            conf = CONF_HIGH if len(parts) >= 3 else CONF_MEDIUM
        else:
            conf = CONF_MEDIUM

        return NormalizedVersion(
            raw_version=raw_version,
            normalized_version=norm_v,
            vendor_suffix=vendor_suffix,
            confidence=conf,
            is_semantic=is_semantic,
        )

    return NormalizedVersion(
        raw_version=raw_version,
        normalized_version=clean_raw,
        vendor_suffix=None,
        confidence=CONF_LOW,
        is_semantic=False,
    )


class LifecycleProvider:
    """
    Queries lifecycle and latest release data for technologies.
    Uses Redis cache with fallback to local curated database.
    Guarantees non-blocking fail-safe operation: never raises to caller.
    """

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._cache_ttl = 86400  # 24 hours

    async def get_lifecycle(self, tech_name: str, normalized_version: str | None) -> dict[str, Any]:
        """
        Determines component lifecycle state, EOL date, and latest release.
        """
        if not normalized_version:
            return {
                "status": STATE_VERSION_UNKNOWN,
                "eol_date": None,
                "latest_version": None,
                "source": "None",
                "notes": "Version not disclosed; lifecycle evaluation unavailable.",
            }

        # 1. Query upstream endoflife.date API (Redis cached, 3.0s timeout)
        slug = EOL_API_PRODUCT_MAP.get(tech_name.lower())
        if slug:
            cycles = await self._fetch_upstream_cycles(slug)
            if cycles:
                matched = self._match_cycle(cycles, normalized_version)
                if matched:
                    return matched

        # 2. Fallback to local curated database
        local_match = self._check_local_db(tech_name, normalized_version)
        if local_match:
            return local_match

        # 3. Fallback: Lifecycle status unknown for this branch
        return {
            "status": STATE_LIFECYCLE_UNKNOWN,
            "eol_date": None,
            "latest_version": None,
            "source": "None",
            "notes": "No authoritative vendor lifecycle schedule found for this version branch.",
        }

    def _check_local_db(self, tech_key: str, version: str) -> dict[str, Any] | None:
        """Evaluates against local curated _LIFECYCLE_DB."""
        entries = _LIFECYCLE_DB.get(tech_key)
        if not entries:
            for k, v in _LIFECYCLE_DB.items():
                if k.lower() == tech_key.lower():
                    entries = v
                    break
        if not entries:
            return None

        for entry in entries:
            prefix = entry["version_prefix"]
            if version == prefix or version.startswith(prefix + ".") or (prefix == "5" and version.startswith("5.")):
                status_raw = entry.get("status", "active")
                eol_date_str = entry.get("eol_date")
                
                status = STATE_SUPPORTED
                if status_raw == "eol":
                    status = STATE_END_OF_LIFE
                elif status_raw == "security-only":
                    status = STATE_SECURITY_SUPPORT_ENDED

                # Check if approaching EOL within warning window
                if eol_date_str and status == STATE_SUPPORTED:
                    try:
                        eol = date.fromisoformat(eol_date_str)
                        if (eol - date.today()).days <= _EOL_WARNING_DAYS:
                            status = STATE_SECURITY_SUPPORT_ENDED
                    except ValueError:
                        pass

                return {
                    "status": status,
                    "eol_date": eol_date_str,
                    "latest_version": None,
                    "source": entry.get("source", ""),
                    "notes": entry.get("note", ""),
                }
        return None

    async def _fetch_upstream_cycles(self, slug: str) -> list[dict[str, Any]] | None:
        """Fetches product cycle information from endoflife.date API with Redis caching."""
        cache_key = f"sentinelscan:lifecycle:{slug}"
        if self.redis:
            try:
                cached = await self.redis.get(cache_key)
                if cached:
                    import json
                    return json.loads(cached)
            except Exception as e:
                logger.debug(f"Redis lifecycle cache read error: {e}")

        # Upstream HTTP fetch with 3.0s strict timeout
        url = f"https://endoflife.date/api/{slug}.json"
        try:
            async with httpx.AsyncClient(timeout=3.0, follow_redirects=True) as client:
                resp = await client.get(url, headers={"User-Agent": "SentinelScan-Security-Scanner/2.0"})
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        if self.redis:
                            try:
                                import json
                                await self.redis.setex(cache_key, self._cache_ttl, json.dumps(data))
                            except Exception:
                                pass
                        return data
        except Exception as e:
            logger.debug(f"Upstream lifecycle API request failed for {slug}: {e}")

        return None

    def _match_cycle(self, cycles: list[dict[str, Any]], version: str) -> dict[str, Any] | None:
        """Matches a semantic version against product cycles from upstream data."""
        today = date.today().isoformat()
        for c in cycles:
            cycle_name = str(c.get("cycle", "")).strip()
            if version == cycle_name or version.startswith(cycle_name + "."):
                eol_val = c.get("eol")
                eol_date = str(eol_val) if isinstance(eol_val, str) and len(eol_val) == 10 else None
                latest_ver = str(c.get("latest", "")) if c.get("latest") else None

                # Determine state
                if eol_val is True or (eol_date and eol_date < today):
                    status = STATE_END_OF_LIFE
                elif c.get("support") is False:
                    status = STATE_SECURITY_SUPPORT_ENDED
                elif latest_ver and version != latest_ver:
                    status = STATE_UPDATE_AVAILABLE
                else:
                    status = STATE_SUPPORTED

                return {
                    "status": status,
                    "eol_date": eol_date,
                    "latest_version": latest_ver,
                    "source": "https://endoflife.date",
                    "notes": f"Cycle {cycle_name} -- release date: {c.get('releaseDate')}",
                }
        return None


def assess_component(
    tech_name: str,
    raw_version: str | None,
    category: str,
    source: str,
    evidence: str,
    lifecycle_info: dict[str, Any],
    cves: list[dict[str, Any]] | None = None,
) -> ComponentAssessment:
    """
    Constructs a standardized ComponentAssessment record.
    """
    norm = normalize_component_version(raw_version, source=source)
    cve_list = cves or []
    
    return ComponentAssessment(
        technology=tech_name,
        category=category,
        raw_version=norm.raw_version or None,
        normalized_version=norm.normalized_version,
        vendor_suffix=norm.vendor_suffix,
        version_confidence=norm.confidence,
        source=source,
        evidence=evidence,
        lifecycle_status=lifecycle_info.get("status", STATE_VERSION_UNKNOWN),
        eol_date=lifecycle_info.get("eol_date"),
        latest_version=lifecycle_info.get("latest_version"),
        cves=cve_list,
        cve_count=len(cve_list),
        notes=lifecycle_info.get("notes", ""),
    )


def generate_component_findings(assessment: ComponentAssessment) -> list[dict[str, Any]]:
    """
    Generates structured, non-conflated security findings for component lifecycle
    and outdated versions without duplicating CVE findings.
    """
    findings: list[dict[str, Any]] = []
    tech = assessment.technology
    v = assessment.normalized_version or assessment.raw_version or "unknown"
    status = assessment.lifecycle_status
    eol_date = assessment.eol_date or "not formally published"
    source = assessment.source or "HTTP Inspection"

    # Caveat text for Linux distribution backports
    backport_note = ""
    if assessment.vendor_suffix:
        backport_note = (
            f" Note: Server banner exposes vendor package suffix '{assessment.vendor_suffix}'. "
            "Linux distributions frequently backport security fixes into older upstream release versions; "
            "verify whether distribution package updates have been applied."
        )

    if status == STATE_END_OF_LIFE:
        findings.append({
            "category": "Outdated Software / CVE",
            "title": f"{tech} {v} -- End of Life (No Security Updates)",
            "description": (
                f"{tech} version {v} has reached end-of-life (EOL date: {eol_date}) and no longer "
                "receives security patches from the vendor. Any vulnerabilities discovered in this version line "
                "will remain unaddressed by official upstream releases. "
                "This does not confirm the presence of a specific CVE — refer to CVE correlation findings."
                f"{backport_note}"
            ),
            "severity": "high",
            "confidence": assessment.version_confidence.lower() if assessment.version_confidence != CONF_UNKNOWN else "medium",
            "cvss_score": None,
            "recommendation": f"Upgrade {tech} to an actively supported release. Vendor documentation: {source}",
            "references": [assessment.evidence] if assessment.evidence else [],
            "endpoint": source,
            "evidence": f"Technology: {tech}, Version: {v}, EOL Date: {eol_date}, Status: {status}",
        })
    elif status == STATE_SECURITY_SUPPORT_ENDED:
        findings.append({
            "category": "Outdated Software / CVE",
            "title": f"{tech} {v} -- Security-Fixes-Only Maintenance Mode",
            "description": (
                f"{tech} version {v} is in maintenance mode or approaching end-of-life (EOL: {eol_date}). "
                f"It receives critical security patches only.{backport_note}"
            ),
            "severity": "low",
            "confidence": assessment.version_confidence.lower() if assessment.version_confidence != CONF_UNKNOWN else "low",
            "cvss_score": None,
            "recommendation": f"Plan migration to an actively supported {tech} release before vendor support concludes.",
            "references": [],
            "endpoint": source,
            "evidence": f"Technology: {tech}, Version: {v}, EOL Date: {eol_date}, Status: {status}",
        })
    elif status == STATE_UPDATE_AVAILABLE and assessment.latest_version:
        findings.append({
            "category": "Outdated Software / CVE",
            "title": f"{tech} {v} -- Outdated Component (Update Available: {assessment.latest_version})",
            "description": (
                f"Detected {tech} version {v}. A newer release ({assessment.latest_version}) is available "
                f"from the vendor.{backport_note}"
            ),
            "severity": "low",
            "confidence": assessment.version_confidence.lower() if assessment.version_confidence != CONF_UNKNOWN else "low",
            "cvss_score": None,
            "recommendation": f"Review release notes and upgrade {tech} to version {assessment.latest_version}.",
            "references": [],
            "endpoint": source,
            "evidence": f"Technology: {tech}, Detected Version: {v}, Latest Version: {assessment.latest_version}",
        })

    return findings


async def build_component_inventory(
    detected_technologies: dict[str, Any],
    cve_findings: list[dict[str, Any]] | None = None,
    redis_client: Any | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Builds the full component inventory and generates lifecycle findings
    for all detected technologies.
    """
    cve_findings = cve_findings or []
    provider = LifecycleProvider(redis_client=redis_client)
    inventory: list[dict[str, Any]] = []
    lifecycle_findings: list[dict[str, Any]] = []

    for tech_name, tech_data in detected_technologies.items():
        raw_v = tech_data.get("version") if isinstance(tech_data, dict) else None
        category = tech_data.get("category", "Web Framework / Server") if isinstance(tech_data, dict) else "Technology"
        source = tech_data.get("source", "HTTP Inspection") if isinstance(tech_data, dict) else "HTTP Inspection"
        evidence = tech_data.get("evidence", f"Detected {tech_name}") if isinstance(tech_data, dict) else f"Detected {tech_name}"

        # Match CVEs belonging to this technology
        matching_cves = [
            cve for cve in cve_findings
            if tech_name.lower() in (cve.get("title", "") + cve.get("description", "")).lower()
        ]

        try:
            lifecycle_info = await provider.get_lifecycle(tech_name, raw_v)
        except Exception as e:
            logger.debug(f"Lifecycle retrieval failed for {tech_name}: {e}")
            lifecycle_info = {
                "status": STATE_LIFECYCLE_UNKNOWN,
                "eol_date": None,
                "latest_version": None,
                "source": "None",
                "notes": "Provider retrieval error; fell back safely.",
            }
        assessment = assess_component(
            tech_name=tech_name,
            raw_version=raw_v,
            category=category,
            source=source,
            evidence=evidence,
            lifecycle_info=lifecycle_info,
            cves=matching_cves,
        )
        inventory.append(assessment.to_dict())
        lifecycle_findings.extend(generate_component_findings(assessment))

    return inventory, lifecycle_findings

