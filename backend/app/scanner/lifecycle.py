"""
Lifecycle / End-of-Life (EOL) Assessment

Checks whether a detected technology version is within its active support window,
approaching end-of-life, or already end-of-life based on vendor published lifecycle data.

Scope Constraint
----------------
This module only covers technologies for which:
  (a) the version is reliably extractable via passive HTTP response analysis, AND
  (b) the vendor publishes or has historically published explicit EOL dates.

Technologies whose versions cannot be reliably extracted passively (e.g. Django, Rails,
Node.js when the version is not disclosed in a header) are NOT assessed. Do not add entries
for technologies without reliable passive version signals.

Data Provenance
---------------
All lifecycle dates are sourced from official vendor lifecycle pages or their archived
equivalents. The source URL is recorded in each entry's "source" field.

Date format: ISO 8601 (YYYY-MM-DD).

Last curated: 2026-09-07 (verified against live vendor pages).
Always cross-reference against the official source before modifying entries.

IMPORTANT — WordPress-specific constraint
-----------------------------------------
WordPress does NOT publish formal end-of-life dates for any release branch.
The project provides security patches to all maintained branches on an ongoing
basis (multiple branches patched simultaneously). "Status" labels in this
database are editorial approximations based on the current release cadence:
  - Only the latest major release is labelled "active" (full support).
  - Prior majors that still receive security patches are labelled
    "security-only" (patches released alongside the latest major).
  - Branches for which no patch activity has been observed in the release
    archive for a substantial period are labelled "eol".
Because no formal EOL dates are published, all WordPress eol_date fields are
set to None. This prevents the scanner from asserting a specific date that
cannot be authoritatively sourced.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any


# -- Lifecycle Database -------------------------------------------------------
#
# Structure per technology:
#
#   {
#       "tech_name": [
#           {
#               "version_prefix": str,      # e.g. "8.1" matches "8.1.x"
#               "eol_date":       str,       # ISO 8601 date -- last day of active support
#               "status":         str,       # "active" | "security-only" | "eol"
#               "note":           str,       # human-readable label
#               "source":         str,       # authoritative URL
#           },
#           ...
#       ],
#       ...
#   }
#
# "security-only" means the branch receives critical security patches only (no feature/bug
# fixes). This is sometimes called "maintenance mode" or "long-term support" depending on
# the vendor. It is still better than "eol" but operators should plan for migration.
#
# Entries are ordered most-recent first within each technology.

_LIFECYCLE_DB: dict[str, list[dict[str, str]]] = {

    # -- PHP -------------------------------------------------------------------
    # Source: https://www.php.net/supported-versions.php
    # Last verified: 2025-08-01
    "PHP": [
        {"version_prefix": "8.4", "eol_date": "2028-11-30", "status": "active",        "note": "Active support",          "source": "https://www.php.net/supported-versions.php"},
        {"version_prefix": "8.3", "eol_date": "2027-11-30", "status": "active",        "note": "Active support",          "source": "https://www.php.net/supported-versions.php"},
        {"version_prefix": "8.2", "eol_date": "2026-12-08", "status": "active",        "note": "Active support",          "source": "https://www.php.net/supported-versions.php"},
        {"version_prefix": "8.1", "eol_date": "2025-12-31", "status": "security-only", "note": "Security fixes only",     "source": "https://www.php.net/supported-versions.php"},
        {"version_prefix": "8.0", "eol_date": "2023-11-26", "status": "eol",           "note": "End of life",             "source": "https://www.php.net/eol.php"},
        {"version_prefix": "7.4", "eol_date": "2022-11-28", "status": "eol",           "note": "End of life",             "source": "https://www.php.net/eol.php"},
        {"version_prefix": "7.3", "eol_date": "2021-12-06", "status": "eol",           "note": "End of life",             "source": "https://www.php.net/eol.php"},
        {"version_prefix": "7.2", "eol_date": "2020-11-30", "status": "eol",           "note": "End of life",             "source": "https://www.php.net/eol.php"},
        {"version_prefix": "7.1", "eol_date": "2019-12-01", "status": "eol",           "note": "End of life",             "source": "https://www.php.net/eol.php"},
        {"version_prefix": "7.0", "eol_date": "2019-01-10", "status": "eol",           "note": "End of life",             "source": "https://www.php.net/eol.php"},
        {"version_prefix": "5",   "eol_date": "2018-12-31", "status": "eol",           "note": "End of life",             "source": "https://www.php.net/eol.php"},
    ],

    # -- Nginx -----------------------------------------------------------------
    # Source: https://nginx.org/en/download.html
    # Nginx follows "stable" (even minor) and "mainline" (odd minor) release lines.
    # Only the latest stable branch receives security backports; older stables are EOL.
    #
    # Note on eol_date for Nginx: Nginx does not publish formal EOL dates.
    # The dates below represent the release date of the successor stable branch
    # (i.e. when the previous stable was superseded), derived from the download
    # changelog at nginx.org/en/download.html. They are accurate supersession
    # dates, not vendor-published end-of-life dates.
    # Last verified: 2026-09-07
    "Nginx": [
        {"version_prefix": "1.27", "eol_date": None,          "status": "active",  "note": "Mainline branch (feature/security; no formal EOL date)", "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.26", "eol_date": None,          "status": "active",  "note": "Stable branch (current; no formal EOL date published)", "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.25", "eol_date": "2024-05-28", "status": "eol",     "note": "Superseded by 1.26 stable",          "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.24", "eol_date": "2024-05-28", "status": "eol",     "note": "Superseded by 1.26 stable",          "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.23", "eol_date": "2023-05-24", "status": "eol",     "note": "End of life",                        "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.22", "eol_date": "2023-05-24", "status": "eol",     "note": "End of life",                        "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.20", "eol_date": "2022-05-24", "status": "eol",     "note": "End of life",                        "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.18", "eol_date": "2021-04-20", "status": "eol",     "note": "End of life",                        "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.16", "eol_date": "2020-04-21", "status": "eol",     "note": "End of life",                        "source": "https://nginx.org/en/download.html"},
        {"version_prefix": "1.14", "eol_date": "2019-04-23", "status": "eol",     "note": "End of life",                        "source": "https://nginx.org/en/download.html"},
    ],

    # -- Apache HTTP Server ----------------------------------------------------
    # Source: https://httpd.apache.org/download.cgi
    # Apache only actively supports the current stable release line (2.4).
    # 2.2 and 2.0 have been EOL since 2017 and 2013 respectively.
    # Apache does NOT publish a formal EOL date for the 2.4 branch; it is the
    # current maintained line with no announced end date. eol_date is None to
    # avoid asserting a date that cannot be authoritatively sourced.
    # Last verified: 2026-09-07
    "Apache": [
        {"version_prefix": "2.4",  "eol_date": None,          "status": "active",  "note": "Current stable release line (no formal EOL date published)", "source": "https://httpd.apache.org/download.cgi"},
        {"version_prefix": "2.2",  "eol_date": "2017-12-31",  "status": "eol",     "note": "End of life (Dec 2017)",                                       "source": "https://httpd.apache.org/download.cgi"},
        {"version_prefix": "2.0",  "eol_date": "2013-07-10",  "status": "eol",     "note": "End of life (Jul 2013)",                                       "source": "https://httpd.apache.org/download.cgi"},
        {"version_prefix": "1.",   "eol_date": "2010-02-02",  "status": "eol",     "note": "End of life",                                                 "source": "https://httpd.apache.org/download.cgi"},
    ],

    # -- Microsoft IIS ---------------------------------------------------------
    # IIS lifecycle is tied to the Windows Server lifecycle it ships with.
    # Source: https://learn.microsoft.com/en-us/lifecycle/products/
    # Last verified: 2025-08-01
    "IIS": [
        {"version_prefix": "10.0", "eol_date": "2031-10-14", "status": "active",  "note": "Windows Server 2019/2022 -- active",        "source": "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2022"},
        {"version_prefix": "8.5",  "eol_date": "2023-10-10", "status": "eol",     "note": "Windows Server 2012 R2 -- EOL Oct 2023",    "source": "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2012-r2"},
        {"version_prefix": "8.0",  "eol_date": "2023-10-10", "status": "eol",     "note": "Windows Server 2012 -- EOL Oct 2023",       "source": "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2012"},
        {"version_prefix": "7.5",  "eol_date": "2020-01-14", "status": "eol",     "note": "Windows Server 2008 R2 -- EOL Jan 2020",    "source": "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2"},
        {"version_prefix": "7.0",  "eol_date": "2015-01-13", "status": "eol",     "note": "Windows Server 2008 -- EOL Jan 2015",       "source": "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008"},
        {"version_prefix": "6.",   "eol_date": "2015-07-14", "status": "eol",     "note": "Windows Server 2003 -- EOL Jul 2015",       "source": "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003"},
    ],

    # -- WordPress -------------------------------------------------------------
    # Source: https://wordpress.org/documentation/article/wordpress-versions/
    # Last verified: 2026-09-07 (live page, last modified 2026-08-19)
    #
    # WordPress does NOT publish formal EOL dates for any release branch.
    # Multiple branches receive simultaneous security patches with each release.
    # As of 2026-09-07, the live release archive shows ALL branches from 6.0
    # onward receiving patches alongside the current 7.1 release.
    #
    # Status labels are editorial approximations:
    #   "active"        = the current latest major release (7.x at time of writing)
    #   "security-only" = prior major branches still receiving security patches
    #                     alongside current release
    #   "eol"           = branches for which the last observed patch is
    #                     substantially old and no further activity is documented
    #
    # All eol_date values are None — no authoritatively sourced dates exist.
    #
    # IMPORTANT: This database must be updated when the release archive changes.
    # The current release family changes with each WordPress major release.
    "WordPress": [
        {"version_prefix": "7.1",  "eol_date": None, "status": "active",        "note": "Current release (7.1 — Mary Lou, Aug 2026)",                                         "source": "https://wordpress.org/news/2026/08/mary-lou/"},
        {"version_prefix": "7.0",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.9",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.8",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.7",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.6",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.5",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.4",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.3",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.2",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.1",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "6.0",  "eol_date": None, "status": "security-only", "note": "Security patches released alongside current major (verified Aug 2026)",             "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "5.",   "eol_date": None, "status": "eol",           "note": "WordPress 5.x -- no patch activity in 2026 release archive",                       "source": "https://wordpress.org/documentation/article/wordpress-versions/"},
        {"version_prefix": "4.",   "eol_date": None, "status": "eol",           "note": "WordPress 4.x -- end of life",                                                      "source": "https://wordpress.org/documentation/article/wordpress-versions-0-7-to-4-9/"},
    ],

    # -- Python ----------------------------------------------------------------
    # Source: https://devguide.python.org/versions/
    "Python": [
        {"version_prefix": "3.13", "eol_date": "2029-10-31", "status": "active",        "note": "Active support",          "source": "https://devguide.python.org/versions/"},
        {"version_prefix": "3.12", "eol_date": "2028-10-31", "status": "active",        "note": "Active support",          "source": "https://devguide.python.org/versions/"},
        {"version_prefix": "3.11", "eol_date": "2027-10-31", "status": "active",        "note": "Active support",          "source": "https://devguide.python.org/versions/"},
        {"version_prefix": "3.10", "eol_date": "2026-10-31", "status": "security-only", "note": "Security fixes only",     "source": "https://devguide.python.org/versions/"},
        {"version_prefix": "3.9",  "eol_date": "2025-10-31", "status": "security-only", "note": "Security fixes only",     "source": "https://devguide.python.org/versions/"},
        {"version_prefix": "3.8",  "eol_date": "2024-10-07", "status": "eol",           "note": "End of life",             "source": "https://devguide.python.org/versions/"},
        {"version_prefix": "2.7",  "eol_date": "2020-01-01", "status": "eol",           "note": "End of life",             "source": "https://devguide.python.org/versions/"},
    ],
}

# Number of days before EOL at which to emit an "approaching EOL" warning.
_EOL_WARNING_DAYS = 180


def _version_matches_prefix(detected: str, prefix: str) -> bool:
    """
    Returns True if detected begins with prefix.

    Examples:
        "8.2.26" matches prefix "8.2"   -> True
        "8.2.26" matches prefix "8.3"   -> False
        "5.6.40" matches prefix "5"     -> True
        "1.14.3" matches prefix "1.14"  -> True
    """
    detected_clean = re.match(r'^([0-9.]+)', detected)
    if not detected_clean:
        return False
    detected_str = detected_clean.group(1).rstrip('.')
    prefix_str = prefix.rstrip('.')
    return detected_str == prefix_str or detected_str.startswith(prefix_str + '.')


def get_lifecycle_status(tech_name: str, version: str | None) -> dict[str, Any] | None:
    """
    Returns EOL/lifecycle assessment for a detected technology and version.

    Returns None when:
    - The technology is not in the lifecycle database (not assessed).
    - The version is None or empty (cannot be determined passively).

    Never raises -- on any error returns None (scanner pipeline must not be
    interrupted by a missing lifecycle entry).

    Return value structure when assessment is available:
        {
            "status": "active" | "security-only" | "eol" | "approaching-eol",
            "eol_date": "YYYY-MM-DD" | None,
            "note": str,
            "source": str,
            "version_assessed": str,
        }
    """
    if not version:
        return None

    entries = _LIFECYCLE_DB.get(tech_name)
    if not entries:
        return None

    try:
        for entry in entries:
            if _version_matches_prefix(version, entry["version_prefix"]):
                status = entry["status"]
                eol_date_str = entry.get("eol_date")

                # Check if "active" is actually approaching EOL
                if status == "active" and eol_date_str:
                    try:
                        eol = date.fromisoformat(eol_date_str)
                        today = date.today()
                        if (eol - today).days <= _EOL_WARNING_DAYS:
                            status = "approaching-eol"
                    except ValueError:
                        pass

                return {
                    "status": status,
                    "eol_date": eol_date_str,
                    "note": entry.get("note", ""),
                    "source": entry.get("source", ""),
                    "version_assessed": version,
                }
    except Exception:
        return None

    return None


def build_lifecycle_finding(tech_name: str, version: str, lifecycle: dict[str, Any]) -> dict[str, Any] | None:
    """
    Converts a lifecycle assessment result into a scanner finding dict if warranted.

    Returns None for "active" status (no finding needed).
    """
    status = lifecycle.get("status")
    # eol_date may be None for technologies that do not publish formal EOL dates
    # (e.g. WordPress, Apache 2.4). Use "not formally published" as the display
    # fallback so the rendered finding text is always accurate.
    eol_date_raw = lifecycle.get("eol_date")
    eol_date = eol_date_raw if eol_date_raw else "not formally published"
    source = lifecycle.get("source", "")

    if status == "active":
        return None

    if status == "eol":
        severity = "high"
        title = f"{tech_name} {version} -- End of Life (No Security Updates)"
        description = (
            f"{tech_name} version {version} reached end-of-life on {eol_date} and no longer "
            "receives security patches. Any vulnerabilities discovered in this version line "
            "after the EOL date will not be patched by the vendor. "
            "This does not confirm the presence of a specific CVE — use CVE correlation "
            "results for known vulnerability findings."
        )
        recommendation = (
            f"Upgrade {tech_name} to a currently supported release as soon as possible. "
            f"Check the official lifecycle page for supported versions: {source}"
        )
    elif status == "approaching-eol":
        severity = "medium"
        title = f"{tech_name} {version} -- Approaching End of Life ({eol_date})"
        description = (
            f"{tech_name} version {version} is approaching its end-of-life date ({eol_date}). "
            "After this date it will no longer receive security patches."
        )
        recommendation = (
            f"Plan migration to a currently supported {tech_name} release before {eol_date}. "
            f"Official lifecycle schedule: {source}"
        )
    elif status == "security-only":
        severity = "low"
        title = f"{tech_name} {version} -- Security-Fixes-Only Maintenance Mode"
        description = (
            f"{tech_name} version {version} is in security-fixes-only maintenance mode "
            f"(EOL: {eol_date}). It receives critical security patches only -- no bug fixes "
            "or new features."
        )
        recommendation = (
            f"Consider upgrading to an actively supported {tech_name} release. "
            f"Official lifecycle schedule: {source}"
        )
    else:
        return None

    return {
        "category": "Outdated Software / CVE",
        "title": title,
        "description": description,
        "severity": severity,
        "cvss_score": None,
        "confidence": "medium",
        "recommendation": recommendation,
        "references": [source] if source else [],
        "evidence": f"Detected {tech_name} version {version} -- lifecycle status: {status} (EOL: {eol_date})",
    }
