"""
Advanced Security Score Calculator
Computes a weighted per-category score and letter grade from all findings.

Categories and max points:
  SSL/TLS            20
  Security Headers   20
  Cookies            10
  DNS                15
  Technology Stack   15
  Content Exposure   10
  Configuration      10
  Total             100
"""
from typing import Any


GRADE_THRESHOLDS = [
    (90, "A+"), (80, "A"), (70, "B"), (60, "C"), (50, "D"), (0, "F"),
]

# ─── Category definitions ────────────────────────────────────────────────────

SCORE_CATEGORIES = {
    "ssl_tls": {
        "label": "SSL / TLS",
        "max": 20,
        "keywords": ["ssl", "tls", "transport security", "certificate", "cipher", "https"],
        "icon": "Lock",
    },
    "security_headers": {
        "label": "Security Headers",
        "max": 20,
        "keywords": [
            "injection prevention", "clickjacking protection",
            "mime sniffing", "xss protection", "isolation", "feature control",
            "content-security-policy", "x-frame-options", "referrer", "permissions",
            "cors",
        ],
        "icon": "Shield",
    },
    "cookies": {
        "label": "Cookies",
        "max": 10,
        "keywords": ["cookie"],
        "icon": "Cookie",
    },
    "dns": {
        "label": "DNS",
        "max": 15,
        "keywords": ["dns", "spf", "dmarc", "dkim", "mx", "email auth"],
        "icon": "Globe",
    },
    "technology_stack": {
        "label": "Technology Stack",
        "max": 15,
        "keywords": ["cve", "technology", "vulnerable", "outdated", "component"],
        "icon": "Cpu",
    },
    "content_exposure": {
        "label": "Content Exposure",
        "max": 10,
        "keywords": ["content", "information disclosure", "exposed", "sensitive", "privacy"],
        "icon": "Eye",
    },
    "configuration": {
        "label": "Configuration",
        "max": 10,
        "keywords": ["configuration", "misconfiguration", "connectivity"],
        "icon": "Settings",
    },
}

# Severity penalty weights (per-finding within a category)
SEVERITY_WEIGHTS = {"critical": 25, "high": 10, "medium": 5, "low": 2, "info": 0}

# Color thresholds for category scores
def _color(pct: float) -> str:
    if pct >= 80:
        return "green"
    if pct >= 60:
        return "yellow"
    if pct >= 40:
        return "orange"
    return "red"


def _map_finding_to_category(finding: dict) -> str:
    """Map a finding to a scoring category key."""
    cat = (finding.get("category") or "").lower()
    title = (finding.get("title") or "").lower()
    combined = f"{cat} {title}"

    for cat_key, spec in SCORE_CATEGORIES.items():
        for kw in spec["keywords"]:
            if kw in combined:
                return cat_key

    return "configuration"  # fallback


def calculate_score(findings: list[dict]) -> dict[str, Any]:
    """Compute weighted category scores and overall grade from a list of findings."""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # Initialise per-category penalty accumulators
    category_penalties: dict[str, float] = {k: 0.0 for k in SCORE_CATEGORIES}
    category_recommendations: dict[str, list[str]] = {k: [] for k in SCORE_CATEGORIES}
    category_deductions: dict[str, list[dict]] = {k: [] for k in SCORE_CATEGORIES}

    for finding in findings:
        if finding.get("is_passed_control"):
            continue

        sev = (finding.get("severity") or "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

        if sev == "info":
            continue  # info findings never incur a penalty

        cat_key = _map_finding_to_category(finding)
        max_pts = SCORE_CATEGORIES[cat_key]["max"]

        # Scale global severity weight to category max
        weight = SEVERITY_WEIGHTS.get(sev, 0)
        scaled = (weight / 25.0) * max_pts * 0.6
        category_penalties[cat_key] = min(
            category_penalties[cat_key] + scaled, max_pts
        )

        category_deductions[cat_key].append({
            "finding_title": finding.get("title", ""),
            "severity": sev,
            "points_deducted": round(scaled, 1),
        })

        rec = finding.get("recommendation")
        if rec and rec not in category_recommendations[cat_key]:
            category_recommendations[cat_key].append(rec)

    # Build per-category scores
    category_scores: dict[str, dict] = {}
    total_score = 0
    total_max = 0

    for cat_key, spec in SCORE_CATEGORIES.items():
        max_pts = spec["max"]
        raw_score = max(0.0, max_pts - category_penalties[cat_key])
        score = round(raw_score)
        pct = round((score / max_pts) * 100)
        category_scores[cat_key] = {
            "label": spec["label"],
            "score": score,
            "max": max_pts,
            "pct": pct,
            "color": _color(pct),
            "recommendations": category_recommendations[cat_key][:3],
            "deductions": category_deductions[cat_key],
            "icon": spec["icon"],
        }
        total_score += score
        total_max += max_pts

    overall_score = max(0, min(100, round(total_score)))

    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if overall_score >= threshold:
            grade = letter
            break

    if severity_counts["critical"] > 0:
        risk_level = "critical"
    elif severity_counts["high"] > 0:
        risk_level = "high"
    elif severity_counts["medium"] > 0:
        risk_level = "medium"
    elif severity_counts["low"] > 0:
        risk_level = "low"
    else:
        risk_level = "info"

    return {
        "overall_score": overall_score,
        "grade": grade,
        "risk_level": risk_level,
        "severity_counts": severity_counts,
        "total_findings": len(findings),
        "category_scores": category_scores,
    }


def generate_executive_summary(url: str, score: int, grade: str, severity_counts: dict, tech_stack: dict) -> str:
    tech_list = ", ".join(list(tech_stack.keys())[:5]) if tech_stack else "Unknown"
    severity_summary = ", ".join(
        f"{count} {sev}" for sev, count in severity_counts.items() if count > 0 and sev != "info"
    )
    # Risk qualifier MUST align with the risk_level logic used by calculate_score().
    # Derive from severity counts (same source of truth as risk_level field) rather than
    # arbitrary score bands that can produce contradictory statements (e.g. score=74
    # with high-severity findings previously yielding "low risk" which directly contradicts
    # the HIGH RISK badge shown on the cover and throughout the report).
    crit = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    med  = severity_counts.get("medium", 0)
    low  = severity_counts.get("low", 0)
    if crit > 0:
        risk_qualifier = "critical risk"
    elif high > 0:
        risk_qualifier = "high risk"
    elif med > 0:
        risk_qualifier = "moderate risk"
    elif low > 0:
        risk_qualifier = "low risk"
    else:
        risk_qualifier = "a strong security posture"
    return (
        f"SentinelScan performed a comprehensive security assessment of {url}. "
        f"The site received an overall security score of {score}/100 (Grade: {grade}), "
        f"indicating {risk_qualifier}. "
        f"The technology stack includes: {tech_list}. "
        f"{'The assessment identified ' + severity_summary + ' issues.' if severity_summary else 'No significant issues were identified.'} "
        f"Immediate attention is recommended for all Critical and High severity findings. "
        f"This report provides detailed recommendations to improve the security posture."
    )


def generate_enriched_executive_summary(url: str, score: int, grade: str, severity_counts: dict, findings: list[dict], category_scores: dict) -> dict[str, Any]:
    """Generates an 8-section professional executive summary dict for security consulting reports."""
    crit_count = severity_counts.get("critical", 0)
    high_count = severity_counts.get("high", 0)
    med_count = severity_counts.get("medium", 0)
    low_count = severity_counts.get("low", 0)

    # Strengths (categories with pct >= 80)
    strengths = [
        f"{c['label']}: Secured with {c['score']}/{c['max']} pts ({c['pct']}%)"
        for c in category_scores.values() if c.get("pct", 0) >= 80
    ]
    if not strengths:
        strengths = ["Target responds to standard network requests without connection drops."]

    # Weaknesses (categories with pct < 70)
    weaknesses = [
        f"{c['label']}: Incomplete hardening ({c['score']}/{c['max']} pts, {c['pct']}%)"
        for c in category_scores.values() if c.get("pct", 0) < 70
    ]
    if not weaknesses:
        weaknesses = ["No major systemic security weakness detected in primary categories."]

    # Critical Issues & Priority Fixes
    crit_findings = [f["title"] for f in findings if (f.get("severity") or "").lower() in ("critical", "high")][:5]
    # Derive quick wins from actual findings rather than returning a hardcoded list.
    # Quick wins are low-to-medium severity findings with actionable recommendations
    # that don't require architectural changes — sorted by impact (medium first).
    _QUICK_WIN_CATEGORIES = {
        "Injection Prevention", "Clickjacking Protection", "MIME Sniffing Prevention",
        "Privacy", "Feature Control", "Isolation", "Transport Security",
        "Cookie Security", "Email Security",
    }
    quick_wins = []
    seen_recs: set[str] = set()
    for f in sorted(findings, key=lambda x: (0 if (x.get("severity") or "").lower() == "medium" else 1)):
        sev = (f.get("severity") or "").lower()
        rec = (f.get("recommendation") or "").strip()
        cat = (f.get("category") or "").strip()
        if sev in ("medium", "low") and rec and rec not in seen_recs and cat in _QUICK_WIN_CATEGORIES:
            quick_wins.append(rec)
            seen_recs.add(rec)
        if len(quick_wins) >= 3:
            break
    # Fallback: if no actionable findings match, provide generic guidance
    if not quick_wins:
        quick_wins = [
            "Implement a Content Security Policy header",
            "Enable HTTP Strict Transport Security (HSTS)",
            "Set Secure & HttpOnly attributes on all session cookies",
        ]

    overall_risk = "CRITICAL RISK" if crit_count > 0 or score < 50 else "HIGH RISK" if high_count > 0 or score < 65 else "MEDIUM RISK" if med_count > 0 or score < 80 else "LOW RISK"

    business_impact = (
        "High risk of business disruption, reputational damage, and customer data exposure. "
        "Immediate remediation is required to satisfy compliance frameworks (OWASP Top 10, ISO 27001, PCI-DSS)."
        if score < 70 else
        "Low to Moderate exposure. Application meets foundational security baselines but retains minor configuration gaps that could be leveraged during targeted multi-stage attacks."
    )

    security_posture = (
        f"Target {url} achieved an overall security rating of {score}/100 (Grade {grade}). "
        f"The evaluation uncovered {crit_count} Critical, {high_count} High, and {med_count} Medium severity vulnerabilities across tested attack vectors."
    )

    return {
        "overall_risk": overall_risk,
        "business_impact": business_impact,
        "strengths": strengths,
        "weaknesses": weaknesses,
        "critical_issues": crit_findings if crit_findings else ["No critical vulnerabilities detected."],
        "quick_wins": quick_wins,
        "priority_fixes": [f"Remediate {title}" for title in crit_findings] if crit_findings else ["Implement security header hardening across web servers."],
        "security_posture": security_posture,
    }

