# Report Format

## Overview

A SentinelScan report is the primary output of a completed scan. It aggregates all findings from every scanner module into a single structured record, generates a security score, and produces a human-readable executive summary.

---

## Report Structure

```json
{
  "id": "abc123...",
  "scan_id": "7f000001...",
  "url": "https://example.com",
  "overall_score": 72,
  "grade": "B",
  "risk_level": "medium",
  "summary": "Narrative summary...",
  "tech_stack": { ... },
  "ssl_info": { ... },
  "dns_info": { ... },
  "score_breakdown": { ... },
  "executive_summary": { ... },
  "timeline": [ ... ],
  "findings": [ ... ],
  "created_at": "2024-01-15T10:30:45Z"
}
```

---

## Security Score

### Calculation

The overall score is computed from **7 weighted categories**, each capped at a maximum point value:

| Category | Max Points | Penalized By |
|---|---|---|
| SSL/TLS | 20 | TLS issues, cert expiry, weak ciphers |
| Security Headers | 20 | Missing/misconfigured headers |
| Cookies | 10 | Insecure cookie attributes |
| DNS | 15 | SPF, DMARC, DKIM issues |
| Technology Stack | 15 | CVEs, outdated components |
| Content Exposure | 10 | Exposed files, sensitive info |
| Configuration | 10 | Misconfigurations |
| **Total** | **100** | |

**Penalty weights per finding:**

| Severity | Points Deducted |
|---|---|
| Critical | 25 |
| High | 10 |
| Medium | 5 |
| Low | 2 |
| Info | 0 |

**Formula:** For each category, start at `max_points`. Subtract penalties for each finding in that category. Floor at 0. Sum all categories.

**`info`-severity findings** (passing controls) contribute 0 penalty and are excluded from deduction.

### Grade Thresholds

| Score | Grade | Risk Level |
|---|---|---|
| 90–100 | A+ | Low |
| 80–89 | A | Low |
| 70–79 | B | Medium |
| 60–69 | C | Medium |
| 50–59 | D | High |
| 0–49 | F | Critical |

---

## Finding Schema

Every finding is a structured record:

```json
{
  "id": "uuid",
  "category": "Security Headers",
  "title": "Missing Content-Security-Policy",
  "description": "No Content-Security-Policy header found. Without CSP, ...",
  "severity": "high",
  "status": "open",
  "confidence": "high",
  "cvss_score": 6.1,
  "cve_id": null,
  "cwe_id": "CWE-693",
  "endpoint": "/",
  "recommendation": "Add a Content-Security-Policy header...",
  "problem": "Root cause explanation",
  "impact": "An attacker can inject malicious scripts...",
  "risk_analysis": "This affects all browsers...",
  "technical_details": "The CSP header should restrict...",
  "fix_steps": [
    "Add the header: Content-Security-Policy: default-src 'self'",
    "Test using CSP Evaluator at csp-evaluator.withgoogle.com",
    "Start with report-only mode: Content-Security-Policy-Report-Only"
  ],
  "configuration_example": "Content-Security-Policy: default-src 'self'; ...",
  "best_practices": "Use nonces instead of 'unsafe-inline'...",
  "official_documentation": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
  "references": [
    "https://owasp.org/www-project-secure-headers/",
    "https://content-security-policy.com/"
  ],
  "evidence": "Header not present in HTTP response from https://example.com",
  "owasp_mapping": {
    "id": "A02:2025",
    "title": "Security Misconfiguration",
    "description": "...",
    "reference": "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/"
  },
  "mitre_mapping": {
    "technique_id": "T1189",
    "technique_name": "Drive-by Compromise",
    "description": "...",
    "reference": "https://attack.mitre.org/techniques/T1189/"
  },
  "is_passed_control": false,
  "created_at": "2024-01-15T10:30:45Z"
}
```

### Severity Values

| Value | CVSS Range | Description |
|---|---|---|
| `critical` | 9.0–10.0 | Immediate exploitation risk, data breach |
| `high` | 7.0–8.9 | Significant risk, likely exploitable |
| `medium` | 4.0–6.9 | Moderate risk, requires specific conditions |
| `low` | 0.1–3.9 | Limited risk, defense-in-depth |
| `info` | 0.0 | Informational — passing control or observation |

### Confidence Values

| Value | Meaning |
|---|---|
| `high` | Finding confirmed with strong evidence |
| `medium` | Finding likely correct; some uncertainty |
| `low` | Cannot confirm definitively (e.g. DKIM with custom selectors) |

### Finding Status

| Value | Set By | Meaning |
|---|---|---|
| `open` | System | Default on creation |
| `accepted_risk` | User | User acknowledges and accepts the risk |
| `resolved` | User | Finding has been remediated |
| `false_positive` | User | User determined this is a false positive |

---

## Score Breakdown

The `score_breakdown` field provides per-category detail:

```json
{
  "ssl_tls": {
    "label": "SSL / TLS",
    "score": 18,
    "max": 20,
    "percentage": 90.0,
    "color": "green",
    "findings_count": 1,
    "icon": "Lock"
  },
  "security_headers": {
    "label": "Security Headers",
    "score": 10,
    "max": 20,
    "percentage": 50.0,
    "color": "yellow",
    "findings_count": 4,
    "icon": "Shield"
  }
}
```

---

## Executive Summary

The `executive_summary` field contains a structured business-focused analysis:

```json
{
  "overall_risk": "medium",
  "business_impact": "Moderate security posture. Several misconfigurations...",
  "strengths": [
    "Valid SSL certificate with 180 days remaining",
    "HSTS enabled with includeSubDomains"
  ],
  "weaknesses": [
    "Missing Content-Security-Policy",
    "No DMARC enforcement"
  ],
  "critical_issues": [],
  "quick_wins": [
    "Add X-Content-Type-Options: nosniff (5 minute fix)",
    "Enable DMARC quarantine policy"
  ],
  "priority_fixes": [
    "Implement Content-Security-Policy header",
    "Enable email authentication enforcement (DMARC p=quarantine)"
  ],
  "security_posture": "The site has a solid SSL/TLS foundation but is missing..."
}
```

---

## Scan Timeline

The `timeline` field records per-stage timing:

```json
[
  {"stage": "queued", "label": "Queued", "status": "completed", "duration_ms": 120},
  {"stage": "dns", "label": "DNS Analysis", "status": "completed", "duration_ms": 410},
  {"stage": "ssl", "label": "SSL/TLS Check", "status": "completed", "duration_ms": 820},
  {"stage": "headers", "label": "Security Headers", "status": "completed", "duration_ms": 350},
  {"stage": "technology", "label": "Technology Detection", "status": "completed", "duration_ms": 680},
  {"stage": "cve", "label": "CVE Database Lookup", "status": "completed", "duration_ms": 940},
  {"stage": "content", "label": "Content Analysis", "status": "completed", "duration_ms": 530},
  {"stage": "scoring", "label": "Scoring Engine", "status": "completed", "duration_ms": 180},
  {"stage": "completed", "label": "Scan Completed", "status": "completed", "timestamp": "2024-01-15T10:30:45Z"}
]
```

---

## PDF Report

### Generation

PDFs are generated on-demand via `GET /api/reports/{id}/pdf` using **ReportLab 4.2**.

The PDF includes:
- Cover page with SentinelScan branding and scan metadata
- Executive summary narrative
- Security score ring and grade
- Category score breakdown table
- Findings organized by severity
- Per-finding detail (description, evidence, CVSS, OWASP mapping, remediation)
- Tech stack summary
- SSL/TLS certificate details
- DNS analysis summary
- Recommendations and next steps

### File Naming

```
Content-Disposition: attachment; filename="sentinelscan-report-{scan_id}.pdf"
```

### Limitations

- PDFs are generated in real-time on each request; not cached
- Very large reports (100+ findings) may take 3–5 seconds to generate
- PDF visual rendering uses ReportLab's canvas API; not HTML-to-PDF

---

## JSON Export

The full report JSON is available via `GET /api/reports/{id}`. This is suitable for:
- Integration with other security tools
- Custom report generation
- Data export and archival

---

## OWASP Top 10 Mapping

Every finding is mapped to the nearest OWASP Top 10:2025 category by `threat_intel.py`. The mapping is stored in `owasp_mapping` and used by the OWASP view in the frontend.

| OWASP ID | Category |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |
