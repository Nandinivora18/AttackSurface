# Known Limitations

This document provides an honest assessment of SentinelScan's current limitations. Accuracy is more important than appearing comprehensive.

---

## Scanning Scope

### Passive Scanning Only

SentinelScan performs **passive, non-destructive** scanning only. It never:

- Submits forms or user-supplied input
- Performs authenticated browsing (no session injection)
- Attempts SQL injection, XSS injection, or any exploit payloads
- Crawls multiple pages (single-page analysis only)
- Performs port scanning beyond port 443 for TLS

**Impact:** Many vulnerability classes are undetectable by passive scanning:

- Application logic flaws
- Authenticated-only vulnerabilities
- Injection vulnerabilities (SQL, XSS, command injection)
- Business logic issues
- Server-side vulnerabilities requiring request crafting
- IDOR vulnerabilities within the application

---

## DNS Limitations

### DKIM Cannot Be Confirmed Absent

DKIM uses custom per-organization selectors. SentinelScan probes 9 common selectors (`default`, `google`, `mail`, `k1`, `s1`, `s2`, `dkim`, `selector1`, `selector2`). If your mail provider uses a custom selector (e.g. `mailchimp`, `em1234`), the probe will fail but DKIM is actually configured.

**Result:** DKIM detection reports `confidence: low` with an explicit caveat. This is a fundamental limitation of passive DNS enumeration.

**What to do:** Use your mail provider's admin panel or [mail-tester.com](https://mail-tester.com) to confirm DKIM status.

### DNS Caching

DNS results are not cached between scans. If DNS changes occur between scans, each scan reflects the current DNS state at the time it ran.

---

## SSL/TLS Limitations

### Port 443 Only

TLS analysis only connects on port 443. Non-standard HTTPS ports (e.g. 8443) are not evaluated.

### No OCSP/CRL Checking

Certificate revocation status is not checked (no OCSP or CRL lookup).

### No Certificate Transparency Monitoring

SentinelScan does not verify whether certificates are logged in Certificate Transparency logs.

### Python SSL Library

TLS analysis is limited to what Python's `ssl` module exposes. Advanced TLS features (cipher ordering preference, TLS 1.3 session tickets, 0-RTT) are not assessed.

---

## Technology Detection Limitations

### Detection Depends on Observable Signals

Technology fingerprinting only works if the technology reveals itself through:
- HTTP headers
- HTML source code (meta tags, script/link tags, data attributes)
- Cookie names
- URL patterns

Obfuscated or hardened deployments that suppress all signals cannot be fingerprinted.

### 23 Technologies Supported

The signature database covers 23 technologies. Less common frameworks, custom CMS platforms, obscure e-commerce systems, and in-house frameworks will not be detected.

### Version Extraction Is Best-Effort

Version strings are only extracted when they appear in predictable locations (e.g. `jquery-3.2.1.min.js`, WordPress generator meta tag). Many technologies do not expose version information in standard locations.

### CVE Lookup Is Keyword-Based

NVD API queries use `{technology_name} {version}` keyword search. This may:
- Return false positives (CVEs for other products mentioning similar keywords)
- Miss CVEs with unusual product names in NVD
- Be incomplete for very recent CVEs (NVD indexing lag)

---

## Content Analysis Limitations

### Single Page Analysis

Only the target URL and a fixed set of 15 sensitive paths are probed. The scanner does not crawl linked pages.

### Soft-404 Heuristics Are Not Foolproof

The soft-404 detector uses token-overlap heuristics to classify custom 200-response error pages. Unusual error page designs may occasionally produce false positives (finding reported) or false negatives (finding suppressed).

### Rate-Limited Targets

Some servers rate-limit rapid requests. The content analyzer makes sequential HTTP probes; aggressive rate limiting may cause timeouts or incomplete results.

---

## CDN and Proxy Limitations

### Cloudflare and Other CDNs

When a site is behind Cloudflare or a similar CDN/WAF:

- The Server header reflects the CDN, not the origin server
- SSL certificates are the CDN's certificates, not the origin's
- Sensitive file probes may be blocked by the WAF (correct: no real exposure)
- Security headers may be injected by the CDN (not set by the application itself)

**Impact:** Reports for Cloudflare-protected sites may undercount vulnerabilities that only exist on the origin server and are masked by CDN protections.

### Reverse Proxies

If the application sits behind Nginx/Apache as a reverse proxy, headers set by the proxy (e.g. `X-Frame-Options: SAMEORIGIN`) may mask header misconfigurations in the actual application.

---

## Authentication Limitations

### No Authenticated Scanning

SentinelScan does not support authenticating to the target application (no cookie/session injection, no form-based login). This means:

- Vulnerabilities behind login walls are completely invisible
- Authenticated API endpoints are not tested
- User-role-specific pages are not analyzed

Authenticated scanning is on the [v1.1 roadmap](Roadmap.md).

---

## False Negative Sources

A **false negative** is a real vulnerability that SentinelScan misses. Known false negative categories:

| Category | Why It's Missed |
|---|---|
| Application logic flaws | Requires authenticated session and interaction |
| Server-side vulnerabilities | Requires exploit payloads |
| SSRF vulnerabilities | Requires crafted input submission |
| Blind XSS | Requires interaction with logged output |
| Insecure direct object references | Requires guessing/iterating over IDs |
| Weak session management | Requires multiple requests and timing analysis |
| Broken authentication flows | Requires full auth flow execution |
| IDOR | Requires multiple authenticated accounts |
| Business logic flaws | Requires domain knowledge and interaction |
| Server misconfiguration hidden by WAF | WAF blocks the probe |

---

## False Positive Sources

A **false positive** is a finding reported when no real vulnerability exists. Known mitigation efforts:

| Detector | FP Risk | Mitigation Status |
|---|---|---|
| Exposed .env | Custom 200 pages | ✅ Soft-404 detection + content validation |
| Exposed .git | Custom 200 pages | ✅ Content validation (must start with `ref:`) |
| Admin panel exposed | Generic login pages | ✅ Requires password input + login form action |
| Server version disclosure | Hostname-style server values | ✅ Strict `product/version` regex required |
| DKIM not detected | Custom selectors | ✅ Confidence=low + explicit caveat |
| Missing HSTS | HTTP-only targets | ✅ Suppressed on non-HTTPS targets |

---

## Infrastructure Limitations

### NVD API Availability

CVE lookups require internet access to the NIST NVD API. Outages or rate limiting may cause the CVE stage to be skipped or return incomplete results.

### DNS Resolver Availability

DNS analysis requires network access to authoritative nameservers. Firewalled environments or resolver failures may produce incomplete DNS results.

### Scan Timeout

Scans time out after 600 seconds (10 minutes). Unusually slow targets may not complete all stages before timeout.

---

## Finding-Level Remediation Guidance Boundaries

### Guidance Only — No Automated Remote Changes

SentinelScan provides finding-level remediation guidance, sequential configuration steps, and copy-ready snippets (Nginx, Apache, Express/Helmet, Caddy) that operators apply manually to their own servers. SentinelScan never connects to, authenticates to, or modifies a live server or code repository. There is no automated PR creation, remote SSH execution, or deployment-API integration.

### Scope of Automated Guidance

Finding-level remediation guidance is tailored for applicable security configuration findings (HTTP response headers, cookie flags, TLS protocol/cipher suites, DNS policies, and common framework version upgrades). Complex application architecture flaws, business-logic vulnerabilities, or bespoke software designs require manual developer triage and architecture-specific remediation.

---

## What SentinelScan Is Not

SentinelScan is **not** a substitute for:

- Manual penetration testing by a qualified security engineer
- Automated dynamic application security testing (DAST) tools like OWASP ZAP or Burp Suite
- Static application security testing (SAST) that analyzes source code
- Software composition analysis (SCA) for dependency vulnerabilities
- Runtime application self-protection (RASP)
- Continuous vulnerability scanning with agent-based tools

It is a complementary tool for rapid passive security assessment of public-facing web applications.
