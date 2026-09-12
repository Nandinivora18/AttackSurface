# Detector Reference

Complete reference for every security detector implemented in SentinelScan v1.0.

Each entry documents: purpose, methodology, severity, confidence, evidence format, known false positives, known false negatives, and remediation guidance.

---

## Table of Contents

- [DNS Detectors](#dns-detectors)
- [SSL/TLS Detectors](#ssltls-detectors)
- [HTTP Header Detectors](#http-header-detectors)
- [CORS Detector](#cors-detector)
- [Cookie Security Detectors](#cookie-security-detectors)
- [Technology Detectors](#technology-detectors)
- [CVE Detectors](#cve-detectors)
- [Content Exposure Detectors](#content-exposure-detectors)
- [Email Security Detectors](#email-security-detectors)

---

## DNS Detectors

### Missing SPF Record

| Field | Value |
|---|---|
| **Module** | `dns_checker.py` |
| **Category** | Email Security |
| **Severity** | Medium |
| **CVSS** | 5.3 |
| **Confidence** | High |

**Purpose:** Detect domains with active mail servers that lack an SPF (Sender Policy Framework) policy, enabling email spoofing attacks.

**Methodology:** Queries DNS TXT records for the hostname. If no record beginning with `v=spf1` is found AND MX records are present, the finding is emitted.

**Condition for suppression:** If no MX records exist, SPF is not applicable (domain sends no email) and no finding is emitted.

**Evidence example:**
```
No TXT record starting with 'v=spf1' found for example.com
```

**False Positives:** Low. Some organizations route mail through a subdomain and set SPF only there; the apex domain may legitimately have no SPF.

**False Negatives:** SPF on a non-queried subdomain is not evaluated.

**Remediation:** Add a TXT record: `v=spf1 include:_spf.google.com ~all` (adjust for your mail provider)

---

### SPF Uses +all (Permissive)

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS** | 7.5 |
| **Confidence** | High |

**Methodology:** SPF record contains `+all` which permits any server worldwide to send mail as your domain. Equivalent to having no SPF.

**Evidence example:**
```
SPF: v=spf1 +all
```

**Remediation:** Change to `~all` (softfail) or `-all` (hardfail).

---

### SPF Uses ?all (Neutral)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS** | 5.3 |
| **Confidence** | High |

**Methodology:** SPF `?all` qualifier provides no protection — receiving mail servers treat any sender as neutral.

---

### Missing DMARC Record

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS** | 5.3 |
| **Confidence** | High |

**Methodology:** Queries `_dmarc.{hostname}` for a TXT record beginning with `v=DMARC1`. Missing DMARC means spoofed emails cannot be automatically quarantined or rejected.

**Evidence example:**
```
No TXT record starting with 'v=DMARC1' found for _dmarc.example.com
```

---

### DMARC Policy is 'none'

| Field | Value |
|---|---|
| **Severity** | Low |
| **CVSS** | 3.1 |
| **Confidence** | High |

**Methodology:** DMARC `p=none` only monitors — it never causes a receiving mail server to quarantine or reject a spoofed message.

**Remediation:** Upgrade to `p=quarantine` then eventually `p=reject`.

---

### Potential DKIM Not Detected

| Field | Value |
|---|---|
| **Severity** | Info |
| **CVSS** | N/A |
| **Confidence** | **Low** |

**Methodology:** Probes `{selector}._domainkey.{hostname}` TXT records for 9 common selectors: `default`, `google`, `mail`, `k1`, `s1`, `s2`, `dkim`, `selector1`, `selector2`.

**Important limitation:** Selector enumeration cannot prove DKIM is absent. Organizations frequently use custom selectors (e.g. `mailchimp`, `em1234`, organization-specific names) that are impossible to enumerate passively.

**Finding title:** "Potential DKIM Configuration Not Detected via Common Selectors"

**Evidence example:**
```
No DKIM TXT record found under 9 common selectors for _domainkey.example.com.
This does NOT confirm DKIM is absent — a custom selector may be in use.
```

**Recommended follow-up:** Use your mail provider admin panel or mail-tester.com to confirm actual DKIM status.

---

## SSL/TLS Detectors

### Certificate Expired

| Field | Value |
|---|---|
| **Severity** | Critical |
| **CVSS** | 9.8 |
| **Confidence** | High |

**Methodology:** Compares certificate `notAfter` date against current UTC time. An expired certificate causes browser security warnings and breaks all HTTPS connections for most clients.

**Evidence example:**
```
Certificate expired 14 days ago. Expired: 2024-01-15T00:00:00Z
```

---

### Certificate Expiring Soon (< 14 days)

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS** | 6.5 |
| **Confidence** | High |

**Methodology:** `days_remaining < 14`. This is the window where HSTS preload removal requests must be submitted if needed.

---

### Certificate Expiring (< 30 days)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS** | 4.3 |
| **Confidence** | High |

---

### Weak TLS Version

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS** | 7.4 |
| **Confidence** | High |

**Methodology:** Checks the negotiated TLS version string. Flags: `TLSv1`, `TLSv1.1`, `SSLv3`, `SSLv2`.

TLSv1.0 and TLSv1.1 are deprecated per RFC 8996 (2021).

**False Positives:** None — this reflects the actual negotiated protocol.

---

### Weak Cipher Suite

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS** | 7.4 |
| **Confidence** | High |

**Methodology:** Checks the negotiated cipher name for known-weak algorithms: `RC4`, `DES`, `NULL`, `EXPORT`.

---

### Certificate Verification Failed

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | High |

**Methodology:** Raised when Python's ssl module raises `SSLCertVerificationError` — typically self-signed, hostname mismatch, or untrusted CA.

---

### HTTPS Unavailable

| Field | Value |
|---|---|
| **Severity** | Info |
| **Confidence** | High |

**Methodology:** Connection to port 443 refused or timed out. Reported as Info — the `No HTTPS redirect` header check reports the security impact.

---

## HTTP Header Detectors

### Missing Strict-Transport-Security (HSTS)

| Field | Value |
|---|---|
| **Severity** | High (HTTPS targets) / Info (HTTP-only targets) |
| **CVSS** | 6.5 |
| **Confidence** | High |

**Methodology:** Checks for presence of the `Strict-Transport-Security` header. On HTTP-only targets, suppressed to `info` to avoid double-penalising the missing HTTPS redirect.

**Remediation:** `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

---

### Missing Content-Security-Policy

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS** | 6.1 |
| **Confidence** | High |

**Methodology:** Absence of `Content-Security-Policy` header leaves the browser unprotected against XSS and data injection.

---

### CSP Allows 'unsafe-inline'

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS** | 6.1 |
| **Confidence** | High |

**Methodology:** `'unsafe-inline'` in CSP `script-src` or `default-src` allows inline JavaScript execution, bypassing XSS protections.

---

### CSP Allows 'unsafe-eval'

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS** | 5.0 |
| **Confidence** | High |

---

### CSP Uses Wildcard Source

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | High |

**Methodology:** `*` in `default-src` or `script-src` allows loading content from any origin, rendering CSP ineffective.

---

### Missing X-Frame-Options

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS** | 4.3 |
| **Confidence** | High |

**Methodology:** Without `X-Frame-Options`, the page can be embedded in an `<iframe>` on any domain, enabling clickjacking attacks.

**Note:** Modern browsers support the `frame-ancestors` CSP directive which supersedes this header.

---

### Missing X-Content-Type-Options

| Field | Value |
|---|---|
| **Severity** | Low |
| **CVSS** | 3.1 |
| **Confidence** | High |

**Remediation:** `X-Content-Type-Options: nosniff`

---

### Server Header Discloses Version

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS** | 5.3 |
| **Confidence** | High |

**Methodology:** Checks `Server` header against pattern `\w[\w\-]*/\d[\d.]*` — requires an explicit `ProductName/version` format. Examples that match: `Apache/2.4.58`, `nginx/1.26.1`, `Microsoft-IIS/10.0`.

**Examples that do NOT match (no finding / lower severity):** `github.com`, `cloudflare`, `netlify`.

**False Positive Prevention:** Plain hostnames and benign CDN values are excluded. The strict regex prevents `github.com` from matching.

---

### Server Header Discloses Software

| Field | Value |
|---|---|
| **Severity** | Low |
| **CVSS** | 3.1 |
| **Confidence** | High |

**Methodology:** `Server` header is present but doesn't contain a version string. Reveals software type without version. Known benign values (`cloudflare`, `netlify`, `vercel`, `fastly`, etc.) are silently skipped.

---

### X-Powered-By Disclosure

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS** | 5.3 |
| **Confidence** | High |

**Methodology:** Any value in `X-Powered-By` header reveals the underlying technology stack.

---

### No HTTPS Redirect

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS** | 7.5 |
| **Confidence** | High |

**Methodology:** URL starts with `http://` and the final response URL (after following redirects) is still `http://`.

---

## CORS Detector

### CORS Wildcard + Credentials

| Field | Value |
|---|---|
| **Severity** | Critical |
| **CVSS** | 9.1 |
| **Confidence** | High |

**Methodology:** `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true`. This combination allows any website to make credentialed cross-origin requests, potentially stealing session data.

**Note:** Browsers actually block this combination per the CORS spec, but detecting it flags a server misconfiguration that could break functionality or reveal implementation errors.

---

## Cookie Security Detectors

### Session Cookie Missing Secure Flag

| Field | Value |
|---|---|
| **Severity** | High |
| **Confidence** | High |

**Methodology:** Cookies with session-related names (`session`, `auth`, `token`, `sid`, `SESSID`) lacking the `Secure` attribute can be transmitted over plain HTTP connections.

---

### Cookie Missing HttpOnly Flag

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | High |

**Methodology:** Without `HttpOnly`, cookies are accessible via JavaScript `document.cookie`, enabling XSS attacks to steal session tokens.

---

### Cookie Missing SameSite

| Field | Value |
|---|---|
| **Severity** | Low |
| **Confidence** | High |

**Methodology:** Missing `SameSite` attribute. Without it, cookies are sent in cross-site requests, enabling CSRF attacks in some configurations.

---

## Technology Detectors

Each technology detector produces one of two finding types:

1. **Technology identified** (Info) — passively informing about the stack
2. **Outdated version detected** (Medium/High) — when a version is extracted and matches a vulnerable version threshold

All technology findings use evidence that includes the matched signal (e.g., the specific header or HTML pattern that triggered detection).

### WordPress Detector

| Signal | Confidence |
|---|---|
| `wp-content/` in HTML | 90% |
| `wp-includes/` in HTML | 90% |
| Meta generator tag | 95% |
| `X-Powered-By: WordPress` | 95% |
| `wordpress_*` cookie | 85% |

**Version extraction:** `<meta name="generator" content="WordPress X.X.X">`

**Known vulnerable versions:** < 6.4 (CVE-2024-6386, High), < 6.3 (CVE-2023-5561, Medium)

---

### Drupal Detector

| Signal | Confidence |
|---|---|
| `/sites/default/files/` in HTML | 85% |
| Meta generator tag | 95% |
| `X-Generator: Drupal` header | 95% |
| `SESS[hex32]` cookie pattern | 75% |

**Known vulnerable versions:** < 10.2 (CVE-2024-45440, Medium)

---

### Django Detector

| Signal | Confidence |
|---|---|
| `csrftoken` cookie | 80% |

**Note:** The `X-Frame-Options: SAMEORIGIN` pattern was removed because it is commonly set by Nginx/Apache/CDNs, causing false positives. `sessionid` was also removed — too generic.

---

### jQuery Detector

**Version extraction:** Filename pattern `jquery-X.X.X.min.js`

**Known vulnerable versions:** < 3.5.0 (CVE-2020-11022), < 3.0.0 (CVE-2019-11358)

---

## CVE Detectors

CVE findings are dynamically generated by querying the NVD API for each detected technology with a confirmed version string.

### Finding Schema

```json
{
  "category": "Technology Stack",
  "title": "CVE-2021-44228 — Apache Log4j2 Remote Code Execution",
  "description": "Description from NVD",
  "severity": "critical",
  "cvss_score": 10.0,
  "cve_id": "CVE-2021-44228",
  "published_date": "2021-12-10",
  "confidence": "medium",
  "evidence": "Detected Apache/2.4.51 — known vulnerable range: < 2.4.52",
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
}
```

**Confidence note:** CVE findings from NVD keyword search are marked `medium` confidence because keyword matching may return CVEs for other products sharing the technology name.

---

## Content Exposure Detectors

### Exposed .env File

| Field | Value |
|---|---|
| **Severity** | Critical |
| **CVSS** | 9.8 |
| **Confidence** | Confirmed (when validated) |

**Methodology:**
1. Probe `/.env` — if response is HTML → skip (soft-404 or homepage)
2. Check for ≥ 2 lines matching `KEY=VALUE` pattern
3. Validate not a soft-404 against baseline
4. Redact sensitive values before storing evidence

**False Positive Prevention:** Minimum 2 KEY=VALUE lines required. HTML responses always rejected. Soft-404 detection eliminates custom error pages returning 200.

**Evidence example (redacted):**
```
Verified environment file containing 8 key=value pairs:
APP_KEY=[REDACTED]
DB_PASSWORD=[REDACTED]
APP_NAME=MyApp
DB_HOST=127.0.0.1
```

---

### Exposed Git Repository

| Field | Value |
|---|---|
| **Path** | `/.git/HEAD` |
| **Severity** | Critical |
| **Confidence** | Confirmed |

**Methodology:** Response must start with `ref: refs/` or match 40-character hex commit hash.

**Evidence example:**
```
Verified Git HEAD reference: ref: refs/heads/main
```

---

### Exposed WordPress Config Backup

| Field | Value |
|---|---|
| **Path** | `/wp-config.php.bak` |
| **Severity** | Critical |
| **Confidence** | Confirmed |

**Methodology:** Content must contain `define( 'DB_` — the WordPress configuration macro pattern.

---

### Exposed SQL Dump

| Field | Value |
|---|---|
| **Path** | `/backup.sql` |
| **Severity** | Critical |
| **Confidence** | Confirmed |

**Methodology:** Content contains SQL dump keywords: `-- MySQL dump`, `CREATE TABLE`, `INSERT INTO`.

---

### Exposed .htaccess

| Field | Value |
|---|---|
| **Path** | `/.htaccess` |
| **Severity** | High |
| **Confidence** | High |

**Methodology:** Content contains Apache config directives: `RewriteRule`, `Options`, `Deny from`.

---

### Exposed Admin Panel (/admin)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Confidence** | High |

**Methodology:** HTML response must contain **both**:
1. `<input type="password">` (case-insensitive)
2. Form `action` attribute containing `admin`, `login`, or `signin`

**False Positive Prevention:** Prior implementation only checked for the word "login" which matched any page with a navigation login link. The dual-requirement (password input + login form action) eliminates generic landing pages.

---

### Exposed phpMyAdmin

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Confidence** | Confirmed |

**Methodology:** Page contains phpMyAdmin-specific keywords: `pma_username`, `pma_password`, `phpmyadmin`, `input_username`.

---

### Sensitive Information in HTML Comments

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS** | 5.3 |
| **Confidence** | High |

**Methodology:** Scans homepage source for `<!-- ... -->` comments containing: `password`, `api key`, `secret`, `token`, `credential`, `private key`, `access key`.

**Excluded keywords:** `todo`, `fixme`, `hack` — standard developer annotations, not security-relevant.

**Evidence:** First matching comment is included (redacted).

---

### Email Addresses Exposed

| Field | Value |
|---|---|
| **Severity** | Low |
| **Confidence** | High |

**Methodology:** Regex scans homepage source: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`. Excludes false positives: `@2x.png`, `@example.js`, `@charset`.

---

### Interactive API Documentation Exposed

| Field | Value |
|---|---|
| **Paths** | `/swagger-ui.html`, `/api/docs` |
| **Severity** | Medium |
| **Confidence** | High |

**Methodology:** Page contains Swagger UI or ReDoc keywords. API documentation in production exposes endpoint schemas to attackers.

---

### Exposed Apache Server Status

| Field | Value |
|---|---|
| **Path** | `/server-status` |
| **Severity** | High |
| **Confidence** | High |

**Methodology:** Page contains `Apache Server Status`, `Apache Status`, or `Server Version:`. Reveals active connections, request rates, and worker states.

---

## Email Security Detectors

See [DNS Detectors](#dns-detectors) — SPF and DMARC detectors are documented there as they operate through DNS resolution. (Note: DKIM selector lookup operates as an advisory probe and is not a registered detector ID in `DETECTOR_REGISTRY`).
