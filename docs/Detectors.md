# Detector Reference

Complete technical reference for all **82 security detectors** registered in SentinelScan (`DETECTOR_REGISTRY`).

The engine includes **37 core baseline & OWASP assessment detectors** and **45 external exposure detectors across 12 intelligence domains**.

Each entry documents: purpose, methodology, severity, confidence, evidence format, known limitations, and remediation guidance.

---

## Table of Contents

- [Core Security Detectors](#core-security-detectors)
  - [DNS Detectors](#dns-detectors)
  - [SSL/TLS Detectors](#ssltls-detectors)
  - [HTTP Header Detectors](#http-header-detectors)
  - [CORS Detector](#cors-detector)
  - [Cookie Security Detectors](#cookie-security-detectors)
  - [Technology Detectors](#technology-detectors)
  - [CVE Detectors](#cve-detectors)
  - [Content Exposure Detectors](#content-exposure-detectors)
  - [Email Security Detectors](#email-security-detectors)
- [External Exposure Detectors (45 Detectors across 12 Domains)](#external-exposure-detectors)
  - [Domain 1: Web Security Configuration](#domain-1-web-security-configuration)
  - [Domain 2: Auth & Session Security](#domain-2-auth--session-security)
  - [Domain 3: API Surface Exposure](#domain-3-api-surface-exposure)
  - [Domain 4: JavaScript Secret Detection](#domain-4-javascript-secret-detection)
  - [Domain 5: Source Map Exposure](#domain-5-source-map-exposure)
  - [Domain 6: Sensitive Files & Standards](#domain-6-sensitive-files--standards)
  - [Domain 7: Cloud Storage Exposure](#domain-7-cloud-storage-exposure)
  - [Domain 8: DNS Intelligence](#domain-8-dns-intelligence)
  - [Domain 9: TLS Deep Analysis](#domain-9-tls-deep-analysis)
  - [Domain 10: Mixed Content Detection](#domain-10-mixed-content-detection)
  - [Domain 11: Third-Party Scripts & SRI](#domain-11-third-party-scripts--sri)
  - [Domain 12: Web Cache Exposure](#domain-12-web-cache-exposure)

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

---

# External Exposure Detectors

SentinelScan's Stage 5e engine implements **45 dedicated external exposure detectors** across 12 intelligence domains, implemented in [`app/scanner/exposure_detector.py`](../backend/app/scanner/exposure_detector.py). All external requests utilize [`SafeFetchClient`](../backend/app/utils/safe_http.py) with SSRF validation, IP pinning, bounded timeouts, and strict content buffers.

---

## Domain 1: Web Security Configuration

Inspects HTTP response headers and public management routes for configuration weaknesses, technology disclosures, and administrative interface exposure.

### 1. `exposure.cors.misconfiguration`
- **Category**: Web Security Configuration | **OWASP**: A04 | **CWE**: CWE-942
- **Severity**: High (7.5) or Critical (9.1 with credentials) | **Confidence**: High
- **Methodology**: Evaluates `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC). Differentiates wildcard origin (`*`) from origin reflection and combinations with credentials.
- **Evidence**: `Access-Control-Allow-Origin: *` or `Access-Control-Allow-Origin: null | ACAC: true`
- **Passive Boundary**: Evaluates static headers returned by server. Does not send arbitrary origin forgery payloads.

### 2. `exposure.server.version_disclosure`
- **Category**: Web Security Configuration | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Medium (5.3) | **Confidence**: High
- **Methodology**: Regex matching against `Server` response header for versioned software tokens (Apache, nginx, IIS, etc.).
- **Evidence**: `Server: Apache/2.4.51 (Unix)`

### 3. `exposure.server.xpoweredby`
- **Category**: Web Security Configuration | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Low (3.1) | **Confidence**: High
- **Methodology**: Evaluates `X-Powered-By` headers disclosing backend runtime frameworks (PHP/8.1, Express, ASP.NET).
- **Evidence**: `X-Powered-By: PHP/8.1.0`

### 4. `exposure.debug.endpoint_exposed`
- **Category**: Web Security Configuration | **OWASP**: A04 | **CWE**: CWE-489
- **Severity**: High (7.5) / Medium (4.3 for health checks) | **Confidence**: High
- **Methodology**: Probes known debug/management paths (`/debug`, `/actuator`, `/actuator/env`, `/metrics`, `/heapdump`). Filters legitimate benign health checks (`{"status":"up"}`).
- **Evidence**: `HTTP 200 at /actuator/env — body: ...`

---

## Domain 2: Auth & Session Security

Audits cookie security flags, cleartext credential submission, and insecure authentication schemes.

### 5. `exposure.auth.session_cookie_flags`
- **Category**: Auth and Session Security | **OWASP**: A07 | **CWE**: CWE-614 / CWE-1004
- **Severity**: High (7.5) | **Confidence**: High
- **Methodology**: Evaluates `Set-Cookie` directives on known session tokens (`sessionid`, `PHPSESSID`, `JSESSIONID`, `connect.sid`) for missing `HttpOnly`, `Secure`, or `SameSite` flags.
- **Evidence**: `Set-Cookie: sessionid=...; Path=/; SameSite=Lax (missing HttpOnly, missing Secure)`

### 6. `exposure.auth.plaintext_login`
- **Category**: Auth and Session Security | **OWASP**: A02 | **CWE**: CWE-319
- **Severity**: Critical (9.1) | **Confidence**: High
- **Methodology**: Identifies password inputs (`<input type="password">`) served over unencrypted HTTP.
- **Evidence**: `<input type="password"> found on HTTP page`

### 7. `exposure.auth.basic_auth_exposed`
- **Category**: Auth and Session Security | **OWASP**: A07 | **CWE**: CWE-522
- **Severity**: Medium (5.3 over HTTPS) / High (7.5 over HTTP) | **Confidence**: High
- **Methodology**: Detects `WWW-Authenticate: Basic` challenge headers on public endpoints.
- **Evidence**: `WWW-Authenticate: Basic realm="Restricted Area"`

---

## Domain 3: API Surface Exposure

Identifies publicly discoverable API specifications, interactive documentation, and GraphQL endpoints.

### 8. `exposure.api.openapi_exposed`
- **Category**: API Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Medium (5.3) | **Confidence**: High
- **Methodology**: Probes for reachable OpenAPI specifications (`/openapi.json`, `/openapi.yaml`).
- **Evidence**: `HTTP 200 at /openapi.json`

### 9. `exposure.api.docs_exposed`
- **Category**: API Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Medium (5.3) | **Confidence**: High
- **Methodology**: Probes `/api-docs`, `/redoc`, `/api/swagger` returning interactive API documentation in production.
- **Evidence**: `HTTP 200 at /api-docs`

### 10. `exposure.api.graphql_exposed`
- **Category**: API Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Medium (5.3) | **Confidence**: Medium
- **Methodology**: Identifies reachable `/graphql`, `/graphiql`, `/playground` endpoints. Does not claim introspection without verification.
- **Evidence**: `HTTP 200 at /graphql`

### 11. `exposure.api.graphql_introspection`
- **Category**: API Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: High (7.5) | **Confidence**: High
- **Methodology**: Probes GraphQL endpoints with a non-destructive introspection query (`{__schema{queryType{name}}}`). Emitted strictly when `__schema` is confirmed in response.
- **Evidence**: `POST /graphql returned __schema`

---

## Domain 4: JavaScript Secret Detection

Scans inline script blocks and same-origin external JavaScript files for hardcoded API keys, tokens, and private credentials.

- **Size Controls**: HTML clamped to 1 MB; scripts clamped to 512 KB; maximum 10 same-origin scripts parsed.
- **Secret Redaction**: Detected values are masked in evidence (`val[:4] + "****" + val[-4:]`). Raw secrets are never persisted or logged.

| Detector ID | Secret Type | Severity | CVSS | Confidence | Pattern Focus |
|---|---|:---:|:---:|:---:|---|
| **12. `exposure.js.aws_key`** | AWS Access Key ID | Critical | 9.8 | High | `AKIA[0-9A-Z]{16}` |
| **13. `exposure.js.aws_secret`** | AWS Secret Access Key | Critical | 9.8 | Medium | `aws_secret_access_key = '...'` |
| **14. `exposure.js.google_api_key`** | Google Cloud / Maps API Key | High | 8.8 | High | `AIza[0-9A-Za-z\-_]{35}` |
| **15. `exposure.js.github_token`** | GitHub Personal Access Token | Critical | 9.8 | High | `gh[pousr]_[A-Za-z0-9]{36,}` |
| **16. `exposure.js.stripe_live_key`** | Stripe Live Secret Key | Critical | 9.8 | High | `sk_live_[A-Za-z0-9]{24,}` |
| **17. `exposure.js.stripe_test_key`** | Stripe Test Key | Medium | 4.3 | High | `sk_test_[A-Za-z0-9]{24,}` |
| **18. `exposure.js.slack_token`** | Slack API / Bot Token | High | 8.1 | High | `xox[baprs]-[0-9A-Za-z\-]{10,}` |
| **19. `exposure.js.sendgrid_key`** | SendGrid API Key | High | 8.1 | High | `SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}` |
| **20. `exposure.js.jwt_secret`** | JWT HMAC Secret | High | 8.8 | Medium | `jwt_secret = '...'` |
| **21. `exposure.js.generic_api_key`** | Generic High-Entropy API Key | Medium | 5.3 | Medium | `api_key = '...'` (filters test/dummy stubs) |
| **22. `exposure.js.private_key`** | PEM Private Key Header | Critical | 9.8 | High | `-----BEGIN (RSA\|EC) PRIVATE KEY-----` |

- **B-Grade Calibration Note**: Generic API keys and JWT secrets are calibrated to `confidence="medium"`. Passive scanning cannot verify whether keys are active without attempting unauthorized external API authentication.

---

## Domain 5: Source Map Exposure

### 23. `exposure.sourcemap.exposed`
- **Category**: Source Map Exposure | **OWASP**: A04 | **CWE**: CWE-540
- **Severity**: Medium (5.3) | **Confidence**: High
- **Methodology**: Extracts `sourceMappingURL` comments from JavaScript assets and probes reachable `.map` endpoints. Validates presence of the `"sources"` JSON array.
- **Evidence**: `HTTP 200 at https://example.com/app.js.map with 'sources' key`

---

## Domain 6: Sensitive Files & Standards

### 24. `exposure.files.robots_sensitive_paths`
- **Category**: Sensitive File Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Low (3.1) | **Confidence**: High
- **Methodology**: Parses `robots.txt` for `Disallow` directives revealing high-value targets (`/admin`, `/internal`, `/secret`, `/backup`, `/db`).
- **Evidence**: `Sensitive Disallow entries: /admin, /api/internal, /backup`

### 25. `exposure.files.security_txt_missing`
- **Category**: Sensitive File Exposure | **OWASP**: A04 | **CWE**: RFC 9116
- **Severity**: Info | **Confidence**: High
- **Methodology**: Probes `/.well-known/security.txt`. Emitted when the standard security disclosure contact file is missing.
- **Evidence**: `HTTP 404 for /.well-known/security.txt`

---

## Domain 7: Cloud Storage Exposure

Audits client HTML and JavaScript code for references to public cloud storage containers (AWS S3, Google Cloud Storage, Azure Blob).

### 26. `exposure.cloud.bucket_public`
- **Category**: Cloud Storage Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Critical (9.1) | **Confidence**: High
- **Methodology**: Probes referenced cloud bucket URLs. Emitted when response body contains public enumeration signatures (`<ListBucketResult`, `<EnumerationResults`).
- **Evidence**: `HTTP 200 at https://my-bucket.s3.amazonaws.com with public listing response`

### 27. `exposure.cloud.bucket_accessible`
- **Category**: Cloud Storage Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Medium (5.3) | **Confidence**: Medium
- **Methodology**: Probes referenced cloud bucket URLs. Emitted when the bucket returns HTTP 200 without full XML directory enumeration.
- **Evidence**: `HTTP 200 at https://storage.googleapis.com/my-bucket`

### 28. `exposure.cloud.bucket_reference`
- **Category**: Cloud Storage Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Low (3.1) | **Confidence**: Medium
- **Methodology**: Identifies cloud storage bucket URLs in page source that return non-200 status codes (e.g. 403 Forbidden). Network connection exceptions cleanly pass and never create spurious findings.
- **Evidence**: `Bucket URL referenced in source: https://my-bucket.s3.amazonaws.com (HTTP 403)`

---

## Domain 8: DNS Intelligence

Expands baseline DNS checks with deep policy hygiene and takeover risk analysis.

### 29. `exposure.dns.spf_passall`
- **Category**: DNS Intelligence | **OWASP**: A04 | **CWE**: CWE-345
- **Severity**: High (7.5) | **Confidence**: High
- **Methodology**: Emitted when SPF TXT records contain `+all` or `?all`, allowing any sender to forge mail. Collapsed with baseline `dns.spf.*` in deduplication.
- **Evidence**: `SPF record contains permissive +all mechanism: v=spf1 include:_spf.example.com +all`

### 30. `exposure.dns.spf_softfail`
- **Category**: DNS Intelligence | **OWASP**: A04 | **CWE**: CWE-345
- **Severity**: Medium (4.3) | **Confidence**: Medium
- **Methodology**: Emitted when SPF uses `~all` without strong DMARC rejection, leaving spoofed emails delivered to spam folders instead of rejected.
- **Evidence**: `SPF record uses ~all softfail mechanism`

### 31. `exposure.dns.wildcard`
- **Category**: DNS Intelligence | **OWASP**: A04 | **CWE**: CWE-345
- **Severity**: Low (3.1) | **Confidence**: Medium
- **Methodology**: Resolves random high-entropy test subdomains. Emitted when wildcard A records resolve.
- **Evidence**: `Wildcard DNS resolution active: *.example.com -> 93.184.216.34`

### 32. `exposure.dns.dmarc_missing`
- **Category**: DNS Intelligence | **OWASP**: A04 | **CWE**: CWE-345
- **Severity**: High (7.5) | **Confidence**: High
- **Methodology**: Checks for absence of DMARC policy at `_dmarc.<domain>`. Canonicalized with `dns.dmarc.missing`.
- **Evidence**: `No DMARC policy record found at _dmarc.example.com`

### 33. `exposure.dns.dmarc_none_policy`
- **Category**: DNS Intelligence | **OWASP**: A04 | **CWE**: CWE-345
- **Severity**: Medium (5.3) | **Confidence**: High
- **Methodology**: Detects `p=none` monitor-only policies that fail to instruct receiving mail servers to quarantine or reject spoofed mail.
- **Evidence**: `v=DMARC1; p=none; rua=mailto:dmarc@example.com`

---

## Domain 9: TLS Deep Analysis

Evaluates protocol deprecation, cipher suite strength, and public key deployment hygiene.

### 34. `exposure.tls.weak_protocols`
- **Category**: TLS Analysis | **OWASP**: A02 | **CWE**: CWE-326
- **Severity**: High (7.5) | **Confidence**: High
- **Methodology**: Detects server support for deprecated TLS 1.0, 1.1, SSLv2, or SSLv3 protocols during handshake negotiation.
- **Evidence**: `Weak protocols: TLSv1.0, TLSv1.1`

### 35. `exposure.tls.weak_ciphers`
- **Category**: TLS Analysis | **OWASP**: A02 | **CWE**: CWE-327
- **Severity**: High (7.5) | **Confidence**: High
- **Methodology**: Identifies legacy non-AEAD cipher suites (RC4, 3DES, DES, EXPORT, NULL, MD5) accepted by the server.
- **Evidence**: `Weak ciphers: TLS_RSA_WITH_3DES_EDE_CBC_SHA`

### 36. `exposure.tls.hsts_not_preloaded`
- **Category**: TLS Analysis | **OWASP**: A02 | **CWE**: CWE-319
- **Severity**: Low (3.1) | **Confidence**: Medium
- **Methodology**: Identifies valid HSTS deployments that omit the `preload` directive, leaving first-time visitors vulnerable to SSL stripping.
- **Evidence**: `HSTS present but 'preload' directive absent`

### 37. `exposure.tls.ct_not_logged`
- **Category**: TLS Analysis | **OWASP**: A02 | **CWE**: CWE-295
- **Severity**: Info | **Confidence**: Low
- **Methodology**: Flagged when SCTs cannot be confirmed via passive handshake.
- **Passive Limitation**: Formatted explicitly as a `NOT_VERIFIABLE` advisory. Passive scanners cannot independently verify Certificate Transparency compliance without live log monitoring.
- **Evidence**: `Passive handshake cannot verify SCT presence (NOT_VERIFIABLE)`

---

## Domain 10: Mixed Content Detection

Identifies unencrypted HTTP assets embedded within HTTPS target pages.

### 38. `exposure.mixed_content.active`
- **Category**: Mixed Content | **OWASP**: A02 | **CWE**: CWE-319
- **Severity**: High (7.5) | **Confidence**: High
- **Methodology**: Identifies unencrypted JavaScript sources (`<script src="http://...">`) and insecure form actions (`<form action="http://...">`) on HTTPS pages.
- **Evidence**: `HTTP active resource URLs: http://cdn.example.com/lib.js`

### 39. `exposure.mixed_content.passive`
- **Category**: Mixed Content | **OWASP**: A02 | **CWE**: CWE-319
- **Severity**: Medium (4.3) | **Confidence**: Medium
- **Methodology**: Identifies unencrypted images, stylesheets, and audio/video resources loaded over plain HTTP on HTTPS pages.
- **Evidence**: `HTTP resource URLs: http://images.example.com/logo.png`

---

## Domain 11: Third-Party Scripts & SRI

Verifies that third-party scripts loaded from external CDNs implement cryptographic subresource integrity checks.

### 40. `exposure.sri.cdn_missing`
- **Category**: Third-Party and SRI | **OWASP**: A08 | **CWE**: CWE-353
- **Severity**: Medium (5.3) | **Confidence**: High
- **Methodology**: Identifies scripts loaded from known CDN domains (cdnjs, unpkg, jsdelivr, googleapis) lacking the `integrity` attribute.
- **Evidence**: `CDN scripts without SRI: https://cdn.jsdelivr.net/npm/jquery.min.js`

### 41. `exposure.sri.external_missing`
- **Category**: Third-Party and SRI | **OWASP**: A08 | **CWE**: CWE-353
- **Severity**: Low (3.1) | **Confidence**: Medium
- **Methodology**: Identifies scripts hosted on external domains lacking `integrity` attributes.
- **Evidence**: `External scripts without SRI: https://externalsite.com/widget.js`

---

## Domain 12: Web Cache Exposure

Audits HTTP caching headers for potential credential and sensitive data exposure in shared intermediary proxies.

### 42. `exposure.cache.authenticated_cacheable`
- **Category**: Cache Exposure | **OWASP**: A02 | **CWE**: CWE-524
- **Severity**: Medium (5.3) | **Confidence**: Medium
- **Methodology**: Detects authenticated responses lacking `Cache-Control: no-store` or `private` directives.
- **Evidence**: `Cache-Control: public, max-age=3600 | Auth header present`

### 43. `exposure.cache.sensitive_api_cacheable`
- **Category**: Cache Exposure | **OWASP**: A02 | **CWE**: CWE-524
- **Severity**: High (7.5) | **Confidence**: Medium
- **Methodology**: Probes sensitive user endpoints (`/api/user`, `/api/profile`, `/api/account`). Emitted when responses returning sensitive tokens, passwords, or PII omit `Cache-Control: no-store`.
- **Evidence**: `HTTP 200 | Cache-Control: max-age=60 | API token in response`

### 44. `exposure.cache.no_cache_control`
- **Category**: Cache Exposure | **OWASP**: A04 | **CWE**: RFC 7234
- **Severity**: Low (3.1) | **Confidence**: Medium
- **Methodology**: Detects JSON API endpoints returning no `Cache-Control` header, allowing indefinite caching by intermediaries.
- **Evidence**: `HTTP 200 | Cache-Control: absent`

### 45. `exposure.api.rest_exposed`
- **Category**: API Exposure | **OWASP**: A04 | **CWE**: CWE-200
- **Severity**: Medium (5.3) | **Confidence**: Medium
- **Methodology**: Detects public versioned REST API root endpoints (`/api/v1`, `/api/v2`, `/v1`) accessible without credentials.
- **Evidence**: `HTTP 200 at /api/v1`

