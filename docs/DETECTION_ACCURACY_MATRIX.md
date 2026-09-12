# SentinelScan — Detection Accuracy Matrix

**Version:** 1.0.0  
**Audit Date:** 2026-08-15  
**Methodology:** Adversarial evidence-chain validation — every finding path traced from raw observation through evidence, confidence, severity, and mapping.

> **Standard:** Evidence-driven detection with systematic false-positive mitigation and regression coverage.

---

## How to Read This Matrix

| Column | Meaning |
|---|---|
| **Evidence Required** | What must be observed before a finding is emitted |
| **Strong Signal** | Evidence that alone justifies detection |
| **Weak Signal (suppressed)** | Evidence that exists but is insufficient alone — used only as corroboration |
| **Known FP Scenario** | Legitimate configuration that produces the same signal |
| **Mitigation** | How the FP is prevented in code |
| **Confidence** | `high` / `medium` / `low` — set on every finding |

---

## 1. HTTP Security Headers (11 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **Missing HSTS** | Header absent from live HTTPS response | Header not present | — | HTTP-only site (HSTS irrelevant) | Severity demoted to `info` for `http://` targets | high |
| **HSTS max-age too short** | `max-age=<N>` where N < 15,768,000 | Parsed integer value | — | Intentional short TTL for testing | Reports value in evidence | high |
| **HSTS missing includeSubDomains** | `includeSubDomains` absent from HSTS | — | Header present but incomplete | Intentionally omitted (uncontrolled subdomains) | Downgraded to `info` | high |
| **Missing CSP** | Header absent from HTML response | Header not present | — | JSON/XML API endpoint | `html_only=True`: only checked on `text/html` responses | high |
| **CSP unsafe-inline** | `'unsafe-inline'` in CSP value | Literal string present | — | Nonce-based CSP with unsafe-inline fallback | Reported regardless; operator must verify nonce | high |
| **CSP wildcard** | Standalone `*` in `script-src` or `default-src` | `*` not followed by `.` or `\w` | `*.cdn.com` (subdomain glob) | `script-src *.trusted.com` | Negative lookahead regex `(?![.\w])` prevents glob match | high |
| **Missing X-Frame-Options** | Header absent, no CSP `frame-ancestors` | — | — | CSP `frame-ancestors` present (W3C supersedes XFO) | Suppressed when CSP has `frame-ancestors` | high |
| **Missing X-Content-Type-Options** | Header absent | Header not present | — | — | — | high |
| **Missing Referrer-Policy** | Header absent | Header not present | — | — | — | high |
| **CORS wildcard + credentials** | `ACAO: *` + `ACAC: true` | Both headers present | `ACAO: *` alone (public API) | Public CDN endpoints | `ACAO: *` without credentials → `info` only; critical only with `ACAC: true` | high |
| **Server version disclosure** | `Server:` header with `word/digit` pattern | `Apache/2.4.51`, `nginx/1.20.1` | `nginx` (no version), `cloudflare` | CDN/proxy banner, vendor-only header | `_BENIGN_EXACT` + `_BENIGN_PREFIXES` allowlist; version pattern `\w[\w\-]*/\d[\d.]*` required | high |

---

## 2. SSL/TLS (6 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **Certificate expired** | TLS handshake: `notAfter` < now | Certificate dates from handshake | — | Self-signed cert on internal API | `verify=False` in scanner httpx client; still reports cert metadata | high |
| **Certificate near expiry** | `days_remaining` < 30 | Parsed `notAfter` date | — | — | Threshold set at 30 days | high |
| **Weak TLS version** | Negotiated protocol is TLS 1.0 or 1.1 | Protocol string from `ssl.SSLSocket.version()` | — | Legacy HTTPS load balancers | Checks negotiated protocol only, not offered ciphers | high |
| **Weak cipher suite** | Negotiated cipher in blocklist | `DES-CBC3-SHA`, `RC4-*` etc. | — | Custom cipher ordering by CDN | Checks negotiated cipher, not full server preference order | high |
| **Missing HSTS** (via SSL) | HTTP→HTTPS redirect absent or HSTS absent | Live HTTP response check | — | HTTPS-only deployment (no HTTP listener) | Separate check in `header_analyzer.py` | high |
| **SSL grade** | Composite score from protocol + cipher + cert validity | All three checked | — | — | Grade A–F derived from weighted sub-scores | high |

---

## 3. DNS / Email Security (5 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **Missing SPF** | No TXT `v=spf1` for domain | DNS TXT query result | — | Domain that never sends email | Only reported as medium when MX records present | high (MX present) / medium (no MX) |
| **SPF +all permissive** | `+all` in SPF record | Literal `+all` in record | `~all` (softfail, acceptable) | Old/legacy SPF configs | `~all` is NOT flagged — only `+all` and `?all` | high |
| **Missing DMARC** | No TXT `v=DMARC1` at `_dmarc.<domain>` | DNS TXT query result | — | Domain that never sends email | Confidence=medium when no MX records detected | high (MX) / medium (no MX) |
| **DMARC p=none** | DMARC record with `p=none` | Literal policy value | — | Transition/monitoring phase | Low severity (not high) — monitoring is valid but weak | high |
| **DKIM not detected** | No `v=DKIM1` / `p=` under 9 common selectors | — | Absence of common selectors | Custom selector (e.g. `20230601`) | Severity=`info`, confidence=`low`; description explicitly states this cannot prove DKIM is absent | low |

---

## 4. Technology Detection (3 categories, 22 tech signatures)

| Detector | Evidence Required | Strong Signal (≥80) | Weak Signal (suppressed <60) | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **WordPress** | `wp-content/` or `wp-includes/` in HTML | meta generator tag (95), X-Powered-By (95) | — | — | Two independent 90+ patterns | high |
| **Drupal** | `/sites/default/files/` or meta generator | meta generator (95), X-Generator header (95) | — | — | — | high |
| **Joomla** | `/media/jui/` or meta generator | meta generator (95) | `/components/com_` (80) | Custom Joomla-named URL | Requires 80+ confidence | high |
| **Shopify** | `cdn.shopify.com` in HTML | CDN domain (95), `_shopify_` cookie (90) | — | — | cdn.shopify.com is definitionally Shopify | high |
| **React** | `react.js` or `data-reactroot` in HTML | `data-reactroot` (90), `__REACT_DEVTOOLS_GLOBAL_HOOK__` (85) | `react.js` filename (80) | Text mention of "react.js" | `_next/static` explicitly excluded (Next.js signal) | high/medium |
| **Next.js** | `_next/static` in HTML or `X-Powered-By: Next.js` | XPB header (99), `__NEXT_DATA__` (95) | — | — | — | high |
| **Vue.js** | `vue.js` or `data-v-*` in HTML | `__vue_app__` (90), `data-v-[hex]` (85) | — | — | — | high |
| **Angular** | `ng-version` attribute | `ng-version=` (95) | `angular.js` (80), `[ng-app]` (75) | — | — | high |
| **Bootstrap** | `bootstrap.min.css` or `bootstrap.min.js` | — | `container`, `navbar` CSS classes | Any site using `container` class | Generic classes explicitly excluded from patterns | medium |
| **Tailwind CSS** | `tailwindcss` literal in HTML/script | literal string (85) | `flex`, `grid`, `text-*` utility classes | Sites using custom utility CSS | Utility class patterns explicitly excluded | medium |
| **Nginx** | `Server: nginx` | header value (99) | — | CDN edge serving nginx header | CDN detected → confidence downgraded to 60, cdn_note added | high (no CDN) / low (CDN) |
| **Apache** | `Server: Apache` | header value (99) | — | CDN masking origin | Same CDN downgrade as Nginx | high (no CDN) / low (CDN) |
| **PHP** | `X-Powered-By: PHP/x.y.z` | XPB header (99), `PHPSESSID` cookie (90) | `.php` URL extension (70) | — | Version extracted from XPB for CVE lookup | high |
| **Django** | *(No reliable passive signal)* | — | `csrftoken` cookie (55), `sessionid` cookie (55) | Flask-WTF, Rails CSRF, custom CSRF — all use same cookie names | Both signals below 60 threshold → Django NOT reported from cookies alone | **Not detectable passively** |
| **Laravel** | `laravel_session` cookie | cookie (95) | `XSRF-TOKEN` cookie (50) | Angular SPA also sets `XSRF-TOKEN` | XSRF-TOKEN explicitly at 50 (<60 threshold) | high |
| **ASP.NET** | `X-Powered-By: ASP.NET` or `X-AspNet-Version` | XPB header (99), `ASP.NET_SessionId` cookie (95) | — | — | — | high |
| **Cloudflare** | `Server: cloudflare` or `CF-Ray` header | CF-Ray header (99) | — | — | — | high |
| **Cookie: missing Secure** | Session cookie without `Secure` flag | `Set-Cookie` header parsed per-cookie | — | Non-HTTPS deployment | Only flagged for `session`/`auth`/`token`/`jwt` named cookies | high |
| **Cookie: missing HttpOnly** | Session cookie without `HttpOnly` flag | Per-cookie `Set-Cookie` parse | — | — | All Set-Cookie headers parsed individually (not just first) | high |
| **Cookie: missing SameSite** | Session cookie with `SameSite=None` or absent | Per-cookie `Set-Cookie` parse | — | `SameSite=Lax` (browser default) | Only flags `None` or absent SameSite | high |

---

## 5. CVE Detection (1 detector)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **CVE via NVD lookup** | Confirmed technology + valid semver version (`X.Y[.Z]`) + CPE mapping | NVD API result with matching CPE | — | CVE for `product ≤ 2.4` returned for `product 5.x` (broad NVD CPE ranges) | Version validated with `_VALID_VERSION_RE` before CPE query; confidence=`medium` on all NVD findings with note to verify version range | medium |
| **CVE via VULNERABLE_VERSIONS** | Confirmed technology + version < threshold | `_version_lt()` comparison | — | Same CPE precision limitation | Hardcoded known-bad version thresholds with specific CVE IDs | high |

---

## 6. Sensitive File / Content Exposure (3 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **Exposed `.git/HEAD`** | HTTP 200 + content starts with `ref: refs/` or 40-char hex SHA | Content validation | HTTP 200 alone | Soft-404 serving 200 | Soft-404 baseline comparison + content validation | high |
| **Exposed `.env`** | HTTP 200 + ≥2 `KEY=VALUE` lines (non-HTML) | 2+ env key-value pairs | Single key-value line | Soft-404 with text content | HTML check + minimum 2 valid lines required | high |
| **Exposed `backup.zip`** | HTTP 200 + ZIP magic bytes `PK\x03\x04` | Magic bytes | `application/zip` Content-Type alone | Soft-404 serving binary | Magic byte check OR Content-Type + size > 100 bytes | high |
| **Exposed `backup.sql`** | HTTP 200 + SQL DDL/DML keywords | `CREATE TABLE`, `INSERT INTO` etc. | — | Soft-404 with random text | SQL keyword check in first 3KB | high |
| **Exposed `.env.production`** | Same as `.env` | Same as `.env` | — | Same | Same | high |
| **WordPress admin** | HTTP 200 + `wp-login.php` or `loginform` in HTML | WordPress-specific strings | Login keyword alone | Generic login page at `/wp-admin/` | WordPress-specific keyword check | high |
| **Admin panel `/admin`** | HTTP 200 + password `<input>` + form action targeting admin/login | Both password input AND admin form action | Password input alone | Nav bar login link | Requires BOTH signals: password input field AND admin form action | medium |
| **phpMyAdmin** | HTTP 200 + `pma_username` or `pma_password` in HTML | phpMyAdmin-specific identifiers | — | — | Specific attribute name check | high |
| **phpinfo.php** | HTTP 200 + `phpinfo()` or `php version` in body | PHP diagnostic page keywords | — | — | Multiple PHP-specific keywords | high |
| **Email addresses** | Email regex match in HTML or visible text | `user@domain.ext` pattern | — | Sentry.io, Bugsnag, SDK embedded addresses | `ignored_domains` set + `ignored_prefixes` | high |
| **HTML comment credentials** | Comment contains security keyword AND credential-name=value pattern | `password = secret123`, `api_key: abc123xyz` | `<!-- TODO: check password flow -->` | Developer advisory comments | `_CREDENTIAL_ASSIGNMENT_RE`: keyword must be directly adjacent to `=` or `:` | high |
| **robots.txt sensitive paths** | HTTP 200 + `Disallow:` + admin/backup/config/secret keyword | Explicit sensitive path disallow | `/upload`, `/api` (excluded) | Upload directories (legitimate SEO practice) | `upload` and `api` explicitly excluded from keyword list | high |

---

## What Explicitly Does NOT Trigger Findings

The following signals are present in the codebase as **commented-out** or **below-threshold** patterns, maintained as documentation of rejected FP sources:

| Signal | Why Excluded |
|---|---|
| `class="container"` in HTML | Used by Bootstrap, Bulma, Foundation, custom CSS — cannot distinguish |
| `class="flex"`, `class="grid"` | Native CSS display values used as class names everywhere |
| `_next/static` in React patterns | Next.js signal — must not trigger generic React detection |
| `XSRF-TOKEN` cookie → Laravel | Angular `HttpClient` also sets this cookie automatically |
| `csrftoken` cookie → Django | Flask-WTF, custom CSRF middleware use same name; confidence 55 < threshold 60 |
| `sessionid` cookie → Django | Too generic; confidence 55 < threshold 60 |
| `Server: nginx` (no version) | Vendor-only disclosure; version pattern `\w[\w-]*/\d[\d.]*` not matched |
| `Server: cloudflare` | CDN banner in benign allowlist |
| HTTP 200 alone → sensitive file | Soft-404 + content validation required |
| `ACAO: *` without `ACAC: true` | Acceptable for public APIs; reported as `info` only |
| `/upload` in robots.txt | Common file-upload SEO exclusion; not security-sensitive |
| `Disallow: /api` in robots.txt | Standard SEO practice |
| `<!-- TODO: fix password -->` | No assignment pattern; advisory text not a credential |
| React CVEs, Angular CVEs, Vue CVEs | Component-level CVEs require package version data passive scanning cannot provide |

---

*Generated by: SentinelScan v1.0 Adversarial Detection Validation, 2026-08-15*
