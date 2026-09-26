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

## 7. External Exposure: Web Security Configuration (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.cors.null_origin`** | `ACAO: null` received on request | Literal string `"null"` | — | Internal development mocking | Verified on live public response headers | high |
| **`exposure.cors.wildcard_creds`** | `ACAO: *` AND `ACAC: true` | Both headers present | `ACAO: *` alone | Public CDN open APIs | Suppressed to Info if credentials flag is absent | high |
| **`exposure.headers.missing_security`** | Absence of ≥4 core baseline headers (`HSTS`, `CSP`, `XFO`, `XCTO`) | Missing from headers dict | Partial coverage | Non-HTML API endpoints | Evaluated on target primary content response | high |
| **`exposure.headers.server_tokens`** | Detailed runtime/OS disclosure in `Server` or `X-Powered-By` | `Server: Apache/2.4.41 (Ubuntu)`, `X-Powered-By: PHP/7.4.3` | `Server: cloudflare` | Obfuscated proxies | Verified against `_BENIGN_PREFIXES` allowlist | high |

---

## 8. External Exposure: Authentication & Session Security (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.auth.cookie_no_secure`** | `Set-Cookie` on HTTPS lacking `Secure` attribute | `Secure` token missing | — | Dev/testing HTTP sites | Only evaluated for HTTPS responses | high |
| **`exposure.auth.cookie_no_httponly`** | `Set-Cookie` for session identifiers lacking `HttpOnly` | `session`, `auth`, `token`, `jwt` names | Non-session tracking cookies | Analytics cookies (`_ga`, `theme`) | Scoped to session-relevant cookie name patterns | high |
| **`exposure.auth.cookie_no_samesite`** | `Set-Cookie` lacking `SameSite` attribute | `SameSite` token missing | — | Legacy browser targets | Flags absence of Lax/Strict/None enforcement | high |
| **`exposure.auth.basic_over_http`** | `WWW-Authenticate: Basic` header on plaintext HTTP endpoint | Header present without TLS | — | Localhost testing | Enforced strictly on non-TLS endpoints | high |

---

## 9. External Exposure: API Exposure (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.api.openapi_exposed`** | HTTP 200 + valid JSON/YAML containing `openapi:` or `swagger:` | `"openapi": "3.0"` or `"swagger": "2.0"` | Generic JSON 200 | Soft-404 serving JSON error | Requires structural JSON key parsing + OpenAPI markers | high |
| **`exposure.api.graphql_exposed`** | HTTP 200 + GraphQL introspection or schema keywords | `{"data": {"__schema": ...}}` | Generic 400 GraphQL error | Public query endpoint with introspection disabled | Requires affirmative GraphQL schema or Playground HTML | high |
| **`exposure.api.debug_endpoint`** | HTTP 200 + debug dashboard keywords | `/debug/pprof`, `django-debug-toolbar` | `/health` endpoint | Standard orchestration `/health` checks | `/health` and `/ready` with status=UP explicitly allowed | high |
| **`exposure.api.actuator_exposed`** | HTTP 200 + Spring Boot Actuator endpoints | `_links`, `jvm.memory.used`, `env` keys | `/actuator/health` | Public Actuator health check | Sensitive endpoints checked: `/actuator/env`, `/beans`, `/heapdump` | high |

---

## 10. External Exposure: JavaScript Secrets & Token Exposure (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.js.aws_keys`** | AWS access key pattern `AKIA[0-9A-Z]{16}` in client JS | Exact regex match | Generic 20-char alphanumeric | Example keys in documentation | High-entropy validation; redacted before reporting | high |
| **`exposure.js.github_tokens`** | GitHub token pattern `ghp_[0-9a-zA-Z]{36}` in client JS | Exact prefix and format | — | Test fixtures in comments | Format-specific regex matching; redacted before reporting | high |
| **`exposure.js.private_keys`** | RSA/EC/OPENSSH private key header block | `-----BEGIN (RSA\|EC\|OPENSSH\|PRIVATE) KEY-----` | Generic pem cert block | Public X.509 certificate | Distinct negative match on `CERTIFICATE` blocks | high |
| **`exposure.js.generic_tokens`** | High-entropy authorization bearer or private API key tokens | High Shannon entropy + assignment | Generic string literals | Minified bundle variable names | Calibrated honestly: Medium confidence; token redacted | medium |

---

## 11. External Exposure: Source Map Exposure (3 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.sourcemap.map_file_accessible`** | HTTP 200 on `.js.map` file + valid JSON containing `sources` | `"version": 3, "sources": [...]` | HTTP 200 on random URL | Soft-404 serving HTML | Validates JSON parse and presence of `sources` array | high |
| **`exposure.sourcemap.inline_sources`** | Valid `.map` file with `sourcesContent` array containing raw code | `"sourcesContent": ["const x = ..."]` | Empty sourcesContent | Minified source code | Verifies non-empty source files embedded in map | high |
| **`exposure.sourcemap.source_code_leak`** | Referenced source maps publicly downloadable on CDN/origin | `//# sourceMappingURL=` resolves to 200 | Comment present, file 404 | Source maps hosted internally | SafeFetch probe validates public availability | high |

---

## 12. External Exposure: Sensitive Files & Backup Exposure (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.files.env_accessible`** | HTTP 200 + plaintext environment variables | ≥2 `KEY=VALUE` pairs (non-HTML) | Generic text response | Soft-404 returning homepage | Token overlap baseline comparison + HTML rejection | high |
| **`exposure.files.git_accessible`** | HTTP 200 on `/.git/config` or `/.git/HEAD` | `[core]`, `repositoryformatversion` | Generic 200 response | Custom SPA 404 handler | Verifies Git repository configuration syntax | high |
| **`exposure.files.backup_accessible`** | HTTP 200 + archive magic bytes or SQL dump syntax | `PK\x03\x04`, `CREATE TABLE` | `application/octet-stream` | Soft-404 serving empty binary | Magic byte header check + minimum size (>100 bytes) | high |
| **`exposure.files.config_accessible`** | HTTP 200 on configuration endpoints (`web.config`, `config.json`) | Valid XML/JSON configuration keys | HTML error page | Soft-404 | Format validation + parser check | high |

---

## 13. External Exposure: Cloud Storage Exposure (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.cloud.s3_bucket_public`** | HTTP 200 on AWS S3 bucket endpoint | `<ListBucketResult>` XML root | 403 Forbidden | Authenticated or private S3 bucket | Verified via safe HTTP HEAD/GET; write operations forbidden | high |
| **`exposure.cloud.gcs_bucket_public`** | HTTP 200 on GCP Cloud Storage bucket URL | XML/JSON bucket listing | 401/403 response | Private GCP bucket | Validates unauthenticated read response | high |
| **`exposure.cloud.azure_blob_public`** | HTTP 200 on Azure Blob container URL | `<EnumerationResults>` XML | ResourceNotFound | Private container | Confirms unauthenticated XML container response | high |
| **`exposure.cloud.bucket_listing`** | Public directory listing containing object keys and timestamps | `<Contents><Key>...</Key>` | AccessDenied | Private bucket root | Only reported when unauthenticated object listing is confirmed | high |

---

## 14. External Exposure: DNS Security Expansion (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.dns.spf_permissive`** | DNS TXT record containing `+all` or `?all` | Literal `+all` or `?all` mechanism | `~all` (softfail) | Intentional transition policy | `~all` explicitly allowed; flagged only on `+all`/`?all` | high |
| **`exposure.dns.dmarc_missing`** | Absence of `_dmarc.<domain>` TXT record | NXDOMAIN or no TXT record | — | Non-mail sending domain | Cross-referenced with MX record presence | high |
| **`exposure.dns.dmarc_none`** | DMARC record exists with `p=none` without reporting URIs | `p=none` without `rua=` or `ruf=` | `p=none` with active `rua=` | Initial monitoring phase | Flags absence of active enforcement and visibility | high |
| **`exposure.dns.zone_transfer`** | Successful AXFR query response returning full DNS zone | Full zone response returned | REFUSED / NOTAUTH | Zone transfer restricted to primaries | Passive query only; AXFR attempt rejected by standard nameservers | high |

---

## 15. External Exposure: TLS Deep Analysis (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.tls.weak_version`** | Negotiated protocol is TLS 1.0 or TLS 1.1 | Python SSL negotiated protocol | Server supports but negotiates 1.3 | Legacy compatibility gateways | Direct socket handshake verifies negotiated protocol | high |
| **`exposure.tls.weak_cipher`** | Negotiated cipher in known weak/deprecated blocklist | 3DES, RC4, NULL, EXPORT ciphers | CBC ciphers on TLS 1.2 | Custom cipher ordering | Evaluates actual negotiated cipher suite | high |
| **`exposure.tls.cert_expired`** | Certificate `notAfter` date < current timestamp | Validated X.509 date | Self-signed cert | Timezone differences | Evaluates UTC timestamp comparison | high |
| **`exposure.tls.ct_not_logged`** | Absence of Signed Certificate Timestamps (SCTs) in TLS/X.509 | No SCT extension in handshake or cert | — | Internal private CA | Honest caveat: checks extension presence, not public CT proofs | medium |

---

## 16. External Exposure: Mixed Content (3 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.mixed_content.script`** | `http://` script source on HTTPS page | `<script src="http://...">` | Relative URLs | Protocol-relative `//` | Evaluated strictly on `http://` scheme matches | high |
| **`exposure.mixed_content.style`** | `http://` stylesheet link or `@import` on HTTPS page | `<link rel="stylesheet" href="http://...">` | CSS background URLs | Protocol-relative `//` | Evaluates link tags and CSS import statements | high |
| **`exposure.mixed_content.form_action`** | `<form action="http://...">` on HTTPS page | Insecure form submission action | — | Form action to external non-sensitive site | Categorized as Medium severity; validates unencrypted data post | high |

---

## 17. External Exposure: Third-Party Dependency & SRI (3 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.dep.no_sri`** | External CDN `<script>` tag lacking `integrity` attribute | Third-party script without `integrity` | First-party script | In-house CDN on same root domain | Same-origin and first-party CDN hostnames excluded | medium |
| **`exposure.dep.cdn_dependency`** | High reliance on untrusted or unpinned third-party CDNs | Multiple external CDN domains | Single trusted CDN (cdnjs) | High availability CDN | Evaluates total external script dependencies | medium |
| **`exposure.dep.deprecated_lib`** | Detected semver version matches known end-of-life library | Angular 1.x, jQuery < 3.5.0 | Unversioned library | Backported vendor security patches | Notes vendor backport caveat; reports published CVEs | medium |

---

## 18. External Exposure: Web Cache & Sensitive Response Exposure (4 detectors)

| Detector | Evidence Required | Strong Signal | Weak Signal | Known FP Scenario | Mitigation | Confidence |
|---|---|---|---|---|---|---|
| **`exposure.cache.missing_no_store`** | Sensitive endpoint response lacking `no-store` in `Cache-Control` | Auth/account endpoint with public cache | Static asset cache | Generic marketing pages | Scoped to authenticated, user-specific, or login endpoints | medium |
| **`exposure.cache.public_sensitive`** | `Cache-Control: public` present on responses containing session data | `public` + `Set-Cookie` header | Static images | Cookie set on non-cached static resources | Evaluates combination of public caching and sensitive headers | high |
| **`exposure.cache.unkeyed_header`** | Response reflects unkeyed client headers without proper `Vary` | Reflected header without `Vary` | Standard CDN Vary | Static content | Tests reflection of custom request headers | medium |
| **`exposure.cache.authenticated_cache`** | Authenticated response cached without `private` or `no-store` | 200 with Auth + cacheable headers | Generic API response | Public unauthenticated API | Requires presence of authentication indicators | medium |

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
