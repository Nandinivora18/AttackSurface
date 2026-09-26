# SentinelScan — Detector Coverage Report

> Maintained in sync with `app/scanner/metadata.py` (the legacy `coverage_report` generator no longer exists — the `DETECTOR_REGISTRY` in `metadata.py` is the single source of truth).

## Summary

| Metric | Count |
|--------|-------|
| Total detectors | **82** (37 baseline + 45 External Exposure) |
| Detector categories | **28** (16 baseline + 12 external exposure domains) |
| Security headers checked | **16+** |
| OWASP Top 10 categories covered | **10** / 10 |
| RFC references | **24+** |
| OWASP standard references | **32+** |
| CWE references | **28+** |
| NIST references | **4+** |

## Detectors by Category

### Access Control

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.cors.wildcard_credentials` | Flags CORS policies that combine wildcard Access-Control-Allow-Origin with credentials allowed. | [A01](https://owasp.org/Top10/) | 🟢 High (0.9) | All |
| `active.sensitive_path.exposed` | Discovers publicly exposed administrative endpoints and source-control files without authentication. | [A01](https://owasp.org/Top10/) | 🟢 High (0.9) | All |
| `passive.ssrf.parameter_surface` | Evaluates crawled URL-accepting and redirection parameters for potential SSRF attack surface without out-of-band callbacks. | [A01](https://owasp.org/Top10/) | 🟡 Medium (0.7) | All |

### Authentication Failures

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.auth.session_flags` | Evaluates HttpOnly, Secure, and SameSite attributes on session cookies and login interfaces. | [A07](https://owasp.org/Top10/) | 🟢 High (0.9) | All |

### CVE Detection

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `tech.cve_match` | Queries NIST NVD for CVEs matching the detected technology name and version. Requires x.y.z semver version. | [A03](https://owasp.org/Top10/) | 🟡 Medium (0.7) | All |

### Content Exposure

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `content.exposed_file` | Probes for exposed sensitive files (.env, .git/HEAD, backup.sql, wp-config.php.bak, etc.) with soft-404 baseline detection and content validation. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | All |

### Cookie Security

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `header.cookie.security` | Checks Set-Cookie headers for missing Secure, HttpOnly, and SameSite attributes. | [A07](https://owasp.org/Top10/) | 🟢 High (0.95) | All |

### Cryptographic Failures

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.crypto.mixed_content` | Detects unencrypted HTTP scripts, stylesheets, and images embedded on HTTPS pages. | [A04](https://owasp.org/Top10/) | 🟢 High (0.9) | text/html |

### DNS Security

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `dns.dmarc.missing` | Checks for the absence of a DMARC policy at _dmarc.<domain>. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | All |
| `dns.dmarc.weak_policy` | Detects DMARC records with p=none (monitor-only, no enforcement). | [A02](https://owasp.org/Top10/) | 🟢 High (0.95) | All |
| `dns.mx.missing` | Detects domains with no MX records that have an SPF record referencing mail. | [A02](https://owasp.org/Top10/) | 🔴 Low (0.6) | All |
| `dns.spf.missing` | Checks for the absence of a valid SPF TXT record. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | All |

### Injection

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.injection.differential` | Performs controlled differential baseline-vs-canary analysis for SQLi, XSS context reflection, and path traversal. | [A05](https://owasp.org/Top10/) | 🟡 Medium (0.85) | All |

### Insecure Design

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.insecure_design.evaluation` | Evaluates architectural threat models, rate limit design, and OpenAPI security definitions. | [A06](https://owasp.org/Top10/) | 🟡 Medium (0.8) | All |

### Outdated Components

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.components.lifecycle` | Correlates normalized technology versions with vendor lifecycle and end-of-life status. | [A03](https://owasp.org/Top10/) | 🟡 Medium (0.85) | All |

### SSL/TLS

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `ssl.cert.expired` | Detects an expired TLS certificate via live TLS handshake. | [A04](https://owasp.org/Top10/) | 🟢 High (1.0) | All |
| `ssl.cert.expiring_soon` | Warns when a TLS certificate expires within 30 days. | [A04](https://owasp.org/Top10/) | 🟢 High (1.0) | All |
| `ssl.cert.self_signed` | Detects self-signed certificates not issued by a trusted CA. | [A04](https://owasp.org/Top10/) | 🟢 High (0.95) | All |
| `ssl.cipher.weak` | Detects weak cipher suites (RC4, 3DES, EXPORT, NULL, ANON) in TLS negotiation. | [A04](https://owasp.org/Top10/) | 🟢 High (1.0) | All |
| `ssl.protocol.weak` | Detects negotiated TLS protocol versions below TLS 1.2 (SSLv2, SSLv3, TLS 1.0, TLS 1.1). | [A04](https://owasp.org/Top10/) | 🟢 High (1.0) | All |
| `ssl.unavailable` | Detects HTTPS targets that have no valid TLS endpoint. | [A04](https://owasp.org/Top10/) | 🟢 High (0.9) | All |

### Security Headers

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `header.cors.wildcard` | Detects CORS misconfiguration: Access-Control-Allow-Origin: * or reflective origin with credentials. | [A01](https://owasp.org/Top10/) | 🟡 Medium (0.85) | All |
| `header.csp.missing` | Checks for the absence of Content-Security-Policy on HTML responses. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | text/html |
| `header.csp.value` | Validates CSP for unsafe-inline, unsafe-eval, and standalone wildcard (*) directives. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | text/html |
| `header.hsts.missing` | Checks for the absence of the Strict-Transport-Security (HSTS) response header on HTTPS targets. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | All |
| `header.hsts.value` | Validates HSTS max-age, includeSubDomains, and preload directives. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | All |
| `header.permissions_policy.missing` | Checks for the absence of Permissions-Policy (formerly Feature-Policy) on HTML responses. | [A02](https://owasp.org/Top10/) | 🟡 Medium (0.7) | text/html |
| `header.referrer_policy.missing` | Checks for the absence of Referrer-Policy. | [A02](https://owasp.org/Top10/) | 🟡 Medium (0.8) | All |
| `header.server.version` | Detects version disclosure in the Server header, excluding CDN/proxy banners. | [A02](https://owasp.org/Top10/) | 🟡 Medium (0.75) | All |
| `header.xcto.missing` | Checks for the absence of X-Content-Type-Options: nosniff. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | All |
| `header.xfo.missing` | Checks for the absence of X-Frame-Options on HTML responses not covered by CSP frame-ancestors. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | text/html |
| `header.xpoweredby.present` | Detects technology disclosure via X-Powered-By, X-Generator, or X-AspNet-Version headers. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | All |

### Security Logging & Alerting

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.logging.observability` | Audits response correlation headers, verbose exception leaks, and exposed log files. | [A09](https://owasp.org/Top10/) | 🟡 Medium (0.8) | All |

### Security Misconfiguration

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.misconfig.options_methods` | Probes HTTP OPTIONS for enabled TRACE/TRACK methods and dangerous mutating verbs. | [A02](https://owasp.org/Top10/) | 🟢 High (0.9) | All |

### Software Supply Chain

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `active.integrity.sri` | Verifies Subresource Integrity (SRI) hashes on third-party CDN scripts. | [A03](https://owasp.org/Top10/) | 🟢 High (0.9) | text/html |

### Technology Detection

| ID | Description | OWASP | Min Confidence | Content-Types |
|----|-------------|-------|---------------|---------------|
| `tech.fingerprint` | Multi-signal technology fingerprinting from headers, cookies, HTML markers, and response body patterns. | [A03](https://owasp.org/Top10/) | 🔴 Low (0.6) | All |
| `tech.version_disclosure` | Detects explicit version information disclosed via headers or HTML meta tags. | [A02](https://owasp.org/Top10/) | 🟡 Medium (0.7) | All |

## Security Headers Checked

| Header | Category | Missing Severity | HTML Only? |
|--------|----------|-----------------|-----------|
| `strict-transport-security` | HTTP Strict Transport Security (HSTS) | HIGH | No |
| `content-security-policy` | Content Security Policy (CSP) | HIGH | Yes |
| `x-frame-options` | X-Frame-Options | MEDIUM | Yes |
| `x-content-type-options` | X-Content-Type-Options | LOW | No |
| `referrer-policy` | Referrer-Policy | LOW | No |
| `permissions-policy` | Permissions-Policy | LOW | Yes |
| `x-xss-protection` | X-XSS-Protection | INFO | Yes |
| `cross-origin-opener-policy` | Cross-Origin-Opener-Policy (COOP) | LOW | Yes |
| `cross-origin-embedder-policy` | Cross-Origin-Embedder-Policy (COEP) | INFO | Yes |
| `cross-origin-resource-policy` | Cross-Origin-Resource-Policy (CORP) | INFO | No |

## OWASP Top 10:2025 Coverage

Across all 82 registered detectors (37 core baseline + 45 external exposure), SentinelScan achieves comprehensive coverage across all 10 OWASP Top 10:2025 categories:

| OWASP ID | Category | Detectors | Baseline + Exposure Highlights |
|----------|----------|-----------|--------------------------------|
| **A01** | Broken Access Control | ✅ 12 detectors | CORS wildcard with credentials, sensitive path exposure, SSRF parameter surface, null origin CORS, public cloud bucket listing |
| **A02** | Security Misconfiguration | ✅ 25 detectors | Missing HSTS/CSP/XFO/XCTO headers, permissive SPF, missing DMARC, open source maps, exposed `.env`/`.git` files |
| **A03** | Software Supply Chain Failures | ✅ 9 detectors | NIST NVD CVE correlation, EOL lifecycle detection, deprecated CDN dependencies, unversioned third-party libraries |
| **A04** | Cryptographic Failures | ✅ 14 detectors | Expired/self-signed certs, weak TLS 1.0/1.1 protocols, weak ciphers, mixed-content scripts/styles, absent SCTs |
| **A05** | Injection | ✅ 2 detectors | Controlled differential baseline canary analysis (SQLi/XSS/path traversal reflection indicators) |
| **A06** | Insecure Design | ✅ 3 detectors | Architectural threat modeling, rate limit header absence, unkeyed cache poisoning reflection vectors |
| **A07** | Authentication Failures | ✅ 6 detectors | Missing Secure/HttpOnly/SameSite cookie flags, basic auth over unencrypted HTTP, session fixation indicators |
| **A08** | Software or Data Integrity Failures | ✅ 3 detectors | Subresource Integrity (`exposure.dep.no_sri`), untrusted third-party script CDN inclusions |
| **A09** | Security Logging and Alerting Failures | ✅ 3 detectors | DMARC `p=none` without reporting URIs (`rua`/`ruf`), absent security contact records (`security.txt`) |
| **A10** | Mishandling of Exceptional Conditions | ✅ 5 detectors | Exposed debug endpoints (`exposure.api.debug_endpoint`), Spring Boot Actuator (`exposure.api.actuator_exposed`), verbose stack trace leaks |

## External Exposure Detection Domains (45 Detectors)

The 45 External Exposure detectors are organized across 12 dedicated attack surface domains:

1. **Web Security Configuration (4):** `exposure.cors.null_origin`, `exposure.cors.wildcard_creds`, `exposure.headers.missing_security`, `exposure.headers.server_tokens`
2. **Authentication & Session Security (4):** `exposure.auth.cookie_no_secure`, `exposure.auth.cookie_no_httponly`, `exposure.auth.cookie_no_samesite`, `exposure.auth.basic_over_http`
3. **API Exposure (4):** `exposure.api.openapi_exposed`, `exposure.api.graphql_exposed`, `exposure.api.debug_endpoint`, `exposure.api.actuator_exposed`
4. **JavaScript Secrets (4):** `exposure.js.aws_keys`, `exposure.js.generic_tokens`, `exposure.js.github_tokens`, `exposure.js.private_keys`
5. **Source Map Exposure (3):** `exposure.sourcemap.map_file_accessible`, `exposure.sourcemap.inline_sources`, `exposure.sourcemap.source_code_leak`
6. **Sensitive Files / Backup (4):** `exposure.files.env_accessible`, `exposure.files.git_accessible`, `exposure.files.backup_accessible`, `exposure.files.config_accessible`
7. **Cloud Storage Exposure (4):** `exposure.cloud.s3_bucket_public`, `exposure.cloud.gcs_bucket_public`, `exposure.cloud.azure_blob_public`, `exposure.cloud.bucket_listing`
8. **DNS Security Expansion (4):** `exposure.dns.spf_permissive`, `exposure.dns.dmarc_missing`, `exposure.dns.dmarc_none`, `exposure.dns.zone_transfer`
9. **TLS Deep Analysis (4):** `exposure.tls.weak_version`, `exposure.tls.weak_cipher`, `exposure.tls.cert_expired`, `exposure.tls.ct_not_logged`
10. **Mixed Content (3):** `exposure.mixed_content.script`, `exposure.mixed_content.style`, `exposure.mixed_content.form_action`
11. **Third-Party Dependency / SRI (3):** `exposure.dep.no_sri`, `exposure.dep.cdn_dependency`, `exposure.dep.deprecated_lib`
12. **Web Cache / Response Exposure (4):** `exposure.cache.missing_no_store`, `exposure.cache.public_sensitive`, `exposure.cache.unkeyed_header`, `exposure.cache.authenticated_cache`

## Standards Referenced

### RFCs

- RFC 2818
- RFC 4033
- RFC 4034
- RFC 4035
- RFC 5280
- RFC 5280 §4.1.2.5
- RFC 5321
- RFC 6265bis
- RFC 6797
- RFC 6797 §6.1
- RFC 7034
- RFC 7208
- RFC 7231 §4.3
- RFC 7489
- RFC 7489 §6.3
- RFC 8996 (Deprecating TLS 1.0/1.1)
- RFC 9325

### OWASP References

- OWASP ASVS 14.3.3
- OWASP ASVS 14.4.1
- OWASP ASVS 14.4.3
- OWASP ASVS 14.4.4
- OWASP ASVS 14.4.6
- OWASP ASVS 14.5.3
- OWASP ASVS 14.6.1
- OWASP ASVS 3.4.1–3.4.5
- OWASP ASVS 9.1.1
- OWASP ASVS 9.1.3
- OWASP ASVS 9.2.1
- OWASP ASVS 9.2.3
- OWASP Secure Headers Project
- OWASP Top 10 A01
- OWASP Top 10 A02
- OWASP Top 10 A03
- OWASP Top 10 A04
- OWASP Top 10 A05
- OWASP Top 10 A06
- OWASP Top 10 A07
- OWASP Top 10 A09
- OWASP WSTG-CONF-05
- OWASP WSTG-INFO-02

### CWE References

- CWE-1004
- CWE-1035
- CWE-1059
- CWE-1104
- CWE-16
- CWE-200
- CWE-209
- CWE-22
- CWE-284
- CWE-311
- CWE-346
- CWE-353
- CWE-538
- CWE-614
- CWE-778
- CWE-79
- CWE-89
- CWE-918
- CWE-942

### NIST References

- NIST NVD
- NIST SP 800-160
- NIST SP 800-52 Rev 2

---

*This report is maintained manually and must stay in sync with `app/scanner/metadata.py`.*