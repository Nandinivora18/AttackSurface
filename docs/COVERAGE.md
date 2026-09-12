# SentinelScan — Detector Coverage Report

> Auto-generated from `app/scanner/metadata.py` and `app/scanner/header_analyzer.py`.
> Re-generate: `python -m app.scanner.coverage_report > docs/COVERAGE.md`

## Summary

| Metric | Count |
|--------|-------|
| Total detectors | **37** |
| Detector categories | **16** |
| Security headers checked | **10** |
| OWASP Top 10 categories covered | **8** / 10 |
| RFC references | **17** |
| OWASP standard references | **23** |
| CWE references | **19** |
| NIST references | **3** |

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

| OWASP ID | Category | Detectors |
|----------|----------|-----------|
| **A01** | Broken Access Control | ✅ 4 detectors |
| **A02** | Security Misconfiguration | ✅ 18 detectors |
| **A03** | Software Supply Chain Failures | ✅ 4 detectors |
| **A04** | Cryptographic Failures | ✅ 7 detectors |
| **A05** | Injection | ✅ 1 detector |
| **A06** | Insecure Design | ✅ 1 detector |
| **A07** | Authentication Failures | ✅ 2 detectors |
| **A08** | Software or Data Integrity Failures | ⬜ Not covered (outside passive scanning scope) |
| **A09** | Security Logging and Alerting Failures | ✅ 1 detector |
| **A10** | Mishandling of Exceptional Conditions | ⬜ Not covered (outside passive scanning scope) |

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

*This report is auto-generated. Do not edit manually.*
*Generated by `python -m app.scanner.coverage_report`*