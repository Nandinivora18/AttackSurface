# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ |
| < 1.0 | ❌ |

---

## Responsible Disclosure

We take security seriously. If you discover a security vulnerability in SentinelScan, please report it responsibly.

**Do NOT:**
- Open a public GitHub issue for security vulnerabilities
- Exploit the vulnerability beyond what is necessary to demonstrate the issue
- Access or modify other users' data

**Do:**
- Email your findings to: `security@sentinelscan.io`
- Include a clear description of the vulnerability
- Include steps to reproduce
- Include the potential impact assessment
- Include your name/handle if you'd like to be credited

---

## What We Consider a Vulnerability

- Authentication bypass
- Authorization flaws allowing access to other users' data (IDOR)
- SSRF vulnerabilities (bypassing the URL validation)
- SQL injection
- Remote code execution
- Sensitive data exposure (JWT secrets, database credentials)
- Cross-site scripting (XSS) in the web interface
- CSRF vulnerabilities

## What We Do NOT Consider Vulnerabilities

- Rate limiting bypass for public endpoints (expected)
- Scanner findings that are informational by design
- Vulnerabilities in third-party dependencies (report upstream)
- Denial of service via large scan volumes (governed by rate limits)

---

## Response Timeline

| Step | Timeline |
|---|---|
| Initial acknowledgement | Within 48 hours |
| Triage and severity assessment | Within 5 business days |
| Fix development (Critical/High) | Within 30 days |
| Public disclosure | After fix is deployed |

---

## Credit

We credit security researchers who report valid vulnerabilities in the release notes of the fixing version, unless they request anonymity.
