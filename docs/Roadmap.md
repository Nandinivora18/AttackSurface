# Roadmap

All items are realistic and grounded in the current architecture. Items marked **Not Planned** acknowledge known limitations that are out of scope for the current architecture.

---

## Version 1.1 — Scan Quality & Automation

*Target: next development cycle*

### Authenticated Scan Mode

Allow users to provide a session cookie or Bearer token for scanning authenticated pages. The scanner will pass the credentials with every HTTP request, enabling detection of:
- Vulnerabilities hidden behind login walls
- User-role-specific misconfigurations
- API endpoint security headers on authenticated routes

Domain ownership verification (via DNS TXT or meta tag verification) will be required before authenticated scan mode is enabled.

### Scheduled Scans

Allow users to schedule automatic recurring scans (daily, weekly, monthly) for monitored assets. Implemented via ARQ cron jobs at the user level.

Requires:
- Cron expression storage per asset
- ARQ scheduling logic
- Email notification on score change

### Webhook Notifications

Deliver scan results to a user-specified webhook URL (e.g. Slack, Teams, custom endpoint) in addition to email.

### Scan Profiles / Presets

Allow users to configure which scanner modules to enable or disable per scan. Useful for:
- Skipping CVE lookup for speed
- Focusing on email security (DNS only)
- Reducing noise for known CDN deployments

### HSTS Preload Check

Add detection for whether the domain is included in the HSTS preload list maintained by browsers.

---

## Version 1.2 — Detection Breadth

*Medium-term*

### Subdomain Enumeration

Passive subdomain discovery via public sources (Certificate Transparency logs, DNS brute-force is out of scope). Identify subdomains that may have lower security standards than the apex domain.

### WAF Detection

Detect whether the target is protected by a Web Application Firewall. Identify the WAF vendor (Cloudflare, AWS WAF, ModSecurity, Akamai) based on response patterns and headers.

**Use case:** Inform users that findings may represent the WAF configuration, not the origin server configuration.

### Custom Policy Rules

Allow users or organizations to define custom finding rules:
- "Flag any site not using HSTS with preload"
- "Flag any CVE with CVSS ≥ 7.0"
- "Require p=reject for DMARC"

Rules stored as JSON policy objects and evaluated against findings post-scan.

### Expanded CVE Database Coverage

In addition to NVD API queries, integrate:
- GitHub Advisory Database (GHSA)
- OSV.dev for language-specific vulnerability databases

### HTTP/2 and HTTP/3 Detection

Detect whether the target supports HTTP/2 (`h2`) or HTTP/3 (`h3`) and report protocol version as an informational finding.

### Enhanced Cookie Analysis

- SameSite=Lax vs SameSite=Strict analysis
- Cookie prefix detection (`__Secure-`, `__Host-`)
- Cookie scoping analysis (domain= attribute)

---

## Version 2.0 — Teams and Organizations

*Long-term*

### Multi-User Organizations

Allow multiple users to share a workspace with:
- Shared scan history and reports
- Role-based access (org admin, analyst, read-only)
- Organization-level notification channels
- Team billing and usage limits

### SAML / SSO Integration

Enterprise Single Sign-On via SAML 2.0. Integrate with Okta, Azure AD, Google Workspace for corporate deployments.

### Scan Comparison Dashboard

Enhanced scan delta view showing:
- Security score trend chart for a specific domain
- New vulnerabilities introduced per code release
- Regression detection (resolved vulnerabilities that reappear)

### API-First Scanning

Full REST API for scan submission and result retrieval, enabling:
- CI/CD pipeline integration (scan on every deployment)
- Third-party tool integration
- Automated compliance workflows

### Asset Monitoring (Continuous)

Automated re-scan of registered assets on a schedule, with:
- Alert on score degradation (e.g. new High finding)
- Alert on certificate approaching expiry
- Drift detection (new technologies appearing)

### Compliance Report Templates

Pre-built report templates aligned to:
- PCI DSS web application requirements
- OWASP ASVS checklist
- CIS Web Application Benchmarks

---

## Version 3.0 — Enterprise Platform

*Long-term research phase*

### Active Scanning Mode (Opt-in)

For verified domain owners, an opt-in active scanning mode that can:
- Submit forms (safe test payloads only)
- Follow authenticated user flows
- Test common XSS and injection patterns (non-destructive)

**Note:** This requires significant legal, operational, and technical work. Not on the immediate roadmap.

### API Security Testing

Analyze REST/GraphQL API schemas (OpenAPI, introspection) for:
- Missing authentication on endpoints
- Excessive data exposure
- Rate limiting absence
- Dangerous HTTP methods enabled

### Dependency Analysis (SCA)

For applications that expose their frontend dependencies (via `package.json` or import map links), perform Software Composition Analysis against known vulnerable library versions.

### Threat Intelligence Feeds

Integrate real-time threat intelligence feeds to:
- Flag target IPs on block lists
- Detect use of known compromised CDN nodes
- Identify services with recent active exploitation reports

---

## Not Planned (Current Architecture)

| Feature | Reason |
|---|---|
| Source code analysis (SAST) | Requires code repository access |
| Agent-based continuous monitoring | Requires deployed agent on target |
| Browser-based dynamic testing | Requires Playwright/Selenium integration |
| Internal network scanning | Prohibited by SSRF protection (by design) |
| Full web crawling | Out of scope for passive assessment |
