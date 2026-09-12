"""
Threat Intelligence Mapping
Provides OWASP Top 10:2025 and MITRE ATT&CK mappings for all findings.
"""
from typing import Any


# ─── OWASP Top 10:2025 ───────────────────────────────────────────────────────

OWASP_TOP10 = {
    "A01": {
        "id": "A01", "title": "Broken Access Control",
        "description": "Access control enforces policy such that users cannot act outside of their intended permissions. Failures lead to unauthorized information disclosure, privilege escalation, or access-boundary evasion.",
        "reference": "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
    },
    "A02": {
        "id": "A02", "title": "Security Misconfiguration",
        "description": "Security settings defined with insecure defaults, missing defensive headers, directory indexing, legacy HTTP methods, verbose error disclosures, or missing DNS security controls.",
        "reference": "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/",
    },
    "A03": {
        "id": "A03", "title": "Software Supply Chain Failures",
        "description": "Risks arising from third-party dependencies, unverified external resources, missing Subresource Integrity (SRI), end-of-life components, and correlated known vulnerabilities (CVEs).",
        "reference": "https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/",
    },
    "A04": {
        "id": "A04", "title": "Cryptographic Failures",
        "description": "Failures related to cryptography leading to exposure of sensitive data in transit or at rest. Covers deprecated TLS protocols, weak ciphers, expired certificates, and unencrypted transmission.",
        "reference": "https://owasp.org/Top10/A04_2025-Cryptographic_Failures/",
    },
    "A05": {
        "id": "A05", "title": "Injection",
        "description": "Injection flaws occur when hostile data is sent to an interpreter as part of a command or query, including SQL, path traversal, and reflected cross-site script contexts.",
        "reference": "https://owasp.org/Top10/A05_2025-Injection/",
    },
    "A06": {
        "id": "A06", "title": "Insecure Design",
        "description": "Risks related to architectural and design flaws, missing threat modeling, unmitigated trust boundaries, and absence of rate limiting or resource consumption safeguards.",
        "reference": "https://owasp.org/Top10/A06_2025-Insecure_Design/",
    },
    "A07": {
        "id": "A07", "title": "Authentication Failures",
        "description": "Confirmation of user identity, session management, and credential protection is critical to prevent automated credential attacks, session hijacking, or cleartext credential exposure.",
        "reference": "https://owasp.org/Top10/A07_2025-Authentication_Failures/",
    },
    "A08": {
        "id": "A08", "title": "Software or Data Integrity Failures",
        "description": "Failures where applications rely on code, serialization objects, or state data without verifying integrity, exposing systems to client-side state manipulation or unauthorized execution.",
        "reference": "https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures/",
    },
    "A09": {
        "id": "A09", "title": "Security Logging and Alerting Failures",
        "description": "Insufficient logging, alerting, detection, and response allowing attacks to proceed undetected. Includes missing correlation headers, exposed log files, and unmonitored exception events.",
        "reference": "https://owasp.org/Top10/A09_2025-Security_Logging_and_Alerting_Failures/",
    },
    "A10": {
        "id": "A10", "title": "Mishandling of Exceptional Conditions",
        "description": "Improper error and exception handling exposing internal stack traces, framework debug diagnostics, or leaking system internals when processing exceptional conditions.",
        "reference": "https://owasp.org/Top10/A10_2025-Mishandling_of_Exceptional_Conditions/",
    },
}


# ─── MITRE ATT&CK Techniques ─────────────────────────────────────────────────

MITRE_TECHNIQUES = {
    "T1190": {
        "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. Vulnerabilities (CVEs) in public-facing software are primary targets.",
        "reference": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1059": {
        "technique_id": "T1059", "technique_name": "Command and Scripting Interpreter",
        "description": "Adversaries may abuse command and script interpreters to execute commands or scripts. Reflected XSS via missing or weak CSP enables client-side script injection.",
        "reference": "https://attack.mitre.org/techniques/T1059/",
    },
    "T1557": {
        "technique_id": "T1557", "technique_name": "Adversary-in-the-Middle",
        "description": "Adversaries may position themselves between two networked devices to intercept and manipulate traffic. Weak TLS configuration and missing HSTS enable AiTM attacks.",
        "reference": "https://attack.mitre.org/techniques/T1557/",
    },
    "T1566": {
        "technique_id": "T1566", "technique_name": "Phishing",
        "description": "Missing SPF, DMARC and DKIM records allow attackers to spoof the domain in phishing campaigns, tricking recipients into believing messages come from the legitimate organisation.",
        "reference": "https://attack.mitre.org/techniques/T1566/",
    },
    "T1589": {
        "technique_id": "T1589", "technique_name": "Gather Victim Identity Information",
        "description": "Adversaries may gather information about the victim that can be used during targeting. Information disclosure headers expose internal system details useful for targeting.",
        "reference": "https://attack.mitre.org/techniques/T1589/",
    },
    "T1592": {
        "technique_id": "T1592", "technique_name": "Gather Victim Host Information",
        "description": "Adversaries may gather information about the victim hosts to use during targeting. Server/technology version headers expose software fingerprinting information to attackers.",
        "reference": "https://attack.mitre.org/techniques/T1592/",
    },
    "T1040": {
        "technique_id": "T1040", "technique_name": "Network Sniffing",
        "description": "Adversaries may sniff network traffic to capture information. Sites accessible over plain HTTP allow all transmitted data including credentials to be intercepted.",
        "reference": "https://attack.mitre.org/techniques/T1040/",
    },
    "T1530": {
        "technique_id": "T1530", "technique_name": "Data from Cloud Storage",
        "description": "Adversaries may access data from improperly secured storage. Exposed sensitive files, API keys and credentials in web-accessible locations are high-value targets.",
        "reference": "https://attack.mitre.org/techniques/T1530/",
    },
    "T1213": {
        "technique_id": "T1213", "technique_name": "Data from Information Repositories",
        "description": "Adversaries may leverage information repositories to mine valuable information. Exposed email addresses and internal content facilitate reconnaissance and social engineering.",
        "reference": "https://attack.mitre.org/techniques/T1213/",
    },
}


# ─── Mapping Rules ────────────────────────────────────────────────────────────
# (category_keyword, title_keyword, owasp_id, mitre_id | None)
# Rules are evaluated top-to-bottom; first full match wins.

_MAPPING_RULES: list[tuple[str, str, str, str | None]] = [
    # A03:2025 Software Supply Chain Failures (CVEs, component lifecycle, EOL, SRI, dependencies)
    ("",               "cve-",                    "A03", "T1190"),
    ("cve",            "",                        "A03", "T1190"),
    ("vulnerable",     "",                        "A03", "T1190"),
    ("outdated",       "",                        "A03", "T1190"),
    ("",               "end-of-life",             "A03", "T1190"),
    ("",               "lifecycle",               "A03", "T1190"),
    ("",               "update available",        "A03", "T1190"),
    ("supply chain",   "",                        "A03", "T1190"),
    ("subresource integrity", "",                 "A03", "T1190"),
    ("",               "sri",                     "A03", "T1190"),
    ("",               "external script",         "A03", "T1190"),

    # A10:2025 Mishandling of Exceptional Conditions (verbose stack traces, unhandled exceptions, debug pages)
    ("",               "stack trace",             "A10", None),
    ("",               "debug information disclosed", "A10", None),
    ("",               "debug mode",              "A10", None),
    ("",               "unhandled error",         "A10", None),
    ("",               "exception indicates",     "A10", None),
    ("exceptional conditions", "",                "A10", None),

    # A04:2025 Cryptographic Failures (TLS, SSL, weak ciphers, expired certs, mixed content, HSTS)
    ("ssl",            "",                        "A04", "T1557"),
    ("tls",            "",                        "A04", "T1557"),
    ("transport",      "",                        "A04", "T1557"),
    ("",               "expired",                 "A04", "T1557"),
    ("",               "certificate",             "A04", "T1557"),
    ("",               "weak cipher",             "A04", "T1557"),
    ("",               "weak tls",                "A04", "T1557"),
    ("",               "hsts",                    "A04", "T1557"),
    ("",               "strict-transport",        "A04", "T1557"),
    ("",               "https not available",     "A04", "T1040"),
    ("",               "no https redirect",       "A04", "T1040"),
    ("",               "plain http",              "A04", "T1040"),
    ("cryptographic",  "",                        "A04", "T1557"),
    ("",               "mixed content",           "A04", "T1557"),

    # A05:2025 Injection (SQLi, reflected canary reflection, path traversal)
    ("injection",      "",                        "A05", "T1059"),
    ("injection prevention", "",                  "A05", "T1059"),
    ("",               "sql",                     "A05", "T1059"),
    ("",               "traversal",               "A05", "T1059"),
    ("",               "reflection",              "A05", "T1059"),

    # A01:2025 Broken Access Control (CORS, sensitive paths, admin exposure, SSRF parameter surface)
    ("",               "cors misconfiguration",    "A01", "T1589"),
    ("access control", "",                        "A01", "T1589"),
    ("",               "administrative interface", "A01", "T1589"),
    ("",               ".git repository",         "A01", "T1530"),
    ("ssrf",           "",                        "A01", "T1190"),
    ("",               "server-side request forgery", "A01", "T1190"),
    ("",               "ssrf parameter",          "A01", "T1190"),

    # A07:2025 Authentication Failures (Session cookies, login transport, cleartext forms)
    ("cookie",         "",                        "A07", "T1557"),
    ("",               "cookie",                  "A07", "T1557"),
    ("",               "httponly",                "A07", None),
    ("",               "samesite",                "A07", None),
    ("",               "secure flag",             "A04", "T1557"),
    ("authentication", "",                        "A07", None),
    ("session",        "",                        "A07", None),
    ("",               "login",                   "A07", None),

    # A09:2025 Security Logging and Alerting Failures
    ("telemetry",      "",                        "A09", None),
    ("logging",        "",                        "A09", None),
    ("",               "log file",                "A09", None),
    ("",               "correlation tracking",    "A09", None),
    ("",               "correlation header",      "A09", None),

    # A06:2025 Insecure Design
    ("insecure design","",                        "A06", None),
    ("design",         "",                        "A06", None),
    ("",               "threat modeling",         "A06", None),
    ("",               "rate-limiting controls",  "A06", None),
    ("",               "trust boundaries",        "A06", None),

    # A08:2025 Software or Data Integrity Failures
    ("integrity",      "",                        "A08", None),

    # A02:2025 Security Misconfiguration (Defensive headers, DNS, directory listing, banners)
    ("",               "unsafe-inline",           "A02", "T1059"),
    ("",               "unsafe-eval",             "A02", "T1059"),
    ("",               "wildcard",                "A02", "T1059"),
    ("",               "content security policy", "A02", "T1059"),
    ("",               "missing csp",             "A02", "T1059"),
    ("cors",           "",                        "A02", "T1589"),
    ("",               "cors allows",              "A02", "T1589"),
    ("",               "access-control-allow",    "A02", "T1589"),
    ("clickjacking",   "",                        "A02", None),
    ("",               "x-frame-options",         "A02", None),
    ("information disclosure", "",                "A02", "T1592"),
    ("",               "server header",           "A02", "T1592"),
    ("",               "discloses version",       "A02", "T1592"),
    ("",               "discloses software",      "A02", "T1592"),
    ("",               "x-powered-by",            "A02", "T1592"),
    ("",               "aspnet",                  "A02", "T1592"),
    ("",               "technology stack",        "A03", "T1592"),
    ("technology",     "",                        "A03", "T1592"),
    ("dns",            "",                        "A02", None),
    ("",               "spf",                     "A02", "T1566"),
    ("",               "dmarc",                   "A02", "T1566"),
    ("",               "dkim",                    "A02", "T1566"),
    ("content",        "",                        "A02", "T1213"),
    ("",               "exposed",                 "A02", "T1530"),
    ("",               "email address",           "A02", "T1589"),
    ("",               "api key",                 "A02", "T1530"),
    ("",               "credential",              "A02", "T1530"),
    ("",               "sensitive",               "A02", "T1213"),
    ("",               "private key",             "A02", "T1530"),
    ("http methods",   "",                        "A02", None),
    ("",               "trace/track",             "A02", None),
    ("misconfiguration", "",                      "A02", None),
    ("configuration",  "",                        "A02", None),
    ("security headers", "",                      "A02", None),
    ("header",         "",                        "A02", None),
    ("",               "missing",                 "A02", None),
    ("privacy",        "",                        "A02", None),
    ("feature control","",                        "A02", None),
    ("isolation",      "",                        "A02", None),

    # Default fallback to A02:2025 Security Misconfiguration
    ("",               "",                        "A02", None),
]


def enrich_finding_recommendation(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Enriches a finding dict with 9 recommendation fields:
    problem, impact, risk_analysis, technical_details, evidence,
    fix_steps, configuration_example, best_practices, official_documentation.
    Follows beginner-first plain English presentation with clear verification.
    """
    title = finding.get("title", "")
    category = finding.get("category", "")
    severity = (finding.get("severity") or "info").lower()
    rec = finding.get("recommendation", "")
    desc = finding.get("description", "")
    title_l = title.lower()

    # 1. WHAT'S WRONG? (Simple English Explanation)
    if not finding.get("problem"):
        if "hsts" in title_l or "strict-transport" in title_l:
            finding["problem"] = "Your website is missing a security setting that tells browsers to always use the secure HTTPS version of your website."
        elif "content-security-policy" in title_l or "csp" in title_l:
            if "unsafe-inline" in title_l or "unsafe" in title_l:
                finding["problem"] = "Your website allows certain scripts to run directly inside the webpage, which reduces the browser protection that Content Security Policy normally provides against malicious scripts."
            else:
                finding["problem"] = "Your website is missing a Content Security Policy (CSP), which is a browser safety setting that controls which external scripts and resources are allowed to load."
        elif "frame" in title_l or "clickjacking" in title_l:
            finding["problem"] = "Your website does not restrict other sites from embedding your pages inside invisible frames, which could trick visitors into clicking buttons they did not intend to click."
        elif "content-type-options" in title_l or "sniffing" in title_l:
            finding["problem"] = "Your website does not prevent web browsers from guessing file types, which could allow malicious uploaded files to be mistakenly run as executable scripts."
        elif "referrer" in title_l:
            finding["problem"] = "Your website does not specify a Referrer Policy, which may accidentally share internal page URLs when visitors click outgoing links to other websites."
        elif "permissions" in title_l or "feature" in title_l:
            finding["problem"] = "Your website does not explicitly restrict browser device features like camera, microphone, or location access."
        elif "cookie" in title_l:
            finding["problem"] = "Your website sets browser cookies without essential security flags (Secure, HttpOnly, SameSite) to protect user session credentials."
        elif "cve" in title_l or "outdated" in title_l:
            finding["problem"] = f"Your website appears to be running a software component with a publicly recorded security issue ({finding.get('cve_id') or title})."
        elif "spf" in title_l or "dmarc" in title_l or "dkim" in title_l or "email" in title_l:
            finding["problem"] = "Your domain is missing recommended email authentication records, making it easier for scammers to send fake emails pretending to come from your domain."
        elif "certificate" in title_l or "ssl" in title_l or "tls" in title_l or "expired" in title_l:
            finding["problem"] = "Your website has an SSL/TLS encryption certificate or security configuration issue that needs attention to maintain secure visitor connections."
        elif "cors" in title_l:
            finding["problem"] = "Your website has a permissive Cross-Origin Resource Sharing (CORS) setting that might allow unauthorized websites to read private data."
        elif "server" in title_l or "disclosure" in title_l or "powered-by" in title_l:
            finding["problem"] = "Your web server reveals its exact software name and version number in public responses, giving potential attackers helpful reconnaissance clues."
        elif "exposed" in title_l or "sensitive" in title_l:
            finding["problem"] = "A sensitive configuration or source repository file appears to be publicly accessible on your web server."
        else:
            finding["problem"] = desc or f"Your website has a security configuration setting that should be updated: {title}."

    # 2. WHY IT MATTERS (Plain English Risk)
    if not finding.get("impact"):
        if "hsts" in title_l or "strict-transport" in title_l:
            finding["impact"] = "Without this setting, someone on an unsafe network could potentially interfere with a visitor's connection before it is securely established."
        elif "content-security-policy" in title_l or "csp" in title_l:
            finding["impact"] = "If an attacker finds a way to inject code into your website, this missing setting allows the malicious script to run inside your visitors' browsers, risking stolen logins or data."
        elif "frame" in title_l or "clickjacking" in title_l:
            finding["impact"] = "Attackers can load your website inside a transparent frame on another site to deceive logged-in users into clicking sensitive actions."
        elif "cookie" in title_l:
            finding["impact"] = "Cookies without protection flags can be intercepted over unencrypted connections or read by untrusted scripts, putting user accounts at risk."
        elif "cve" in title_l or "outdated" in title_l:
            finding["impact"] = "Running outdated components with known weaknesses makes your website an easy target for automated attack tools that scan for known security flaws."
        elif "spf" in title_l or "dmarc" in title_l or "email" in title_l:
            finding["impact"] = "Phishing attackers can impersonate your brand by sending fraudulent emails using your domain name."
        elif "certificate" in title_l or "ssl" in title_l or "expired" in title_l:
            finding["impact"] = "Visitors may see scary browser security warnings that block them from visiting your site, and sensitive data transmitted to your website could be vulnerable to eavesdropping."
        elif "exposed" in title_l:
            finding["impact"] = "Attackers can read credentials, secret keys, or internal source code directly from your web server."
        else:
            finding["impact"] = f"This issue affects the security of your website and should be addressed to reduce the chances of unauthorized access or exploitation."

    # 3. Risk Analysis
    if not finding.get("risk_analysis"):
        sev_label = {"critical": "Critical — Urgent attention required", "high": "High — Important security fix", "medium": "Medium — Recommended improvement", "low": "Low — Security hardening measure", "info": "Informational — Good practice"}.get(severity, f"Severity: {severity.upper()}")
        finding["risk_analysis"] = f"{sev_label}. Evaluated based on potential exploit impact and ease of remediation."

    # 4. Technical Details
    if not finding.get("technical_details"):
        finding["technical_details"] = f"Detected during [{category}] scan. Evidence captured from HTTP response headers, SSL handshake, or DNS records."

    # 5. HOW TO FIX IT (Actionable Step-by-Step + Verification)
    if not finding.get("fix_steps"):
        if rec and ";" in rec:
            finding["fix_steps"] = [s.strip() for s in rec.split(";") if s.strip()]
        elif rec:
            finding["fix_steps"] = [
                rec,
                "Save your server configuration and reload your web server.",
                "Run another SentinelScan scan to confirm the setting is detected."
            ]
        else:
            finding["fix_steps"] = [
                f"Open your web server configuration file (such as Nginx, Apache, or your CDN settings).",
                f"Add or enable the recommended security setting for {title}.",
                "Save the configuration and reload your web service.",
                "Run another SentinelScan scan to confirm the fix."
            ]

    # 6. Configuration Example
    if not finding.get("configuration_example"):
        if "hsts" in title_l or "strict-transport" in title_l:
            finding["configuration_example"] = "# Nginx:\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n# Apache:\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
        elif "content-security-policy" in title_l or "csp" in title_l:
            finding["configuration_example"] = "# Nginx:\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' https:; object-src 'none'; base-uri 'self';\" always;\n\n# Apache:\nHeader set Content-Security-Policy \"default-src 'self'; script-src 'self' https:; object-src 'none'; base-uri 'self';\""
        elif "frame" in title_l or "clickjacking" in title_l:
            finding["configuration_example"] = "# Nginx:\nadd_header X-Frame-Options \"DENY\" always;\n\n# Apache:\nHeader always set X-Frame-Options \"DENY\""
        elif "content-type-options" in title_l or "sniffing" in title_l:
            finding["configuration_example"] = "# Nginx:\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# Apache:\nHeader always set X-Content-Type-Options \"nosniff\""
        elif "referrer" in title_l:
            finding["configuration_example"] = "# Nginx:\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n\n# Apache:\nHeader always set Referrer-Policy \"strict-origin-when-cross-origin\""
        elif "permissions" in title_l:
            finding["configuration_example"] = "# Nginx:\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n\n# Apache:\nHeader always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\""
        elif "cookie" in title_l:
            finding["configuration_example"] = "# Set-Cookie header with all security flags:\nSet-Cookie: session_id=abc123xyz; Secure; HttpOnly; SameSite=Lax; Path=/;"
        elif "spf" in title_l or "dmarc" in title_l:
            finding["configuration_example"] = "# DNS TXT Record for SPF:\nv=spf1 include:_spf.google.com ~all\n\n# DNS TXT Record for DMARC (_dmarc.example.com):\nv=DMARC1; p=quarantine; rua=mailto:dmarc-reports@example.com"
        else:
            finding["configuration_example"] = f"# Recommended configuration directive for {title}\n# Ensure hardened settings are applied in your web server or DNS management panel."

    # 7. Best Practices
    if not finding.get("best_practices"):
        finding["best_practices"] = (
            "Enforce security at every layer (DNS records, SSL/TLS encryption, HTTP security headers, and software updates). "
            "Re-scan periodically to make sure new deployments stay secure."
        )

    # 8. Official Documentation
    if not finding.get("official_documentation"):
        refs = finding.get("references") or []
        if refs and len(refs) > 0:
            finding["official_documentation"] = refs[0]
        else:
            finding["official_documentation"] = "https://owasp.org/www-project-web-security-testing-guide/"

    return finding


def get_threat_intel(category: str, title: str) -> dict[str, Any]:
    """
    Returns OWASP Top 10 and MITRE ATT&CK mappings for a given finding.

    Args:
        category: The finding category (e.g. "Injection Prevention", "SSL/TLS")
        title:    The finding title (e.g. "Missing Content Security Policy")

    Returns:
        {
            "owasp": { id, title, description, reference },
            "mitre": { technique_id, technique_name, description, reference } | None
        }
    """
    cat_lower = (category or "").lower()
    title_lower = (title or "").lower()

    owasp_id = "A02"
    mitre_id: str | None = None

    for cat_kw, title_kw, owasp, mitre in _MAPPING_RULES:
        cat_match = (not cat_kw) or (cat_kw in cat_lower)
        title_match = (not title_kw) or (title_kw in title_lower)
        if cat_match and title_match:
            owasp_id = owasp
            mitre_id = mitre
            break

    return {
        "owasp": OWASP_TOP10.get(owasp_id, OWASP_TOP10["A02"]),
        "mitre": MITRE_TECHNIQUES.get(mitre_id) if mitre_id else None,
    }


def resolve_finding_location(finding: Any, scan_url: str = "") -> dict[str, str]:
    """
    Resolves the exact, accurate finding location from scanner data/evidence.
    Priority order:
    1. Exact evidence URL / endpoint returned by detector (e.g. https://example.com/phpinfo.php)
    2. Specific affected page/path
    3. Host:Port for TLS findings (e.g. example.com:443)
    4. Host/Domain for DNS/Email Security findings (e.g. example.com)
    5. Component/software for CVE/tech findings (e.g. example.com — Apache 2.4.49)
    6. 'Entire website / domain' ONLY when detector genuinely operates across domain.
    """
    import re
    from urllib.parse import urlparse

    cat = (getattr(finding, "category", None) or (finding.get("category", "") if isinstance(finding, dict) else "") or "").lower()
    title = (getattr(finding, "title", None) or (finding.get("title", "") if isinstance(finding, dict) else "") or "").lower()
    ep = getattr(finding, "endpoint", None) or (finding.get("endpoint", "") if isinstance(finding, dict) else "") or ""
    ev = getattr(finding, "evidence", None) or (finding.get("evidence", "") if isinstance(finding, dict) else "") or ""
    cve_id = getattr(finding, "cve_id", None) or (finding.get("cve_id", "") if isinstance(finding, dict) else "") or ""

    # Parse target domain from scan_url or endpoint or evidence
    target_str = scan_url or ep or ""
    hostname = ""
    if target_str:
        raw_u = target_str if target_str.startswith(("http://", "https://")) else f"https://{target_str}"
        try:
            p = urlparse(raw_u)
            hostname = (p.hostname or "").split(":")[0].lower()
        except Exception:
            pass

    # 1. Content Exposure Findings
    is_content_exposure = (
        "exposure" in cat or "source" in cat or "credential" in cat or
        "exposed" in title or "phpinfo" in title or "sensitive information in html" in title or
        "backup" in title or ".env" in title or "git" in title or "sitemap" in title or "admin panel" in title
    )
    if is_content_exposure:
        url_val = ""
        if ep and (ep.startswith("http://") or ep.startswith("https://")):
            url_val = ep
        elif ev:
            m = re.search(r'GET\s+(https?://\S+)', ev)
            if m:
                url_val = m.group(1).rstrip(").,")
        if not url_val and ep and ep.startswith("/"):
            base = f"https://{hostname}" if hostname else ""
            url_val = f"{base}{ep}"
        if not url_val and scan_url:
            url_val = scan_url

        if url_val:
            return {
                "label": "Exposed resource",
                "value": url_val,
                "type": "url",
                "badge": "Exposed File",
            }

    # 2. DNS & Email Security Findings (Domain-level by nature)
    is_dns = (
        "dns" in cat or "email" in cat or
        any(k in title for k in ("spf", "dmarc", "dkim", "mx record", "dnssec"))
    )
    if is_dns:
        domain_val = hostname or (urlparse(ep).hostname if ep.startswith("http") else ep) or "Target Domain"
        return {
            "label": "Domain",
            "value": domain_val,
            "type": "dns",
            "badge": "DNS Domain",
        }

    # 3. SSL / TLS Findings (Host:Port)
    is_ssl = (
        "ssl" in cat or "tls" in cat or
        any(k in title for k in ("certificate", "cipher", "tls version", "ssl/tls"))
    )
    if is_ssl:
        if ":443" in ep:
            host_val = ep
        elif hostname:
            host_val = f"{hostname}:443"
        elif ep:
            host_val = ep if ":" in ep else f"{ep}:443"
        else:
            host_val = "Target Host:443"

        return {
            "label": "Host",
            "value": host_val,
            "type": "host",
            "badge": "TLS Host",
        }

    # 4. CVE / Vulnerable Component Findings
    is_cve = "cve" in cat or bool(cve_id) or "cve-" in title
    if is_cve:
        comp = ""
        if " — " in title:
            comp = title.split(" — ")[0].strip()
        elif "detected " in ev.lower():
            m = re.search(r'detected\s+([^|,\n]+)', ev, re.IGNORECASE)
            if m:
                comp = m.group(1).strip()

        if comp and hostname:
            loc_val = f"{hostname} — {comp}"
        elif comp:
            loc_val = comp
        elif hostname:
            loc_val = f"{hostname} — {cve_id or 'Vulnerable Component'}"
        else:
            loc_val = ep or cve_id or "Software Component"

        return {
            "label": "Affected component",
            "value": loc_val,
            "type": "component",
            "badge": "Component",
        }

    # 5. HTTP Header / Cookie / Technology / General Web Findings
    if ep and (ep.startswith("http://") or ep.startswith("https://")):
        try:
            path = urlparse(ep).path
            is_specific_page = len(path) > 1 and path != "/"
        except Exception:
            is_specific_page = False
        return {
            "label": "Found on",
            "value": ep,
            "type": "url",
            "badge": "Specific Page" if is_specific_page else "Specific URL",
        }

    if scan_url and (scan_url.startswith("http://") or scan_url.startswith("https://")):
        try:
            path = urlparse(scan_url).path
            is_specific_page = len(path) > 1 and path != "/"
        except Exception:
            is_specific_page = False
        return {
            "label": "Found on",
            "value": scan_url,
            "type": "url",
            "badge": "Specific Page" if is_specific_page else "Specific URL",
        }

    if hostname:
        return {
            "label": "Domain",
            "value": hostname,
            "type": "domain",
            "badge": "Domain",
        }

    # 6. Fallback
    return {
        "label": "Scope",
        "value": "Entire website / domain",
        "type": "domain_scope",
        "badge": "Entire Domain",
    }


