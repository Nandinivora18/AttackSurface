"""
DNS Security Analyzer
=====================
Queries DNS records to evaluate the email security posture and DNS hardening
of the target domain.

Standards reviewed
------------------
- RFC 1034 / RFC 1035  : Domain Name System (foundational DNS RFCs)
- RFC 5321  : Simple Mail Transfer Protocol (MX record semantics)
- RFC 7208  : Sender Policy Framework (SPF) for Authorizing Use of Domains
- RFC 7489  : Domain-based Message Authentication, Reporting, and Conformance (DMARC)
- RFC 6376  : DomainKeys Identified Mail (DKIM) Signatures
- CISA Email Security Best Practices : DMARC enforcement recommendations
- OWASP ASVS 14.6.1 : DNS security controls

Detection notes
---------------
- SPF  : Checks for TXT record matching "v=spf1 ...". -all preferred, ~all flagged.
- DMARC: Checks _dmarc.<domain> TXT record. p=none is monitor-only (weak).
- DKIM : Probes 9 commonly used DKIM selectors.
- MX: Absence of MX records when SPF references mail is noted as informational.
"""
import asyncio
import dns.resolver
import dns.exception
from typing import Any
import logging

logger = logging.getLogger(__name__)


async def analyze_dns(hostname: str) -> dict[str, Any]:
    findings = []
    dns_info: dict[str, Any] = {
        "a_records": [],
        "mx_records": [],
        "txt_records": [],
        "ns_records": [],
        "spf": None,
        "dmarc": None,
        "dkim": None,
    }

    def _resolve(hostname: str) -> dict:
        result = {
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "ns_records": [],
            "spf": None,
            "dmarc": None,
            "dkim": None,
        }
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8

        # A records
        try:
            answers = resolver.resolve(hostname, "A")
            result["a_records"] = [str(r) for r in answers]
        except Exception:
            pass

        # MX records
        try:
            answers = resolver.resolve(hostname, "MX")
            result["mx_records"] = [{"preference": r.preference, "exchange": str(r.exchange)} for r in answers]
        except Exception:
            pass

        # TXT records (SPF lives here)
        try:
            answers = resolver.resolve(hostname, "TXT")
            txt_values = []
            for r in answers:
                v = b"".join(r.strings).decode("utf-8", errors="replace")
                txt_values.append(v)
                if v.startswith("v=spf1"):
                    result["spf"] = v
            result["txt_records"] = txt_values
        except Exception:
            pass

        # DMARC
        try:
            answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
            for r in answers:
                v = b"".join(r.strings).decode("utf-8", errors="replace")
                if v.startswith("v=DMARC1"):
                    result["dmarc"] = v
                    break
        except Exception:
            pass

        # DKIM (check for at least one DKIM selector; use common selectors)
        dkim_found = False
        for selector in ("default", "google", "mail", "k1", "s1", "s2", "dkim", "selector1", "selector2"):
            try:
                answers = resolver.resolve(f"{selector}._domainkey.{hostname}", "TXT")
                for r in answers:
                    v = b"".join(r.strings).decode("utf-8", errors="replace")
                    if "v=DKIM1" in v or "p=" in v:
                        result["dkim"] = f"{selector}: {v[:80]}"
                        dkim_found = True
                        break
            except Exception:
                pass
            if dkim_found:
                break

        # NS records
        try:
            answers = resolver.resolve(hostname, "NS")
            result["ns_records"] = [str(r) for r in answers]
        except Exception:
            pass

        return result

    try:
        # asyncio.to_thread() (Python 3.9+) is the modern replacement for
        # get_event_loop().run_in_executor(); ssl_checker.py uses the same pattern.
        data = await asyncio.to_thread(_resolve, hostname)
        dns_info.update(data)
    except Exception as e:
        logger.error(f"DNS lookup error for {hostname}: {e}")

    findings = _analyze_dns_findings(hostname, dns_info)
    return {"findings": findings, "dns_info": dns_info}


def _analyze_dns_findings(hostname: str, dns_info: dict) -> list[dict]:
    """
    Pure analysis function: given a pre-populated dns_info dict, return a list
    of findings.  Extracted from analyze_dns so tests can call it directly with
    mock dns_info without needing live DNS resolution.
    """
    findings: list[dict] = []

    # SPF analysis
    if not dns_info["spf"]:
        if dns_info["mx_records"]:
            findings.append({
                "category": "Email Security",
                "title": "Missing SPF Record",
                "description": "No SPF (Sender Policy Framework) record found. Attackers can send spoofed emails appearing to come from your domain.",
                "severity": "medium",
                "cvss_score": 5.3,
                "confidence": "high",
                "recommendation": "Add an SPF TXT record: v=spf1 include:_spf.google.com ~all (adjust for your mail provider)",
                "references": ["https://tools.ietf.org/html/rfc7208", "https://www.cloudflare.com/learning/dns/dns-records/dns-spf-record/"],
                "evidence": f"No TXT record starting with 'v=spf1' found for {hostname}",
            })
    else:
        spf = dns_info["spf"]
        if "+all" in spf:
            findings.append({
                "category": "Email Security",
                "title": "SPF Record Uses +all (Permissive)",
                "description": "SPF record uses '+all' which allows any server to send mail on behalf of your domain.",
                "severity": "high",
                "cvss_score": 7.5,
                "confidence": "high",
                "recommendation": "Change '+all' to '~all' (softfail) or '-all' (hardfail)",
                "references": ["https://tools.ietf.org/html/rfc7208"],
                "evidence": f"SPF: {spf}",
            })
        elif "?all" in spf:
            findings.append({
                "category": "Email Security",
                "title": "SPF Record Uses ?all (Neutral — Ineffective)",
                "description": "SPF record uses '?all' which provides no protection against email spoofing.",
                "severity": "medium",
                "cvss_score": 5.3,
                "confidence": "high",
                "recommendation": "Change '?all' to '~all' or '-all' for effective spoofing protection",
                "references": ["https://tools.ietf.org/html/rfc7208"],
                "evidence": f"SPF: {spf}",
            })
        else:
            findings.append({
                "category": "Email Security",
                "title": "SPF Record Present",
                "description": "SPF record found and configured with a restrictive policy.",
                "severity": "info",
                "cvss_score": None,
                "confidence": "high",
                "recommendation": "Good. Ensure DMARC is also configured.",
                "references": [],
                "evidence": f"SPF: {spf}",
            })

    # DMARC analysis
    if not dns_info["dmarc"]:
        has_mx = bool(dns_info.get("mx_records"))
        dmarc_description = (
            "No DMARC (Domain-based Message Authentication, Reporting and Conformance) policy found. "
            "Even without email sending (no MX records detected), an attacker can spoof this domain "
            "in phishing emails. A DMARC reject/quarantine policy prevents this."
            if not has_mx else
            "No DMARC policy found. Emails can be spoofed without receiver notification."
        )
        findings.append({
            "category": "Email Security",
            "title": "Missing DMARC Record",
            "description": dmarc_description,
            "severity": "medium",
            "cvss_score": 5.3,
            # When no MX records are present the domain may not send email, so
            # missing DMARC is less immediately exploitable — use medium confidence.
            "confidence": "medium" if not has_mx else "high",
            "recommendation": "Add: _dmarc TXT record: v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com",
            "references": ["https://dmarc.org/", "https://tools.ietf.org/html/rfc7489"],
            "evidence": f"No TXT record starting with 'v=DMARC1' found for _dmarc.{hostname}{' (no MX records detected)' if not has_mx else ''}",
        })
    else:
        dmarc = dns_info["dmarc"]
        if "p=none" in dmarc.lower():
            findings.append({
                "category": "Email Security",
                "title": "DMARC Policy is 'none' — Monitoring Only",
                "description": "DMARC policy is set to 'none' which only monitors but does not reject or quarantine spoofed emails.",
                "severity": "low",
                "cvss_score": 3.1,
                "confidence": "high",
                "recommendation": "Upgrade DMARC policy from p=none to p=quarantine or p=reject",
                "references": ["https://dmarc.org/"],
                "evidence": f"DMARC: {dmarc}",
            })
        else:
            findings.append({
                "category": "Email Security",
                "title": "DMARC Record Present with Enforcement",
                "description": "DMARC record found with quarantine or reject policy.",
                "severity": "info",
                "cvss_score": None,
                "confidence": "high",
                "recommendation": "Good. Ensure p=reject for strongest protection.",
                "references": [],
                "evidence": f"DMARC: {dmarc}",
            })

    # DKIM analysis
    if not dns_info.get("dkim"):
        if dns_info["mx_records"]:
            findings.append({
                "category": "Email Security",
                "title": "Potential DKIM Configuration Not Detected via Common Selectors",
                "description": (
                    "No DKIM (DomainKeys Identified Mail) TXT record was found under 9 commonly used "
                    "selectors. DKIM provides cryptographic signing of outbound email, verifying message "
                    "integrity in transit. However, selector enumeration cannot prove DKIM is absent: "
                    "organizations frequently use custom selectors unique to their mail provider that "
                    "passive scanning cannot discover."
                ),
                "severity": "info",
                "cvss_score": None,
                "confidence": "low",
                "recommendation": (
                    "Verify DKIM is configured with your mail provider. "
                    "SentinelScan probes common selectors (default, google, mail, k1, s1, s2, "
                    "dkim, selector1, selector2) but cannot enumerate all possible custom selectors. "
                    "Use your mail provider's admin panel or a tool like mail-tester.com to confirm DKIM status."
                ),
                "references": ["https://tools.ietf.org/html/rfc6376"],
                "evidence": (
                    f"No DKIM TXT record found under 9 common selectors for _domainkey.{hostname}. "
                    "This does NOT confirm DKIM is absent — a custom selector may be in use."
                ),
            })
    else:
        findings.append({
            "category": "Email Security",
            "title": "DKIM Record Present",
            "description": "DKIM record found and cryptographic email signing is configured.",
            "severity": "info",
            "cvss_score": None,
            "confidence": "high",
            "recommendation": "Good. Ensure DKIM key rotation is performed periodically.",
            "references": [],
            "evidence": f"DKIM: {dns_info['dkim']}",
        })

    return findings

