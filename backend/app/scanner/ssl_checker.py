"""
SSL/TLS Certificate and Configuration Analyzer
===============================================
Performs a live TLS handshake to analyze the target's SSL/TLS configuration.

Standards reviewed
------------------
- RFC 5280  : Internet X.509 PKI Certificate and CRL Profile
- RFC 8446  : TLS 1.3 (The Transport Layer Security Protocol Version 1.3)
- RFC 8996  : Deprecating TLS 1.0 and 1.1
- RFC 9325  : Recommendations for Secure Use of TLS and DTLS
- NIST SP 800-52 Rev 2 : Guidelines for TLS Implementations
- CA/Browser Forum Baseline Requirements : Certificate Validity and Issuance
- Qualys SSL Labs Methodology : Grade criteria for A+ through F
- OWASP ASVS 9.2.x : Server communications security requirements

Grading methodology (aligned with Qualys SSL Labs)
---------------------------------------------------
A+  No findings of any severity (perfect configuration)
A   Only info/low findings (well configured)
B   At least one medium finding (acceptable with improvements needed)
C   At least one high finding (significant issues)
F   Critical finding (expired cert, SSL unavailable, self-signed)
"""
import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import Any
import logging

logger = logging.getLogger(__name__)


def _parse_cert_date(date_str: str) -> datetime:
    return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _check_ssl(hostname: str, port: int, resolved_ip: str | None = None) -> dict[str, Any]:
    """
    Synchronous SSL check — runs in a thread via asyncio.to_thread().
    Uses the default SSL context which validates the certificate chain
    against the system's trusted CA store.

    DNS-rebinding defence: when `resolved_ip` is provided (the public IP pinned
    by the validated scan target), the TCP connection is dialed against that
    literal and the hostname is only used for SNI/certificate validation — a
    rebinding DNS server cannot redirect the connect to an internal address.
    When omitted (callers without a validation pass, e.g. some re-probes) the
    hostname is dialed directly.
    """
    ctx = ssl.create_default_context()
    try:
        connect_host = resolved_ip or hostname
        with socket.create_connection((connect_host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()
                cipher = ssock.cipher()

                not_before = _parse_cert_date(cert.get("notBefore", ""))
                not_after = _parse_cert_date(cert.get("notAfter", ""))
                now = datetime.now(timezone.utc)
                days_remaining = (not_after - now).days

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san = [v for _, v in cert.get("subjectAltName", [])]

                issues = []

                # Certificate expiry
                if days_remaining < 0:
                    issues.append({"severity": "critical", "message": "Certificate has expired"})
                elif days_remaining < 14:
                    issues.append({"severity": "high", "message": f"Certificate expires in {days_remaining} day(s) — immediate renewal required"})
                elif days_remaining < 30:
                    issues.append({"severity": "medium", "message": f"Certificate expires in {days_remaining} days — renewal recommended"})

                # Weak TLS version (SSLv3, TLSv1.0, TLSv1.1)
                # Note: ctx.create_default_context() already rejects SSLv2/SSLv3 connections,
                # but we check the negotiated version to flag TLSv1.0 and TLSv1.1.
                if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    issues.append({"severity": "high", "message": f"Deprecated TLS version negotiated: {tls_version} — upgrade to TLS 1.2 or 1.3"})

                # Weak cipher suite
                cipher_name = cipher[0] if cipher else ""
                WEAK_CIPHER_PATTERNS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "MD5")
                if any(pattern in cipher_name.upper() for pattern in WEAK_CIPHER_PATTERNS):
                    issues.append({"severity": "high", "message": f"Weak cipher suite negotiated: {cipher_name}"})

                # Derive SSL grade from findings (aligned with Qualys SSL Labs methodology)
                # Grades: A+, A, A-, B, C, D, E, F  — there is no B+ in SSL Labs.
                severities = {i["severity"] for i in issues}
                if "critical" in severities:
                    grade = "F"
                elif "high" in severities:
                    grade = "C"
                elif "medium" in severities:
                    grade = "B"
                elif "low" in severities:
                    grade = "A"   # Well configured; minor informational notes only
                elif issues:  # info only
                    grade = "A"
                else:
                    grade = "A+"

                return {
                    "supported": True,
                    "certificate": {
                        "subject": subject.get("commonName", ""),
                        "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_remaining": days_remaining,
                        "san": san[:10],
                        "serial_number": cert.get("serialNumber", ""),
                        "version": cert.get("version", ""),
                    },
                    "tls_version": tls_version,
                    "cipher": {
                        "name": cipher_name,
                        "protocol": cipher[1] if cipher else "",
                        "bits": cipher[2] if cipher else 0,
                    },
                    "issues": issues,
                    "grade": grade,
                }
    except ssl.SSLCertVerificationError as e:
        return {
            "supported": True, "certificate": {}, "tls_version": None, "cipher": None, "grade": "F",
            "issues": [{"severity": "critical", "message": f"Certificate verification failed: {str(e)}"}],
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {
            "supported": False, "certificate": {}, "tls_version": None, "cipher": None, "grade": "N/A",
            "issues": [{"severity": "info", "message": "HTTPS not available on port 443"}],
        }


async def analyze_ssl(hostname: str, port: int = 443, resolved_ip: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "supported": False,
        "certificate": {},
        "tls_version": None,
        "cipher": None,
        "issues": [],
        "grade": "F",
    }
    try:
        # asyncio.to_thread() is the modern, non-deprecated approach (Python 3.9+)
        # to run blocking synchronous code from an async context.
        data = await asyncio.to_thread(_check_ssl, hostname, port, resolved_ip)
        result.update(data)
    except Exception as e:
        logger.error(f"SSL check error for {hostname}: {e}")
        result["issues"].append({"severity": "info", "message": f"SSL check error: {str(e)}"})

    return result
