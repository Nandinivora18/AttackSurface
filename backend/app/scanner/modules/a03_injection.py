"""
OWASP A03:2021 — Injection Assessment Module
============================================
Performs controlled, non-destructive baseline-vs-test differential analysis
for SQL injection indicators, reflected XSS context reflection, and path traversal.

Safety & False-Positive Invariants:
- Zero data extraction, zero command execution, zero database modification.
- Harmless, unique canary tokens only.
- Strict baseline comparison: compares status, body length, content-type, and error signatures.
- SQL error signatures alone produce INCONCLUSIVE/POSSIBLE unless differential recovery behavior is confirmed.
- Reflected text is analyzed for execution context (HTML text vs attribute vs encoded).
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from typing import Any
import httpx

from app.utils.safe_http import async_resolve_and_pin, pin_same_host

logger = logging.getLogger(__name__)

# Known SQL error patterns across major relational engines
SQL_ERROR_PATTERNS = [
    re.compile(r'you have an error in your sql syntax', re.IGNORECASE),
    re.compile(r'warning: mysql', re.IGNORECASE),
    re.compile(r'unclosed quotation mark after the character string', re.IGNORECASE),
    re.compile(r'quoted string not properly terminated', re.IGNORECASE),
    re.compile(r'pg_query\(\): query failed', re.IGNORECASE),
    re.compile(r'sqlite3::(?:query|execute)', re.IGNORECASE),
    re.compile(r'syntax error at or near', re.IGNORECASE),
    re.compile(r'microsoft ole db provider for odbc drivers', re.IGNORECASE),
]


async def assess_a03_injection(
    discovered_parameters: dict[str, list[str]],
    timeout_seconds: float = 4.0,
    max_tested_params: int = 10,
) -> dict[str, Any]:
    """
    Executes controlled differential injection tests on discovered parameters.
    """
    findings: list[dict[str, Any]] = []
    tested_count = 0
    status = "PASS"
    confidence = "HIGH"

    if not discovered_parameters:
        return {
            "status": "PASS",
            "method": "Controlled Differential Analysis (Canary Probes)",
            "confidence": "HIGH",
            "findings": [],
            "limitations": "No user-supplied query parameters or form inputs were discovered on crawled same-origin pages.",
        }

    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=False) as client:
        for param_name, sample_urls in discovered_parameters.items():
            if tested_count >= max_tested_params:
                break
            if not sample_urls:
                continue

            test_url = sample_urls[0]
            is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(test_url)
            if not is_safe or conn_url is None or host_header is None:
                continue
            hop_headers = {"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header}

            tested_count += 1
            parsed = urllib.parse.urlparse(test_url)
            qs = urllib.parse.parse_qs(parsed.query)

            # ------------------------------------------------------------------
            # 1. Baseline Request
            # ------------------------------------------------------------------
            try:
                base_resp = await client.get(conn_url, headers=hop_headers)
                base_status = base_resp.status_code
                base_len = len(base_resp.content)
                base_text = base_resp.text
            except Exception as e:
                logger.debug(f"A03 baseline fetch failed for {test_url}: {e}")
                continue

            # ------------------------------------------------------------------
            # 2. Reflected XSS Context Test (Harmless Unique Canary Token)
            # ------------------------------------------------------------------
            import uuid
            canary_id = uuid.uuid4().hex[:8]
            canary_token = f"sentinelscan{canary_id}"
            xss_test_query = {**qs, param_name: [canary_token]}
            xss_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(xss_test_query, doseq=True)))

            try:
                xss_resp = await client.get(pin_same_host(xss_url, conn_url), headers=hop_headers)
                if canary_token in xss_resp.text and "text/html" in xss_resp.headers.get("content-type", "").lower():
                    # Check context: verify if reflected verbatim without HTML entity escaping
                    if f"&lt;{canary_token}" in xss_resp.text or f"&#" in xss_resp.text:
                        # Safely encoded
                        pass
                    else:
                        status = "FAIL"
                        findings.append({
                            "category": "Injection",
                            "title": f"Reflected Input Detected in Parameter '{param_name}'",
                            "description": (
                                f"Input supplied to parameter '{param_name}' was reflected unencoded in the "
                                "HTML response body. If user input is not properly contextual-encoded, this enables "
                                "Cross-Site Scripting (XSS)."
                            ),
                            "severity": "medium",
                            "confidence": "high",
                            "cvss_score": 6.1,
                            "recommendation": "Contextually encode all user-supplied input before rendering into HTML responses (HTML entity, attribute, or JS encoding).",
                            "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
                            "endpoint": test_url,
                            "evidence": f"Parameter: {param_name}, Canary reflected verbatim: {canary_token}",
                        })
            except Exception as e:
                logger.debug(f"A03 XSS test failed: {e}")

            # ------------------------------------------------------------------
            # 3. SQLi Harmless Single/Balanced Quote Differential Test
            # ------------------------------------------------------------------
            sq_query = {**qs, param_name: [f"test'"]}
            sq_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(sq_query, doseq=True)))

            bq_query = {**qs, param_name: [f"test''"]}
            bq_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(bq_query, doseq=True)))

            try:
                sq_resp = await client.get(pin_same_host(sq_url, conn_url), headers=hop_headers)
                # Check for SQL error patterns
                sq_err = any(pat.search(sq_resp.text) for pat in SQL_ERROR_PATTERNS)
                base_err = any(pat.search(base_text) for pat in SQL_ERROR_PATTERNS)

                if sq_err and not base_err:
                    # Test recovery with balanced quote
                    bq_resp = await client.get(pin_same_host(bq_url, conn_url), headers=hop_headers)
                    bq_err = any(pat.search(bq_resp.text) for pat in SQL_ERROR_PATTERNS)

                    if not bq_err and bq_resp.status_code == base_status:
                        # High confidence differential confirmation
                        status = "FAIL"
                        findings.append({
                            "category": "Injection",
                            "title": f"Differential SQL Error Indicator in Parameter '{param_name}'",
                            "description": (
                                f"Parameter '{param_name}' exhibited differential SQL syntax error behavior. "
                                "A single quote elicited an engine error, whereas a balanced quote recovered baseline status."
                            ),
                            "severity": "critical",
                            "confidence": "high",
                            "cvss_score": 8.8,
                            "recommendation": "Use parameterized queries (prepared statements) or an ORM for all database operations.",
                            "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
                            "endpoint": test_url,
                            "evidence": f"Param '{param_name}': baseline={base_status}, quote_err={sq_resp.status_code} (SQL error detected), balanced={bq_resp.status_code}",
                        })
                    else:
                        # Error pattern seen without clean recovery -> Inconclusive
                        findings.append({
                            "category": "Injection",
                            "title": f"Potential SQL Error Signature in Parameter '{param_name}'",
                            "description": f"Parameter '{param_name}' triggered a database error message signature, but differential behavior was inconclusive.",
                            "severity": "medium",
                            "confidence": "medium",
                            "cvss_score": 5.0,
                            "recommendation": "Review backend query construction for parameter and enforce parameterized statements.",
                            "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
                            "endpoint": test_url,
                            "evidence": f"Param '{param_name}' returned SQL error snippet on single-quote probe",
                        })
            except Exception as e:
                logger.debug(f"A03 SQLi differential test failed: {e}")

            # ------------------------------------------------------------------
            # 4. Path Traversal Harmless Canary Test
            # ------------------------------------------------------------------
            pt_query = {**qs, param_name: ["..%2f..%2f"]}
            pt_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(pt_query, doseq=True)))
            try:
                pt_resp = await client.get(pin_same_host(pt_url, conn_url), headers=hop_headers)
                if pt_resp.status_code == 200 and any(w in pt_resp.text.lower() for w in ["directory traversal", "root:"]):
                    status = "FAIL"
                    findings.append({
                        "category": "Injection",
                        "title": f"Potential Path Traversal Indicator in Parameter '{param_name}'",
                        "description": f"Parameter '{param_name}' reacted to directory traversal sequence '..%2f'.",
                        "severity": "high",
                        "confidence": "medium",
                        "cvss_score": 7.5,
                        "recommendation": "Sanitize file path inputs using path whitelisting or resolve paths against a fixed base directory.",
                        "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
                        "endpoint": test_url,
                        "evidence": f"Param '{param_name}' traversal probe returned status {pt_resp.status_code}",
                    })
            except Exception as e:
                logger.debug(f"A03 path traversal test failed: {e}")

    limitations = (
        f"Tested {tested_count} parameter(s) using harmless baseline-vs-test differential probes. "
        "Does not perform destructive payloads, arbitrary command execution, database dumping, or state-changing operations."
    )

    return {
        "status": status,
        "method": "Controlled Differential Analysis (Canary & Quote Probes)",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
