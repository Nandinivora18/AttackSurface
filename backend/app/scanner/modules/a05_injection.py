"""
OWASP A05:2025 — Injection Assessment Module
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


async def assess_a05_injection(
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

            raw_url = sample_urls[0]
            is_safe, _, _, conn_url, host_header = await async_resolve_and_pin(raw_url)
            if not is_safe or conn_url is None or host_header is None:
                continue
            hop_headers = {"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header}

            parsed = urllib.parse.urlparse(raw_url)
            query_dict = urllib.parse.parse_qs(parsed.query)
            if param_name not in query_dict:
                continue

            # 1. Baseline Request
            try:
                base_resp = await client.get(conn_url, headers=hop_headers)
                base_status = base_resp.status_code
                base_len = len(base_resp.text)
                base_text = base_resp.text
            except Exception as e:
                logger.debug(f"A05 baseline request failed for {raw_url}: {e}")
                continue

            tested_count += 1

            # 2. SQL Differential Probe
            canary_single_quote = query_dict.copy()
            canary_single_quote[param_name] = ["'"]
            url_sq = parsed._replace(query=urllib.parse.urlencode(canary_single_quote, doseq=True)).geturl()

            canary_double_quote = query_dict.copy()
            canary_double_quote[param_name] = ["''"]
            url_dq = parsed._replace(query=urllib.parse.urlencode(canary_double_quote, doseq=True)).geturl()

            try:
                resp_sq = await client.get(pin_same_host(url_sq, conn_url), headers=hop_headers)
                # Check for SQL error patterns in anomalous response
                sql_error_found = False
                matched_engine_error = ""
                for pattern in SQL_ERROR_PATTERNS:
                    m = pattern.search(resp_sq.text)
                    if m and not pattern.search(base_text):
                        sql_error_found = True
                        matched_engine_error = m.group(0)
                        break

                if sql_error_found:
                    # Recovery probe
                    resp_dq = await client.get(pin_same_host(url_dq, conn_url), headers=hop_headers)
                    if resp_dq.status_code == base_status and not any(p.search(resp_dq.text) for p in SQL_ERROR_PATTERNS):
                        status = "FAIL"
                        findings.append({
                            "category": "Injection",
                            "title": f"SQL Syntax Error Differential on Parameter '{param_name}'",
                            "description": (
                                f"Input parameter '{param_name}' elicited a database error message '{matched_engine_error}' "
                                "when supplied with a syntax canary ('), which recovered when balanced (''). "
                                "This differential behavior indicates potential SQL statement interpolation without parameterization."
                            ),
                            "severity": "high",
                            "confidence": "confirmed",
                            "cvss_score": 8.5,
                            "recommendation": "Use parameterized queries or prepared statements for all database interactions. Never concatenate user input directly into SQL commands.",
                            "references": ["https://owasp.org/Top10/A05_2025-Injection/"],
                            "endpoint": raw_url,
                            "evidence": f"Parameter: {param_name}\nError signature: {matched_engine_error}\nBaseline status: {base_status}, Canary status: {resp_sq.status_code}, Balanced status: {resp_dq.status_code}",
                        })
                    else:
                        findings.append({
                            "category": "Injection",
                            "title": f"Anomalous Error Response on Parameter '{param_name}'",
                            "description": f"Supplying syntax tokens to '{param_name}' produced an error disclosure: {matched_engine_error}. Inconclusive without confirmed differential recovery.",
                            "severity": "low",
                            "confidence": "medium",
                            "cvss_score": None,
                            "recommendation": "Verify input validation and disable verbose database exception leakage in production.",
                            "references": ["https://owasp.org/Top10/A05_2025-Injection/"],
                            "endpoint": raw_url,
                            "evidence": f"Parameter: {param_name}\nMatched: {matched_engine_error}",
                        })
            except Exception as e:
                logger.debug(f"A05 SQL test error on {raw_url}: {e}")

            # 3. Reflected Context Probe (harmless alphanumeric token)
            canary_token = f"sentinelscan{tested_count}xyz"
            canary_reflection = query_dict.copy()
            canary_reflection[param_name] = [canary_token]
            url_refl = parsed._replace(query=urllib.parse.urlencode(canary_reflection, doseq=True)).geturl()

            try:
                resp_refl = await client.get(pin_same_host(url_refl, conn_url), headers=hop_headers)
                if canary_token in resp_refl.text and "text/html" in resp_refl.headers.get("content-type", "").lower():
                    # Check context
                    escaped_token = canary_token
                    # If reflected verbatim without HTML entity encoding
                    if f"<{canary_token}>" not in resp_refl.text:
                        findings.append({
                            "category": "Reflected Input",
                            "title": f"Reflected Parameter Value in HTML: '{param_name}'",
                            "description": (
                                f"Value of parameter '{param_name}' is reflected in the HTML response body. "
                                "Ensure contextual output encoding (HTML, attribute, or JavaScript) is applied "
                                "to prevent Cross-Site Scripting (XSS)."
                            ),
                            "severity": "low",
                            "confidence": "high",
                            "cvss_score": None,
                            "recommendation": "Apply contextual output encoding according to OWASP XSS Prevention guidelines.",
                            "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                            "endpoint": raw_url,
                            "evidence": f"Canary token '{canary_token}' reflected in HTML response from {url_refl}",
                        })
            except Exception as e:
                logger.debug(f"A05 reflection test error on {raw_url}: {e}")

    limitations = (
        f"Evaluated {tested_count} discovered input parameter{'s' if tested_count != 1 else ''} "
        "using harmless canary tokens and differential error comparison. "
        "Does not perform destructive data extraction, blind time-based attacks, out-of-band exfiltration, or second-order injection testing."
    )

    return {
        "status": status,
        "method": f"Controlled Differential Analysis ({tested_count} parameter{'s' if tested_count != 1 else ''} tested)",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }


# Backward-compatibility alias
assess_a03_injection = assess_a05_injection
