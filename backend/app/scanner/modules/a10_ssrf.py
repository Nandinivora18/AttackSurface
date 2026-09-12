"""
[DEPRECATED] OWASP Top 10:2021 — Legacy Parameter Surface Evaluation
=====================================================================
HISTORICAL / DEPRECATED: Retained strictly for backward compatibility with
test_controlled_evaluation. In OWASP Top 10:2025, A10 is strictly "Mishandling of
Exceptional Conditions" (implemented in a10_exceptional_conditions.py). Candidate
URL parameter surfaces are evaluated as access-control/network-boundary indicators
under A01:2025 (Broken Access Control).

Safety Invariants:
- ZERO active outbound callbacks (no OAST infrastructure).
- ZERO probing of internal IP addresses (127.0.0.1, 169.254.169.254, RFC1918 subnets).
- Server-side request execution is strictly NOT_VERIFIABLE without external verification.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

URL_PARAMETER_NAMES = {
    "url", "dest", "destination", "redirect", "redirect_url", "uri",
    "target", "link", "src", "source", "webhook", "feed", "site",
    "callback", "path", "domain", "fetch",
}


async def assess_a10_ssrf(
    scan_id: str,
    discovered_parameters: dict[str, list[str]],
    *args: Any,
    **kwargs: Any,
) -> dict[str, Any]:
    """
    Executes A10 SSRF attack surface evaluation.
    Analyzes crawled parameter names to identify candidate URL-accepting inputs.
    """
    candidate_params: list[tuple[str, str]] = []
    for param_name, endpoints in discovered_parameters.items():
        if param_name.lower() in URL_PARAMETER_NAMES:
            for ep in endpoints:
                candidate_params.append((param_name, ep))

    if not candidate_params:
        return {
            "status": "PASS",
            "method": "URL Parameter & Redirection Surface Analysis",
            "confidence": "HIGH",
            "findings": [],
            "limitations": "No URL-accepting or redirection parameters were discovered on crawled endpoints.",
        }

    unique_param_names = sorted({p for p, _ in candidate_params})
    preview_params = ", ".join(unique_param_names[:5])
    limitations = (
        f"Identified {len(candidate_params)} URL-accepting or redirection parameter instance(s) "
        f"across crawled endpoints (parameters: {preview_params}). "
        "Server-side outbound egress and internal network reachability cannot be safely verified "
        "via external passive scanning without internal telemetry. "
        "Marked as NOT_VERIFIABLE to avoid false confidence."
    )

    return {
        "status": "NOT_VERIFIABLE",
        "method": "URL Parameter & Redirection Surface Analysis",
        "confidence": "LOW",
        "findings": [],
        "limitations": limitations,
    }
