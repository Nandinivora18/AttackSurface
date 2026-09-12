"""
OWASP A04:2021 — Insecure Design Assessment Module
==================================================
Evaluates security design posture through evidence-assisted analysis of design questionnaires
and optional OpenAPI/Swagger specification definitions.

Design Principle:
Insecure Design (threat modeling flaws, trust boundary violations, business logic architecture)
cannot be reliably confirmed solely through external black-box HTTP probing.
When architectural design evidence or OpenAPI definitions are not supplied, the category
honestly reports INSUFFICIENT_DESIGN_EVIDENCE / NOT_VERIFIABLE rather than an unfounded PASS.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


async def assess_a04_insecure_design(
    design_questionnaire: dict[str, Any] | None = None,
    openapi_spec: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Executes A04 Insecure Design assessment based on supplied design evidence.
    """
    findings: list[dict[str, Any]] = []
    has_evidence = False

    # 1. Evaluate Security Design Questionnaire (if provided)
    if design_questionnaire and isinstance(design_questionnaire, dict):
        has_evidence = True
        
        # Check Threat Modeling
        if not design_questionnaire.get("threat_modeling_conducted", False):
            findings.append({
                "category": "Insecure Design",
                "title": "Threat Modeling Not Formally Conducted",
                "description": (
                    "Security questionnaire indicates threat modeling was not performed during system design. "
                    "Architectural flaws and business logic attack paths may remain unmitigated."
                ),
                "severity": "medium",
                "confidence": "high",
                "cvss_score": None,
                "recommendation": "Incorporate STRIDE or similar threat modeling methodology into the SDLC design phase.",
                "references": ["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
                "endpoint": "Architecture / Design Review",
                "evidence": "Questionnaire response: threat_modeling_conducted = false",
            })

        # Check Rate Limiting Policy Design
        if not design_questionnaire.get("rate_limiting_designed", True):
            findings.append({
                "category": "Insecure Design",
                "title": "Absence of Architectural Rate-Limiting Controls",
                "description": (
                    "Security questionnaire indicates rate limiting or resource consumption bounds were not "
                    "designed into API boundaries, exposing services to denial-of-service and credential stuffing."
                ),
                "severity": "medium",
                "confidence": "high",
                "cvss_score": 5.3,
                "recommendation": "Implement token-bucket or sliding-window rate limiters at API gateway layers.",
                "references": ["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
                "endpoint": "Architecture / Design Review",
                "evidence": "Questionnaire response: rate_limiting_designed = false",
            })

        # Check Trust Boundaries
        if not design_questionnaire.get("trust_boundaries_defined", True):
            findings.append({
                "category": "Insecure Design",
                "title": "Undefined Trust Boundaries",
                "description": (
                    "Questionnaire indicates system components operate without explicit trust boundaries, "
                    "increasing risk of internal lateral movement."
                ),
                "severity": "low",
                "confidence": "high",
                "cvss_score": None,
                "recommendation": "Explicitly document trust boundaries between frontend, API gateway, microservices, and databases.",
                "references": ["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
                "endpoint": "Architecture / Design Review",
                "evidence": "Questionnaire response: trust_boundaries_defined = false",
            })

    # 2. Evaluate OpenAPI Specification (if provided)
    if openapi_spec and isinstance(openapi_spec, dict):
        has_evidence = True
        paths = openapi_spec.get("paths", {})
        components = openapi_spec.get("components", {})
        security_schemes = components.get("securitySchemes", {}) or openapi_spec.get("securityDefinitions", {})

        if not security_schemes:
            findings.append({
                "category": "Insecure Design",
                "title": "OpenAPI Definition Lacks Security Schemes",
                "description": (
                    "The provided OpenAPI/Swagger specification does not declare any security schemes "
                    "(OAuth2, Bearer tokens, API keys) in its components. Note: this reflects specification "
                    "completeness and indicates endpoints may lack documented access control."
                ),
                "severity": "low",
                "confidence": "medium",
                "cvss_score": None,
                "recommendation": "Define authentication schemes in the OpenAPI components and declare security requirements for protected routes.",
                "references": ["https://swagger.io/docs/specification/authentication/"],
                "endpoint": "OpenAPI Specification",
                "evidence": f"Specification declares {len(paths)} paths but 0 securitySchemes.",
            })
        else:
            # Inspect endpoints for missing security requirements
            unsecured_endpoints = []
            sensitive_verbs = {"post", "put", "delete", "patch"}
            for path_str, path_item in paths.items():
                if not isinstance(path_item, dict):
                    continue
                for method, op in path_item.items():
                    if method.lower() in sensitive_verbs and isinstance(op, dict):
                        op_sec = op.get("security")
                        global_sec = openapi_spec.get("security")
                        if op_sec is None and not global_sec:
                            unsecured_endpoints.append(f"{method.upper()} {path_str}")

            if unsecured_endpoints:
                findings.append({
                    "category": "Insecure Design",
                    "title": f"Potentially Unsecured State-Changing Endpoints in OpenAPI: {len(unsecured_endpoints)} found",
                    "description": (
                        f"Found {len(unsecured_endpoints)} mutating operations (POST/PUT/DELETE) without explicit "
                        "security requirements declared in OpenAPI. These endpoints may lack authentication if not protected by a gateway."
                    ),
                    "severity": "medium",
                    "confidence": "medium",
                    "cvss_score": 4.3,
                    "recommendation": "Enforce explicit authentication on all state-changing endpoints in API specifications.",
                    "references": ["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
                    "endpoint": unsecured_endpoints[0] if unsecured_endpoints else "API Routes",
                    "evidence": f"Unsecured routes: {', '.join(unsecured_endpoints[:5])}",
                })

    # Determine status and limitations
    if not has_evidence:
        status = "NOT_VERIFIABLE"
        confidence = "LOW"
        limitations = (
            "A04 Insecure Design cannot be proven solely from external HTTP observation. "
            "No design questionnaire or OpenAPI schema was supplied for architectural evaluation. "
            "Marked as NOT_VERIFIABLE to avoid false confidence."
        )
    elif findings:
        status = "FAIL"
        confidence = "HIGH" if design_questionnaire else "MEDIUM"
        limitations = "Evaluated based on supplied security design questionnaire responses and/or OpenAPI schema definitions."
    else:
        status = "PASS"
        confidence = "HIGH" if design_questionnaire else "MEDIUM"
        limitations = "Supplied design questionnaire and/or OpenAPI definitions satisfy baseline security architecture criteria."

    return {
        "status": status,
        "method": "Design Questionnaire & OpenAPI Specification Security Evaluation",
        "confidence": confidence,
        "findings": findings,
        "limitations": limitations,
    }
