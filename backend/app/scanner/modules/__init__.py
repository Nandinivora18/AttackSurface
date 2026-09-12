"""
OWASP Top 10:2025 Assessment Modules Package for SentinelScan
=============================================================
Controlled, non-destructive assessment mechanisms for all 10 OWASP Top 10:2025 categories:
- A01:2025 — Broken Access Control
- A02:2025 — Security Misconfiguration
- A03:2025 — Software Supply Chain Failures
- A04:2025 — Cryptographic Failures
- A05:2025 — Injection
- A06:2025 — Insecure Design
- A07:2025 — Authentication Failures
- A08:2025 — Software or Data Integrity Failures
- A09:2025 — Security Logging and Alerting Failures
- A10:2025 — Mishandling of Exceptional Conditions
"""
from app.scanner.modules.a01_access_control import assess_a01_access_control
from app.scanner.modules.a02_misconfiguration import assess_a02_misconfiguration
from app.scanner.modules.a03_supply_chain import assess_a03_supply_chain
from app.scanner.modules.a04_cryptography import assess_a04_cryptography
from app.scanner.modules.a05_injection import assess_a05_injection
from app.scanner.modules.a03_injection import assess_a03_injection
from app.scanner.modules.a06_insecure_design import assess_a06_insecure_design, assess_a04_insecure_design
from app.scanner.modules.a07_authentication import assess_a07_authentication
from app.scanner.modules.a08_integrity import assess_a08_integrity
from app.scanner.modules.a09_logging import assess_a09_logging
from app.scanner.modules.a10_exceptional_conditions import assess_a10_exceptional_conditions

# ─────────────────────────────────────────────────────────────────────────────
# Deprecated Backward-Compatibility Aliases (Retired OWASP Top 10:2021 Schema)
# ─────────────────────────────────────────────────────────────────────────────
# IMPORTANT: In OWASP Top 10:2025, A10 is strictly "Mishandling of Exceptional Conditions".
# The legacy assess_a10_ssrf alias evaluates candidate URL parameter surfaces
# from the retired 2021 classification and is retained solely for backward compatibility
# with existing test suites (e.g. test_controlled_evaluation).
assess_a02_cryptography = assess_a04_cryptography
assess_a05_misconfiguration = assess_a02_misconfiguration
assess_a06_components = assess_a03_supply_chain


async def assess_a10_ssrf(scan_id: str = "", discovered_parameters: dict | None = None) -> dict:
    """DEPRECATED: Legacy backward-compatibility alias for test_controlled_evaluation.

    NOTE: In OWASP Top 10:2025, A10 is 'Mishandling of Exceptional Conditions'
    (assess_a10_exceptional_conditions). Parameter surface evaluation is now
    an access-control indicator in A01:2025 (assess_a01_access_control).
    """
    from app.scanner.modules.a10_ssrf import assess_a10_ssrf as _legacy_ssrf
    return await _legacy_ssrf(scan_id, discovered_parameters)


__all__ = [
    # 2025 Primary Modules
    "assess_a01_access_control",
    "assess_a02_misconfiguration",
    "assess_a03_supply_chain",
    "assess_a04_cryptography",
    "assess_a05_injection",
    "assess_a06_insecure_design",
    "assess_a07_authentication",
    "assess_a08_integrity",
    "assess_a09_logging",
    "assess_a10_exceptional_conditions",
    # Backward Compatibility Aliases
    "assess_a02_cryptography",
    "assess_a03_injection",
    "assess_a04_insecure_design",
    "assess_a05_misconfiguration",
    "assess_a06_components",
    "assess_a10_ssrf",
]
