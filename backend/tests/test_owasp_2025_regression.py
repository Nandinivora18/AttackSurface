"""
OWASP Top 10:2025 Category Name Regression Tests
==================================================
Guards every user-output layer against regression to 2021 category labels.

Coverage:
- threat_intel.OWASP_TOP10 dict (the authoritative source used in enrichment)
- scan_task owasp_matrix key names (what the DB / API exposes)
- pdf_generator._owasp_section category list (what the PDF prints)
- get_threat_intel() enrichment output for common finding types
- No legacy 2021 names appear in any live enrichment output

These tests will FAIL immediately if anyone reassigns:
  A02 -> Cryptographic Failures   (was 2021 A02, now 2025 A04)
  A05 -> Security Misconfiguration (was 2021 A05, now 2025 A02)
  A06 -> Vulnerable & Outdated    (was 2021 A06, now 2025 A03)
  A10 -> SSRF                     (was 2021 A10, now 2025 A10=ExceptionalConditions)
"""
import pytest


# =============================================================================
# 1. threat_intel.OWASP_TOP10 is the authoritative 2025 dict
# =============================================================================

class TestThreatIntelOWASPTop10:
    """Locks the OWASP_TOP10 constant against 2021 label regression."""

    def _get_top10(self):
        from app.scanner.threat_intel import OWASP_TOP10
        return OWASP_TOP10

    def test_all_10_categories_present(self):
        top10 = self._get_top10()
        assert set(top10.keys()) == {
            "A01", "A02", "A03", "A04", "A05",
            "A06", "A07", "A08", "A09", "A10",
        }, "OWASP_TOP10 must contain exactly A01 through A10"

    # Positive: correct 2025 names
    def test_a01_broken_access_control(self):
        assert self._get_top10()["A01"]["title"] == "Broken Access Control"

    def test_a02_security_misconfiguration(self):
        assert self._get_top10()["A02"]["title"] == "Security Misconfiguration"

    def test_a03_software_supply_chain_failures(self):
        assert self._get_top10()["A03"]["title"] == "Software Supply Chain Failures"

    def test_a04_cryptographic_failures(self):
        assert self._get_top10()["A04"]["title"] == "Cryptographic Failures"

    def test_a05_injection(self):
        assert self._get_top10()["A05"]["title"] == "Injection"

    def test_a06_insecure_design(self):
        assert self._get_top10()["A06"]["title"] == "Insecure Design"

    def test_a07_authentication_failures(self):
        assert self._get_top10()["A07"]["title"] == "Authentication Failures"

    def test_a08_integrity_failures(self):
        top10 = self._get_top10()
        assert "Integrity" in top10["A08"]["title"]

    def test_a09_logging_alerting_failures(self):
        top10 = self._get_top10()
        assert "Logging" in top10["A09"]["title"] or "Alerting" in top10["A09"]["title"]

    def test_a10_exceptional_conditions(self):
        top10 = self._get_top10()
        assert "Exceptional" in top10["A10"]["title"] or "Mishandling" in top10["A10"]["title"]

    # Negative: 2021 names must NOT appear
    def test_no_2021_a02_cryptographic(self):
        """A02 must NOT be Cryptographic Failures (that was 2021 A02; 2025 A04)."""
        title = self._get_top10()["A02"]["title"]
        assert "Cryptographic" not in title, (
            f"A02 title '{title}' contains 2021 label. "
            "2025: A02=Security Misconfiguration, A04=Cryptographic Failures"
        )

    def test_no_2021_a05_misconfiguration(self):
        """A05 must NOT be Security Misconfiguration (that was 2021 A05; 2025 A02)."""
        title = self._get_top10()["A05"]["title"]
        assert "Misconfiguration" not in title, (
            f"A05 title '{title}' contains 2021 label. "
            "2025: A05=Injection, A02=Security Misconfiguration"
        )

    def test_no_2021_a06_vulnerable_outdated(self):
        """A06 must NOT be Vulnerable and Outdated Components (that was 2021 A06; 2025 A03)."""
        title = self._get_top10()["A06"]["title"]
        assert "Vulnerable" not in title and "Outdated" not in title, (
            f"A06 title '{title}' contains 2021 label. "
            "2025: A06=Insecure Design, A03=Software Supply Chain Failures"
        )

    def test_no_2021_a10_ssrf(self):
        """A10 must NOT be Server-Side Request Forgery (that was 2021 A10)."""
        title = self._get_top10()["A10"]["title"]
        assert "SSRF" not in title and "Server-Side Request Forgery" not in title, (
            f"A10 title '{title}' contains 2021 label. "
            "2025: A10=Mishandling of Exceptional Conditions"
        )


# =============================================================================
# 2. scan_task owasp_matrix keys must use 2025 slugs
# =============================================================================

class TestOWASPMatrixKeys:
    """Verifies scan_task.py owasp_matrix uses 2025 slugs, not 2021 slugs."""

    EXPECTED_KEYS_2025 = [
        "A01_BrokenAccessControl",
        "A02_SecurityMisconfiguration",
        "A03_SoftwareSupplyChainFailures",
        "A04_CryptographicFailures",
        "A05_Injection",
        "A06_InsecureDesign",
        "A07_AuthenticationFailures",
        "A08_SoftwareOrDataIntegrityFailures",
        "A09_SecurityLoggingAndAlertingFailures",
        "A10_MishandlingOfExceptionalConditions",
    ]
    FORBIDDEN_KEYS_2021 = [
        "A02_CryptographicFailures",
        "A05_SecurityMisconfiguration",
        "A06_VulnerableAndOutdatedComponents",
        "A10_ServerSideRequestForgery",
    ]

    def _read_source(self) -> str:
        import pathlib
        src = pathlib.Path(__file__).parent.parent / "app" / "tasks" / "scan_task.py"
        return src.read_text(encoding="utf-8")

    def test_all_2025_matrix_keys_in_source(self):
        src = self._read_source()
        for key in self.EXPECTED_KEYS_2025:
            assert key in src, (
                f"Expected 2025 OWASP matrix key '{key}' not found in scan_task.py"
            )

    def test_no_2021_matrix_keys_in_source(self):
        src = self._read_source()
        for key in self.FORBIDDEN_KEYS_2021:
            assert key not in src, (
                f"Forbidden 2021 OWASP matrix key '{key}' found in scan_task.py"
            )


# =============================================================================
# 3. pdf_generator._owasp_section matrix uses 2025 names
# =============================================================================

class TestPDFGeneratorOWASPMatrix:
    """Validates pdf_generator._owasp_section hardcoded list uses 2025 labels."""

    def _read_source(self) -> str:
        import pathlib
        src = pathlib.Path(__file__).parent.parent / "app" / "utils" / "pdf_generator.py"
        return src.read_text(encoding="utf-8")

    def _owasp_section_text(self) -> str:
        src = self._read_source()
        start = src.find("def _owasp_section(")
        end = src.find("\ndef ", start + 1)
        return src[start:end] if end != -1 else src[start:]

    def test_all_ten_2025_ids_present(self):
        src = self._read_source()
        for cat_id in ("A01:2025", "A02:2025", "A03:2025", "A04:2025", "A05:2025",
                       "A06:2025", "A07:2025", "A08:2025", "A09:2025", "A10:2025"):
            assert cat_id in src, f"PDF generator missing OWASP ID '{cat_id}'"

    def test_2025_category_names_in_pdf(self):
        src = self._read_source()
        for name in [
            "Broken Access Control",
            "Security Misconfiguration",
            "Software Supply Chain Failures",
            "Cryptographic Failures",
            "Injection",
            "Insecure Design",
            "Authentication Failures",
            "Software or Data Integrity Failures",
            "Security Logging",
            "Mishandling of Exceptional Conditions",
        ]:
            assert name in src, f"PDF generator missing 2025 category name '{name}'"

    def test_no_vulnerable_outdated_in_owasp_section(self):
        section = self._owasp_section_text()
        assert "Vulnerable and Outdated" not in section, (
            "PDF _owasp_section must not contain 2021 A06 label"
        )

    def test_no_ssrf_in_owasp_section(self):
        section = self._owasp_section_text()
        assert "Server-Side Request Forgery" not in section, (
            "PDF _owasp_section must not contain 2021 A10 SSRF label"
        )


# =============================================================================
# 4. get_threat_intel() assigns correct Ax to known finding types
# =============================================================================

class TestGetThreatIntelMapping:
    """Integration-level: get_threat_intel() returns correct 2025 Ax buckets."""

    def _intel(self, category: str, title: str) -> dict:
        from app.scanner.threat_intel import get_threat_intel
        return get_threat_intel(category, title)

    # Positive assertions
    def test_ssl_tls_maps_to_a04_cryptographic(self):
        result = self._intel("SSL/TLS", "Expired Certificate")
        assert result["owasp"]["id"] == "A04", (
            "SSL/TLS findings must map to A04:2025 (Cryptographic Failures)"
        )

    def test_hsts_maps_to_a04_cryptographic(self):
        result = self._intel("Security Headers", "Missing HSTS Header")
        assert result["owasp"]["id"] == "A04", (
            "HSTS findings must map to A04:2025 (Cryptographic Failures)"
        )

    def test_cve_maps_to_a03_supply_chain(self):
        result = self._intel("CVE", "CVE-2024-1234: OpenSSL vulnerability")
        assert result["owasp"]["id"] == "A03", (
            "CVE findings must map to A03:2025 (Software Supply Chain Failures)"
        )

    def test_security_headers_maps_to_a02(self):
        result = self._intel("Security Headers", "Missing X-Frame-Options Header")
        assert result["owasp"]["id"] == "A02", (
            "Defensive header findings must map to A02:2025 (Security Misconfiguration)"
        )

    def test_injection_maps_to_a05(self):
        result = self._intel("Injection Prevention", "Reflected Input Detected")
        assert result["owasp"]["id"] == "A05", (
            "Injection findings must map to A05:2025 (Injection)"
        )

    def test_ssrf_parameter_maps_to_a01(self):
        result = self._intel("SSRF", "URL-accepting parameter detected")
        assert result["owasp"]["id"] == "A01", (
            "SSRF parameter surface must map to A01:2025 (Broken Access Control)"
        )

    # Negative assertions: 2021 mis-assignments must not occur
    def test_ssl_does_not_map_to_a02(self):
        """Regression guard: SSL was A02 in 2021, must now be A04."""
        result = self._intel("SSL/TLS", "Weak TLS 1.0 Protocol")
        assert result["owasp"]["id"] != "A02", (
            "SSL/TLS must NOT map to A02 (that was the 2021 label). Use A04:2025."
        )

    def test_cve_does_not_map_to_a06(self):
        """Regression guard: CVE was A06 in 2021, must now be A03."""
        result = self._intel("CVE", "CVE-2024-5678: component vulnerability")
        assert result["owasp"]["id"] != "A06", (
            "CVE findings must NOT map to A06 (that was the 2021 label). Use A03:2025."
        )
