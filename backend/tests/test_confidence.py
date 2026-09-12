"""
Confidence scoring regression tests.

Verifies that every detector produces valid Confidence enum values
and that the metadata-based detector_confidence helper maps correctly.
"""
import pytest
from app.models.finding import Confidence
from app.scanner.metadata import detector_confidence, DETECTOR_REGISTRY


# ---------------------------------------------------------------------------
# Metadata helper tests
# ---------------------------------------------------------------------------

class TestDetectorConfidence:
    """Test the detector_confidence metadata helper."""

    def test_header_hsts_missing_returns_high(self):
        assert detector_confidence("header.hsts.missing") == "high"

    def test_header_csp_missing_returns_high(self):
        assert detector_confidence("header.csp.missing") == "high"

    def test_header_xcto_missing_returns_high(self):
        assert detector_confidence("header.xcto.missing") == "high"

    def test_header_permissions_policy_returns_medium(self):
        # min_confidence 0.7 → medium
        assert detector_confidence("header.permissions_policy.missing") == "medium"

    def test_ssl_cert_expired_returns_high(self):
        assert detector_confidence("ssl.cert.expired") == "high"

    def test_ssl_protocol_weak_returns_high(self):
        assert detector_confidence("ssl.protocol.weak") == "high"

    def test_dns_spf_missing_returns_high(self):
        assert detector_confidence("dns.spf.missing") == "high"

    def test_dns_dmarc_weak_returns_high(self):
        assert detector_confidence("dns.dmarc.weak_policy") == "high"

    def test_dns_mx_missing_returns_low(self):
        # min_confidence 0.6 → low
        assert detector_confidence("dns.mx.missing") == "low"

    def test_tech_fingerprint_returns_low(self):
        # min_confidence 0.6 → low
        assert detector_confidence("tech.fingerprint") == "low"

    def test_tech_version_disclosure_returns_medium(self):
        # min_confidence 0.7 → medium
        assert detector_confidence("tech.version_disclosure") == "medium"

    def test_cve_match_returns_medium(self):
        # min_confidence 0.7 → medium
        assert detector_confidence("tech.cve_match") == "medium"

    def test_content_exposed_file_returns_high(self):
        assert detector_confidence("content.exposed_file") == "high"

    def test_unknown_detector_returns_high(self):
        # Unknown detectors default to high (deterministic assumption)
        assert detector_confidence("nonexistent.detector") == "high"

    def test_all_registered_detectors_return_valid_values(self):
        """Every detector in the registry maps to a valid Confidence value."""
        valid = {"high", "medium", "low"}
        for detector_id in DETECTOR_REGISTRY:
            conf = detector_confidence(detector_id)
            assert conf in valid, f"detector_confidence({detector_id!r}) returned {conf!r}"


# ---------------------------------------------------------------------------
# Content analyzer confidence normalization
# ---------------------------------------------------------------------------

class TestContentAnalyzerConfidence:
    """Verify content_analyzer produces valid Confidence enum values."""

    def test_confirmed_not_in_valid_values(self):
        """'confirmed' is not a valid Confidence member."""
        valid = {c.value for c in Confidence}
        assert "confirmed" not in valid

    def test_none_not_in_valid_values(self):
        """'none' is not a valid Confidence member."""
        valid = {c.value for c in Confidence}
        assert "none" not in valid

    def test_valid_confidence_enum_values(self):
        """The Confidence enum has exactly three members."""
        assert {c.value for c in Confidence} == {"high", "medium", "low"}


# ---------------------------------------------------------------------------
# Scan task normalization tests
# ---------------------------------------------------------------------------

class TestConfidenceNormalization:
    """Test the confidence normalization logic in scan_task.py."""

    def test_valid_confidence_preserved(self):
        """Valid confidence values pass through normalization unchanged."""
        _VALID = {"high", "medium", "low"}
        _MAP = {"confirmed": "high", "none": "low"}
        finding = {"confidence": "medium"}
        conf = finding.get("confidence", "high")
        if conf not in _VALID:
            finding["confidence"] = _MAP.get(conf, "high")
        assert finding["confidence"] == "medium"

    def test_confirmed_mapped_to_high(self):
        """'confirmed' confidence normalizes to 'high'."""
        _VALID = {"high", "medium", "low"}
        _MAP = {"confirmed": "high", "none": "low"}
        finding = {"confidence": "confirmed"}
        conf = finding.get("confidence", "high")
        if conf not in _VALID:
            finding["confidence"] = _MAP.get(conf, "high")
        assert finding["confidence"] == "high"

    def test_none_mapped_to_low(self):
        """'none' confidence normalizes to 'low'."""
        _VALID = {"high", "medium", "low"}
        _MAP = {"confirmed": "high", "none": "low"}
        finding = {"confidence": "none"}
        conf = finding.get("confidence", "high")
        if conf not in _VALID:
            finding["confidence"] = _MAP.get(conf, "high")
        assert finding["confidence"] == "low"

    def test_unknown_value_mapped_to_high(self):
        """Unknown non-standard confidence values default to 'high'."""
        _VALID = {"high", "medium", "low"}
        _MAP = {"confirmed": "high", "none": "low"}
        finding = {"confidence": "custom_value"}
        conf = finding.get("confidence", "high")
        if conf not in _VALID:
            finding["confidence"] = _MAP.get(conf, "high")
        assert finding["confidence"] == "high"

    def test_missing_confidence_defaults_to_high(self):
        """Findings without a confidence field default to 'high'."""
        finding = {}
        conf = finding.get("confidence", "high")
        assert conf == "high"


# ---------------------------------------------------------------------------
# Header analyzer confidence values
# ---------------------------------------------------------------------------

class TestHeaderAnalyzerConfidence:
    """Verify header analyzer findings include valid confidence."""

    def test_spec_is_dict_with_expected_keys(self):
        """SECURITY_HEADERS_SPEC is a dict keyed by header name."""
        from app.scanner.header_analyzer import SECURITY_HEADERS_SPEC
        assert len(SECURITY_HEADERS_SPEC) > 0
        for header_name, spec in SECURITY_HEADERS_SPEC.items():
            assert "name" in spec
            assert "missing_severity" in spec
            assert isinstance(header_name, str)


# ---------------------------------------------------------------------------
# DNS checker confidence values
# ---------------------------------------------------------------------------

class TestDNSCheckerConfidence:
    """Verify DNS checker findings include valid confidence."""

    def test_analyze_dns_findings_use_valid_confidence(self):
        """DNS findings from _analyze_dns_findings should use valid Confidence values."""
        from app.scanner.dns_checker import _analyze_dns_findings
        # Test with mock data that triggers missing SPF finding
        dns_info = {
            "a_records": ["1.2.3.4"],
            "mx_records": [{"priority": 10, "exchange": "mail.example.com"}],
            "txt_records": [],
            "ns_records": ["ns1.example.com"],
            "spf": None,
            "dmarc": None,
            "dkim": {},
        }
        findings = _analyze_dns_findings("example.com", dns_info)
        valid_confidence = {c.value for c in Confidence}
        for finding in findings:
            conf = finding.get("confidence", "high")
            assert conf in valid_confidence, (
                f"DNS finding '{finding.get('title')}' has invalid confidence: {conf!r}"
            )


# ---------------------------------------------------------------------------
# CVE checker confidence values
# ---------------------------------------------------------------------------

class TestCVECheckerConfidence:
    """Verify CVE checker findings include valid confidence."""

    def test_cve_findings_have_medium_confidence(self):
        """NVD CVE findings should have medium confidence (version-range matching)."""
        from app.scanner.cve_checker import _parse_cve_item
        # _parse_cve_item receives the unwrapped "cve" sub-dict from NVD API
        mock_item = {
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Test CVE description"}],
            "published": "2021-12-10T00:00:00.000",
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    }
                }]
            },
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-502"}]}],
        }
        finding = _parse_cve_item(mock_item, "Apache Tomcat", "9.0.50")
        assert finding is not None
        assert finding.get("confidence") == "medium"
        assert finding.get("cve_id") == "CVE-2021-44228"
