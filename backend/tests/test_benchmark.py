"""
Benchmark & Regression Test Suite
==================================
Tests detector behaviour against known-good and known-bad HTTP response fixtures
stored in tests/datasets/.

Every sub-directory under tests/datasets/ represents a scenario:
  request.json  — simulated HTTP headers, cookies, body snippet
  expected.json — assertions: must_detect / must_not_detect

Design goal
-----------
Every historically fixed false positive is encoded here as a permanent
regression test. If a FP is re-introduced in a future code change, these
tests will catch it before it reaches production.

Running
-------
    cd backend
    python -m pytest tests/test_benchmark.py -v
"""
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest

# Dataset root
DATASETS_DIR = Path(__file__).parent / "datasets"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _load_dataset(name: str) -> tuple[dict, dict]:
    """Load request.json and expected.json for a named dataset."""
    base = DATASETS_DIR / name
    with open(base / "request.json") as f:
        request = json.load(f)
    with open(base / "expected.json") as f:
        expected = json.load(f)
    return request, expected


def _finding_matches(finding: dict, spec: dict) -> bool:
    """Return True if finding matches all non-empty spec criteria."""
    title = finding.get("title", "").lower()
    category = finding.get("category", "").lower()

    if "title_contains" in spec:
        if spec["title_contains"].lower() not in title:
            return False
    if "category" in spec:
        if spec["category"].lower() not in category:
            return False
    if "severity" in spec:
        if finding.get("severity", "").lower() != spec["severity"].lower():
            return False
    return True


def _make_header_response(request_data: dict) -> httpx.Response:
    """Build a mock httpx.Response from a dataset request dict."""
    headers = request_data.get("headers", {})
    body = request_data.get("body_preview", "")
    status = request_data.get("status_code", 200)
    req = httpx.Request("GET", "https://example.com/")
    return httpx.Response(status, headers=headers, text=body, request=req)


# ──────────────────────────────────────────────────────────────────────────────
# 1. Server Version Disclosure — parametrised across all datasets
# ──────────────────────────────────────────────────────────────────────────────

class TestServerVersionDisclosure:
    """
    Server header version disclosure must fire ONLY when the Server value
    contains a version string (e.g. Apache/2.4.51).
    
    Benign values like 'nginx', 'Apache', 'cloudflare' must never trigger it.
    These cover confirmed historical false positives from real scans.
    """

    # Each tuple: (server_header_value, should_detect_version)
    CASES = [
        ("Apache/2.4.51 (Ubuntu)",          True,  "version string present"),
        ("nginx/1.20.1",                     True,  "version string present"),
        ("Microsoft-IIS/10.0",              True,  "version string present"),
        ("Apache",                           False, "vendor-only, no version — FP regression"),
        ("nginx",                            False, "vendor-only, no version — FP regression"),
        ("cloudflare",                       False, "CDN banner — FP regression"),
        ("AmazonS3",                         False, "AWS service banner — no version"),
        ("Vercel",                           False, "PaaS banner — no version"),
        ("LiteSpeed",                        False, "vendor-only — FP regression"),
        ("Microsoft-IIS",                   False, "vendor-only — FP regression"),
    ]

    @pytest.mark.parametrize("server_value,should_detect,reason", CASES)
    def test_server_header_version_disclosure(self, server_value: str, should_detect: bool, reason: str):
        """
        Validates the server-version-detection heuristic in header_analyzer.py
        without running a full live scan.
        """
        from app.scanner.header_analyzer import _check_server_version_disclosure

        result = _check_server_version_disclosure(server_value)
        if should_detect:
            assert result is not None, \
                f"Expected version disclosure finding for '{server_value}' but got None ({reason})"
        else:
            assert result is None, \
                f"False positive: '{server_value}' triggered version disclosure ({reason})"


# ──────────────────────────────────────────────────────────────────────────────
# 2. CSP Wildcard Detection — regression for subdomain vs standalone *
# ──────────────────────────────────────────────────────────────────────────────

class TestCSPWildcardDetection:
    """
    Regression tests for the CSP wildcard regex.

    Historical FP: *.cdn.example.com was incorrectly matched as a wildcard
    because a naive regex checked for '*' anywhere in the directive value.
    The fix uses negative lookahead (?![.\\w]) to exclude subdomain globs.
    """

    CASES = [
        # (csp_value, should_flag_wildcard, reason)
        ("default-src 'self'; script-src *",                                True,  "standalone * in script-src — is a full wildcard"),
        ("default-src *",                                                   True,  "standalone * in default-src — policy is disabled"),
        ("script-src 'self' *.cdn.example.com",                            False, "FP regression: *.cdn.example.com is a subdomain glob, not a full wildcard"),
        ("default-src 'self' https: *.trusted.com; script-src 'self'",     False, "FP regression: *.trusted.com subdomain glob in default-src"),
        ("script-src 'self' https://cdn.example.com data:",                False, "no wildcard present"),
        ("default-src 'self'; script-src 'self' 'unsafe-inline'",          False, "unsafe-inline present but no wildcard — different finding"),
    ]

    @pytest.mark.parametrize("csp_value,should_flag,reason", CASES)
    def test_csp_wildcard_regex(self, csp_value: str, should_flag: bool, reason: str):
        from app.scanner.header_analyzer import _CSP_WILDCARD_SCRIPT, _CSP_WILDCARD_DEFAULT

        detected = bool(
            _CSP_WILDCARD_SCRIPT.search(csp_value) or
            _CSP_WILDCARD_DEFAULT.search(csp_value)
        )
        if should_flag:
            assert detected, f"CSP wildcard not detected for '{csp_value}' ({reason})"
        else:
            assert not detected, f"FP: CSP wildcard incorrectly detected for '{csp_value}' ({reason})"


# ──────────────────────────────────────────────────────────────────────────────
# 3. HSTS Analysis — directive validation
# ──────────────────────────────────────────────────────────────────────────────

class TestHSTSAnalysis:
    """Validates HSTS directive checking accuracy."""

    def test_valid_hsts_no_issues(self):
        from app.scanner.header_analyzer import _analyze_hsts
        issues = _analyze_hsts("max-age=31536000; includeSubDomains; preload")
        high_issues = [i for i in issues if i["severity"] in ("high", "medium")]
        assert len(high_issues) == 0, f"Valid HSTS produced high/medium issues: {high_issues}"

    def test_missing_max_age(self):
        from app.scanner.header_analyzer import _analyze_hsts
        issues = _analyze_hsts("includeSubDomains")
        titles = [i["message"] for i in issues]
        assert any("max-age" in m.lower() for m in titles), "Missing max-age not detected"

    def test_short_max_age(self):
        from app.scanner.header_analyzer import _analyze_hsts
        issues = _analyze_hsts("max-age=86400; includeSubDomains")
        titles = [i["message"] for i in issues]
        assert any("short" in m.lower() or "max-age" in m.lower() for m in titles), \
            "Short max-age (86400) not detected"

    def test_includeSubDomains_optional(self):
        """includeSubDomains is intentionally downgraded to info — FP regression."""
        from app.scanner.header_analyzer import _analyze_hsts
        issues = _analyze_hsts("max-age=31536000; preload")
        high_or_medium = [i for i in issues if i["severity"] in ("high", "medium")]
        # Missing includeSubDomains should only be info, never high/medium
        assert len(high_or_medium) == 0, \
            f"includeSubDomains absence incorrectly elevated: {high_or_medium}"


# ──────────────────────────────────────────────────────────────────────────────
# 4. Technology Detection — FP regression for generic patterns
# ──────────────────────────────────────────────────────────────────────────────

class TestTechDetectionFP:
    """
    Regression tests for technology detection false positives.
    These cover patterns that were generating spurious tech detections
    for common CSS/HTML that appears on virtually any site.
    """

    def test_tailwind_container_not_detected_from_bootstrap(self):
        """
        FP regression: Bootstrap 'container' class must not trigger Bootstrap
        detection at high confidence when other Bootstrap signals are absent.
        """
        from app.scanner.tech_detector import TECH_SIGNATURES

        bootstrap_patterns = TECH_SIGNATURES["Bootstrap"]["patterns"]
        container_pattern = next(
            (p for p in bootstrap_patterns if "container" in p["pattern"]),
            None
        )
        assert container_pattern is None, \
            "FP regression: 'container' CSS class is in Bootstrap patterns — it matches nearly every site"

    def test_react_next_static_not_in_patterns(self):
        """
        FP regression: '_next/static' belongs to Next.js, not React.
        Including it in React patterns caused React to be detected on any Next.js site.
        """
        from app.scanner.tech_detector import TECH_SIGNATURES

        react_patterns = TECH_SIGNATURES["React"]["patterns"]
        next_pattern = next(
            (p for p in react_patterns if "_next/static" in p["pattern"]),
            None
        )
        assert next_pattern is None, \
            "FP regression: '_next/static' is a Next.js pattern, not React — must not be in React patterns"

    def test_xsrf_token_low_confidence(self):
        """
        FP regression: XSRF-TOKEN cookie is not exclusively a Laravel signal.
        Its confidence must remain below 60 so it cannot alone trigger
        high-confidence Laravel detection.
        """
        from app.scanner.tech_detector import TECH_SIGNATURES

        laravel_patterns = TECH_SIGNATURES["Laravel"]["patterns"]
        xsrf_pattern = next(
            (p for p in laravel_patterns if "XSRF-TOKEN" in p["pattern"]),
            None
        )
        assert xsrf_pattern is not None, "XSRF-TOKEN pattern missing from Laravel — check detector"
        assert xsrf_pattern["confidence"] < 60, \
            f"FP regression: XSRF-TOKEN confidence is {xsrf_pattern['confidence']} — must be < 60 to avoid solo high-confidence detection"


# ──────────────────────────────────────────────────────────────────────────────
# 5. Version Validation — CVE checker must reject non-semver versions
# ──────────────────────────────────────────────────────────────────────────────

class TestVersionValidation:
    """
    Regression tests for the version-string validator in cve_checker.py.
    Only well-formed version strings should be accepted for CVE lookup.
    Bare major versions, 'latest', 'x.y', etc. must be rejected to prevent
    sending poor queries to NVD.

    Design note: r'_VALID_VERSION_RE = r'^\d+\.\d[\d.]*$'
    This accepts x.y, x.y.z, x.y.z.w — all valid CPE version formats.
    It REJECTS: single integers ('3'), alpha ('latest', 'stable'),
    wildcard ('3.x', '1.*'), and operator prefixes ('~1.0').
    """

    # All of these are valid version strings for NVD CPE lookup
    VALID_VERSIONS = ["3.5.1", "1.0.0", "8.2.3", "5.4.1.2", "10.0.24", "3.5", "8.1"]

    # All of these must be REJECTED — they would produce invalid or useless CPE queries
    INVALID_VERSIONS = ["3", "3.x", "latest", "dev", "1.*", "~1.0", "stable"]

    @pytest.mark.parametrize("version", VALID_VERSIONS)
    def test_valid_version_accepted(self, version: str):
        from app.scanner.cve_checker import _VALID_VERSION_RE
        assert _VALID_VERSION_RE.match(version), \
            f"Valid version '{version}' was rejected by _VALID_VERSION_RE"

    @pytest.mark.parametrize("version", INVALID_VERSIONS)
    def test_invalid_version_rejected(self, version: str):
        from app.scanner.cve_checker import _VALID_VERSION_RE
        assert not _VALID_VERSION_RE.match(version), \
            f"FP regression: invalid version '{version}' was accepted by _VALID_VERSION_RE"


# ──────────────────────────────────────────────────────────────────────────────
# 6. Dataset fixture integrity — ensure all fixtures are valid JSON
# ──────────────────────────────────────────────────────────────────────────────

class TestDatasetIntegrity:
    """Validates that all dataset fixtures are well-formed JSON with required keys."""

    REQUIRED_REQUEST_KEYS = {"headers"}
    REQUIRED_EXPECTED_KEYS = {"must_not_detect"}
    DATASET_NAMES = [
        "apache", "nginx", "wordpress", "laravel",
        "cloudflare", "soft404", "reverse_proxy",
    ]

    @pytest.mark.parametrize("dataset", DATASET_NAMES)
    def test_request_json_valid(self, dataset: str):
        request, _ = _load_dataset(dataset)
        missing = self.REQUIRED_REQUEST_KEYS - set(request.keys())
        assert not missing, f"Dataset '{dataset}/request.json' missing keys: {missing}"

    @pytest.mark.parametrize("dataset", DATASET_NAMES)
    def test_expected_json_valid(self, dataset: str):
        _, expected = _load_dataset(dataset)
        missing = self.REQUIRED_EXPECTED_KEYS - set(expected.keys())
        assert not missing, f"Dataset '{dataset}/expected.json' missing keys: {missing}"

    @pytest.mark.parametrize("dataset", DATASET_NAMES)
    def test_must_not_detect_has_rationale(self, dataset: str):
        _, expected = _load_dataset(dataset)
        for item in expected.get("must_not_detect", []):
            assert "rationale" in item, \
                f"Dataset '{dataset}/expected.json' must_not_detect entry missing 'rationale': {item}"


# ──────────────────────────────────────────────────────────────────────────────
# 7. Evidence Engine — unit tests for evidence.py
# ──────────────────────────────────────────────────────────────────────────────

class TestEvidenceEngine:
    """Unit tests for the evidence.py module."""

    def test_evidence_chain_confidence_high(self):
        from app.scanner.evidence import Evidence, EvidenceType, EvidenceChain
        ev = Evidence(
            detector_id="header.hsts.missing",
            detector_name="HSTS Analyzer",
            evidence_type=EvidenceType.HEADER_ABSENT,
            evidence_source="GET https://example.com",
            observed_value="<not present>",
            expected_value="Strict-Transport-Security: max-age=31536000",
            reliability_score=0.95,
            explanation="HSTS header was absent.",
        )
        chain = EvidenceChain()
        chain.add(ev)
        assert chain.confidence == "high"

    def test_evidence_chain_confidence_medium(self):
        from app.scanner.evidence import Evidence, EvidenceType, EvidenceChain
        ev = Evidence(
            detector_id="tech.fingerprint",
            detector_name="Tech Detector",
            evidence_type=EvidenceType.TECH_FINGERPRINT,
            evidence_source="GET https://example.com",
            observed_value="WordPress 6.x detected via meta generator",
            expected_value="N/A",
            reliability_score=0.65,
            explanation="WordPress detected via meta generator tag.",
        )
        chain = EvidenceChain()
        chain.add(ev)
        assert chain.confidence == "medium"

    def test_finding_builder_produces_valid_dict(self):
        from app.scanner.evidence import Evidence, EvidenceType, FindingBuilder
        ev = Evidence(
            detector_id="header.hsts.missing",
            detector_name="HSTS Analyzer",
            evidence_type=EvidenceType.HEADER_ABSENT,
            evidence_source="GET https://example.com",
            observed_value="<not present>",
            expected_value="Strict-Transport-Security: max-age=31536000",
            reliability_score=0.95,
            explanation="HSTS header absent.",
        )
        finding = (
            FindingBuilder(
                category="Transport Security",
                title="Missing HSTS Header",
                severity="high",
                cvss_score=6.5,
                recommendation="Add HSTS header.",
            )
            .add_evidence(ev)
            .build()
        )
        required_keys = {"category", "title", "severity", "confidence", "technical_details", "evidence"}
        assert required_keys.issubset(finding.keys())
        assert finding["confidence"] == "high"
        assert "evidence" in finding["technical_details"]  # JSON evidence chain

    def test_evidence_chain_to_json_is_parseable(self):
        import json
        from app.scanner.evidence import Evidence, EvidenceType, EvidenceChain
        ev = Evidence(
            detector_id="ssl.cert.expired",
            detector_name="SSL Checker",
            evidence_type=EvidenceType.TLS_HANDSHAKE,
            evidence_source="TLS handshake with example.com:443",
            observed_value="Certificate expired 30 days ago",
            expected_value="Valid certificate with days_remaining > 0",
            reliability_score=1.0,
            explanation="TLS certificate is expired.",
        )
        chain = EvidenceChain()
        chain.add(ev)
        parsed = json.loads(chain.to_json())
        assert parsed["confidence"] == "high"
        assert len(parsed["evidence"]) == 1
        assert parsed["evidence"][0]["evidence_type"] == "tls_handshake"

    def test_make_finding_convenience_factory(self):
        from app.scanner.evidence import EvidenceType, make_finding
        finding = make_finding(
            detector_id="dns.spf.missing",
            detector_name="DNS Checker",
            evidence_type=EvidenceType.DNS_RECORD,
            evidence_source="DNS TXT query for example.com",
            observed_value="No SPF record found",
            expected_value="v=spf1 ... -all",
            reliability_score=0.9,
            explanation="No SPF TXT record exists for this domain.",
            category="DNS Security",
            title="Missing SPF Record",
            severity="medium",
            cvss_score=5.3,
        )
        assert finding["severity"] == "medium"
        assert finding["confidence"] == "high"
        assert "DNS_RECORD" in finding["evidence"]


# ──────────────────────────────────────────────────────────────────────────────
# 8. Metadata Registry — unit tests for metadata.py
# ──────────────────────────────────────────────────────────────────────────────

class TestMetadataRegistry:
    """Validates the DETECTOR_REGISTRY is well-formed."""

    REQUIRED_KEYS = {"id", "version", "author", "category", "description",
                     "standards", "owasp_top10", "min_confidence"}

    def test_all_entries_have_required_keys(self):
        from app.scanner.metadata import DETECTOR_REGISTRY
        for detector_id, entry in DETECTOR_REGISTRY.items():
            missing = self.REQUIRED_KEYS - set(entry.keys())
            assert not missing, \
                f"Detector '{detector_id}' missing keys: {missing}"

    def test_all_ids_match_dict_keys(self):
        from app.scanner.metadata import DETECTOR_REGISTRY
        for key, entry in DETECTOR_REGISTRY.items():
            assert entry["id"] == key, \
                f"Detector key '{key}' does not match entry id '{entry['id']}'"

    def test_all_owasp_ids_valid(self):
        from app.scanner.metadata import DETECTOR_REGISTRY
        valid_owasp = {f"A{str(i).zfill(2)}" for i in range(1, 11)}
        for detector_id, entry in DETECTOR_REGISTRY.items():
            owasp = entry.get("owasp_top10")
            if owasp:
                assert owasp in valid_owasp, \
                    f"Detector '{detector_id}' has invalid OWASP ID: '{owasp}'"

    def test_min_confidence_in_range(self):
        from app.scanner.metadata import DETECTOR_REGISTRY
        for detector_id, entry in DETECTOR_REGISTRY.items():
            conf = entry["min_confidence"]
            assert 0.0 <= conf <= 1.0, \
                f"Detector '{detector_id}' min_confidence {conf} out of range [0, 1]"

    def test_at_least_one_standard_per_detector(self):
        from app.scanner.metadata import DETECTOR_REGISTRY
        for detector_id, entry in DETECTOR_REGISTRY.items():
            assert entry["standards"], \
                f"Detector '{detector_id}' has no referenced standards"

    def test_get_detector_lookup(self):
        from app.scanner.metadata import get_detector
        meta = get_detector("header.hsts.missing")
        assert meta["category"] == "Security Headers"
        assert "RFC 6797" in meta["standards"]

    def test_unknown_detector_returns_empty(self):
        from app.scanner.metadata import get_detector
        result = get_detector("unknown.detector.id")
        assert result == {}

    def test_detectors_by_category(self):
        from app.scanner.metadata import detectors_by_category
        groups = detectors_by_category()
        assert "Security Headers" in groups
        assert "SSL/TLS" in groups
        assert "DNS Security" in groups
        assert len(groups["SSL/TLS"]) >= 4

    def test_all_owasp_mappings(self):
        from app.scanner.metadata import all_owasp_mappings
        mappings = all_owasp_mappings()
        # A04 (Cryptographic Failures in 2025) must have SSL detectors
        assert "A04" in mappings
        assert any("ssl" in d for d in mappings["A04"])
        # A02 (Security Misconfiguration in 2025) must have header detectors
        assert "A02" in mappings
        assert any("header" in d for d in mappings["A02"])

    def test_all_standards_not_empty(self):
        from app.scanner.metadata import all_standards
        standards = all_standards()
        assert "RFC 6797" in standards
        assert "RFC 7208" in standards
        assert "RFC 7489" in standards
