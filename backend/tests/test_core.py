"""
SentinelScan Backend Tests
Run with: pytest tests/ -v
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


# ─── Unit Tests: Scoring Engine ───────────────────────────────────────────────

class TestScoring:
    def test_perfect_score_no_findings(self):
        from app.scanner.scoring import calculate_score
        result = calculate_score([])
        assert result["overall_score"] == 100
        assert result["grade"] == "A+"
        assert result["risk_level"] == "info"

    def test_critical_finding_reduces_score(self):
        from app.scanner.scoring import calculate_score
        findings = [{"severity": "critical", "category": "SSL/TLS"}]
        result = calculate_score(findings)
        # Score must be less than 100 and grade must not be A+
        assert result["overall_score"] < 100
        assert result["grade"] != "A+"
        assert result["risk_level"] == "critical"
        # category_scores must be present with expected keys
        assert "category_scores" in result
        assert "ssl_tls" in result["category_scores"]

    def test_multiple_high_findings(self):
        from app.scanner.scoring import calculate_score
        # 4 high findings spread across different categories
        findings = [
            {"severity": "high", "category": "SSL/TLS"},
            {"severity": "high", "category": "Injection Prevention"},
            {"severity": "high", "category": "DNS"},
            {"severity": "high", "category": "Technology"},
        ]
        result = calculate_score(findings)
        # Score must decrease with multiple high findings
        assert result["overall_score"] < 100
        assert result["risk_level"] == "high"
        assert result["severity_counts"]["high"] == 4

    def test_score_clamps_at_zero(self):
        from app.scanner.scoring import calculate_score
        # Many critical findings across many categories should push score very low
        findings = [
            {"severity": "critical", "category": cat}
            for cat in [
                "SSL/TLS", "Injection Prevention", "DNS",
                "Technology", "Content", "Configuration",
                "Security Headers", "Cookies",
            ]
        ] * 3  # 3x each = 24 criticals
        result = calculate_score(findings)
        assert result["overall_score"] <= 10  # Should be near 0
        assert result["grade"] == "F"

    def test_info_findings_no_penalty(self):
        from app.scanner.scoring import calculate_score
        findings = [{"severity": "info"}] * 10
        result = calculate_score(findings)
        assert result["overall_score"] == 100
        assert result["grade"] == "A+"

    def test_report_consistency_contract(self):
        """Dashboard/report severity counts must agree with findings, and
        informational (info) observability notes must never be counted as
        vulnerabilities nor move the score/grade/risk_level.

        Contract restated:
          - severity_counts == count of open (non-passed) findings per severity;
            info is included ONLY as an informational observability number.
          - is_passed_control findings are excluded from every count.
          - total_findings is a transparency count of ALL findings.
        """
        from app.scanner.scoring import calculate_score
        findings = [
            {"severity": "critical", "category": "SSL/TLS", "title": "Expired cert",
             "is_passed_control": False, "recommendation": "renew"},
            {"severity": "critical", "category": "SSL/TLS", "title": "Expired cert (passed)",
             "is_passed_control": True, "recommendation": "renew"},  # not a vulnerability
            {"severity": "high", "category": "Injection Prevention", "title": "Missing CSP",
             "is_passed_control": False},
            {"severity": "medium", "category": "DNS", "title": "SPF missing",
             "is_passed_control": False},
            {"severity": "low", "category": "Content", "title": "Dir listing",
             "is_passed_control": False},
            {"severity": "info", "category": "General", "title": "Server header present",
             "is_passed_control": True},
            {"severity": "info", "category": "General", "title": "Tech fingerprint",
             "is_passed_control": False},
        ]
        result = calculate_score(findings)

        sc = result["severity_counts"]
        assert sc["critical"] == 1, "passed_control critical must not be counted"
        assert sc["high"] == 1 and sc["medium"] == 1 and sc["low"] == 1
        assert sc["info"] == 1, "info count is informational observability only"
        open_total = sc["critical"] + sc["high"] + sc["medium"] + sc["low"]
        assert open_total == 4
        assert result["total_findings"] == len(findings), (
            "total_findings is a transparency count of ALL findings"
        )

        # Removing the info findings must not change score, grade, or risk.
        base = calculate_score([f for f in findings if f["severity"] != "info"])
        assert result["overall_score"] == base["overall_score"]
        assert result["grade"] == base["grade"]
        assert result["risk_level"] == base["risk_level"] == "critical"
        # And removing the passed-control critical must not change anything either.
        opened_only = calculate_score(
            [f for f in findings if not f.get("is_passed_control")]
        )
        assert result["overall_score"] == opened_only["overall_score"]
        assert result["severity_counts"] == opened_only["severity_counts"]

    def test_mixed_severity(self):
        from app.scanner.scoring import calculate_score
        findings = [
            {"severity": "critical", "category": "SSL/TLS"},
            {"severity": "high",     "category": "Injection Prevention"},
            {"severity": "medium",   "category": "DNS"},
            {"severity": "low",      "category": "Content"},
            {"severity": "info",     "category": "General"},
        ]
        result = calculate_score(findings)
        # Mixed findings: score must be significantly below 100
        assert result["overall_score"] < 90
        assert result["grade"] in ("A", "B", "C", "D", "F")
        assert result["risk_level"] == "critical"

    def test_grade_thresholds(self):
        from app.scanner.scoring import calculate_score, GRADE_THRESHOLDS
        test_cases = [
            (100, "A+"), (90, "A+"), (89, "A"), (80, "A"),
            (79, "B"), (70, "B"), (69, "C"), (60, "C"),
            (59, "D"), (50, "D"), (49, "F"), (0, "F"),
        ]
        for score_target, expected_grade in test_cases:
            # We test by finding what score range maps to each grade
            # directly check the GRADE_THRESHOLDS logic
            grade = "F"
            for threshold, letter in GRADE_THRESHOLDS:
                if score_target >= threshold:
                    grade = letter
                    break
            assert grade == expected_grade, f"Score {score_target} → expected {expected_grade}, got {grade}"

    def test_executive_summary_contains_url(self):
        from app.scanner.scoring import generate_executive_summary
        summary = generate_executive_summary(
            url="https://example.com",
            score=75,
            grade="B",
            severity_counts={"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 3},
            tech_stack={"React": {"category": "JS Framework"}, "nginx": {"category": "Web Server"}},
        )
        assert "example.com" in summary
        assert "75" in summary
        assert "Grade: B" in summary
        assert "React" in summary or "nginx" in summary


# ─── Unit Tests: Security Utils ───────────────────────────────────────────────

class TestSecurityUtils:
    def test_password_hash_and_verify(self):
        from app.utils.security import hash_password, verify_password
        # Keep password short (< 72 bytes) to avoid bcrypt backend detection edge cases
        password = "ValidPass1"
        hashed = hash_password(password)
        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("WrongPass1", hashed)

    def test_token_hashing_deterministic(self):
        from app.utils.security import hash_token
        token = "my-secret-token-value"
        assert hash_token(token) == hash_token(token)
        assert hash_token(token) != hash_token("different-token")

    def test_generate_token_length(self):
        from app.utils.security import generate_token
        token = generate_token(32)
        # URL-safe base64 of 32 random bytes ≈ 43 chars
        assert len(token) >= 40
        assert isinstance(token, str)

    def test_generate_tokens_are_unique(self):
        from app.utils.security import generate_token
        tokens = {generate_token(32) for _ in range(100)}
        assert len(tokens) == 100

    def test_create_access_token_structure(self):
        import uuid
        from app.utils.security import create_access_token, decode_token
        user_id = uuid.uuid4()
        token = create_access_token(user_id, "user")
        payload = decode_token(token, expected_type="access")
        assert payload["sub"] == str(user_id)
        assert payload["role"] == "user"
        assert payload["type"] == "access"
        assert "jti" in payload
        assert "exp" in payload

    def test_create_refresh_token_structure(self):
        import uuid
        from app.utils.security import create_refresh_token, decode_token
        user_id = uuid.uuid4()
        token = create_refresh_token(user_id)
        payload = decode_token(token, expected_type="refresh")
        assert payload["sub"] == str(user_id)
        assert payload["type"] == "refresh"

    def test_invalid_token_raises(self):
        from fastapi import HTTPException
        from app.utils.security import decode_token
        with pytest.raises(HTTPException) as exc_info:
            decode_token("not.a.valid.token")
        assert exc_info.value.status_code == 401

    def test_wrong_token_type_raises(self):
        import uuid
        from fastapi import HTTPException
        from app.utils.security import create_access_token, decode_token
        user_id = uuid.uuid4()
        access_token = create_access_token(user_id, "user")
        with pytest.raises(HTTPException):
            decode_token(access_token, expected_type="refresh")


# ─── Unit Tests: URL Validation ───────────────────────────────────────────────

class TestScanUrlValidation:
    def test_valid_https_url(self):
        from app.schemas.scan import ScanCreate
        scan = ScanCreate(url="https://example.com")
        assert scan.url == "https://example.com"

    def test_url_without_scheme_gets_https(self):
        from app.schemas.scan import ScanCreate
        scan = ScanCreate(url="example.com")
        assert scan.url.startswith("https://")

    def test_blocks_localhost(self):
        from app.schemas.scan import ScanCreate
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ScanCreate(url="http://localhost/admin")

    def test_blocks_internal_ip(self):
        from app.schemas.scan import ScanCreate
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ScanCreate(url="http://192.168.1.1")

    def test_blocks_loopback(self):
        from app.schemas.scan import ScanCreate
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ScanCreate(url="http://127.0.0.1/secret")


# ─── Unit Tests: Password Validation Schema ───────────────────────────────────

class TestPasswordValidation:
    def test_valid_password(self):
        from app.schemas.user import UserCreate
        user = UserCreate(email="test@example.com", name="Test User", password="ValidPass1")
        assert user.password == "ValidPass1"

    def test_too_short(self):
        from app.schemas.user import UserCreate
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UserCreate(email="test@example.com", name="Test", password="Sh0rt")

    def test_no_uppercase(self):
        from app.schemas.user import UserCreate
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UserCreate(email="test@example.com", name="Test User", password="lowercase1pass")

    def test_no_digit(self):
        from app.schemas.user import UserCreate
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UserCreate(email="test@example.com", name="Test User", password="NoDigitPass")


# ─── Unit Tests: Content Analysis Helpers ─────────────────────────────────────

class TestContentAnalysisHelpers:
    def test_email_regex_matches_valid(self):
        import re
        from app.scanner.content_analyzer import EMAIL_PATTERN
        emails = [
            "user@example.com",
            "support@company.io",
            "test.user+tag@subdomain.domain.co",
        ]
        for email in emails:
            assert EMAIL_PATTERN.search(email), f"Should match: {email}"

    def test_email_regex_ignores_invalid(self):
        import re
        from app.scanner.content_analyzer import EMAIL_PATTERN
        non_emails = ["not-an-email", "missing@", "@nodomain", "plain text"]
        for text in non_emails:
            # These should either not match or match partial, we just test the pattern exists
            match = EMAIL_PATTERN.fullmatch(text)
            assert match is None, f"Should not fully match: {text}"


# ─── Integration-style Tests: Scoring + Engine Data Flow ──────────────────────

class TestScoringIntegration:
    def test_score_from_realistic_header_findings(self):
        from app.scanner.scoring import calculate_score
        # Typical header analysis findings
        findings = [
            {"severity": "high",   "category": "Injection Prevention", "title": "Missing Content-Security-Policy", "recommendation": "Add CSP"},
            {"severity": "medium", "category": "Clickjacking Protection", "title": "Missing X-Frame-Options", "recommendation": "Add XFO"},
            {"severity": "medium", "category": "Transport Security", "title": "Missing HSTS", "recommendation": "Add HSTS"},
            {"severity": "low",    "category": "Information Disclosure", "title": "Server header exposes version", "recommendation": "Remove version"},
            {"severity": "info",   "category": "Content", "title": "Sitemap present"},
        ]
        result = calculate_score(findings)
        # With the weighted algorithm, score should be noticeably below 100
        assert result["overall_score"] < 100
        assert result["overall_score"] >= 60  # Not catastrophic — only moderate issues
        assert result["severity_counts"]["high"] == 1
        assert result["severity_counts"]["medium"] == 2
        assert result["total_findings"] == 5
        # Verify new fields exist
        assert "category_scores" in result
        assert isinstance(result["category_scores"], dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
