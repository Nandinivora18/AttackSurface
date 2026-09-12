"""
Regression tests for:
1. Server header version detection — prevents hostname false positives
2. DKIM confidence level — confirms selector enumeration does not assert absence
"""
import pytest
from app.scanner.header_analyzer import _check_server_disclosure
from app.scanner.dns_checker import analyze_dns


# ─────────────────────────────────────────────────────────────────────────────
# Server Header Version Detection
# ─────────────────────────────────────────────────────────────────────────────

class TestServerDisclosure:
    """Tests for _check_server_disclosure — ensures the regex only flags
    real software/version strings, not plain hostnames or benign values."""

    # ── Should detect version (medium severity) ──────────────────────────────

    def test_apache_version_detected(self):
        issues = _check_server_disclosure({"server": "Apache/2.4.58"})
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"
        assert "Apache/2.4.58" in issues[0]["message"]

    def test_nginx_version_detected(self):
        issues = _check_server_disclosure({"server": "nginx/1.26.1"})
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"
        assert "nginx/1.26.1" in issues[0]["message"]

    def test_openresty_version_detected(self):
        issues = _check_server_disclosure({"server": "openresty/1.25.3.1"})
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"

    def test_iis_version_detected(self):
        issues = _check_server_disclosure({"server": "Microsoft-IIS/10.0"})
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"

    def test_apache_with_extra_tokens_detected(self):
        # Apache/2.4.58 (Ubuntu) — still has the version token
        issues = _check_server_disclosure({"server": "Apache/2.4.58 (Ubuntu)"})
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"

    # ── Hostname false positives — must NOT report "version" ─────────────────

    def test_hostname_github_not_version(self):
        """github.com is a plain hostname with no version — must not be medium."""
        issues = _check_server_disclosure({"server": "github.com"})
        # If it produces a finding at all, it must be low (software name), not medium
        for issue in issues:
            assert issue["severity"] != "medium", (
                f"'github.com' incorrectly flagged as version disclosure: {issue['message']}"
            )

    def test_hostname_with_tld_not_version(self):
        """example.org is a plain hostname — no finding expected."""
        issues = _check_server_disclosure({"server": "example.org"})
        for issue in issues:
            assert issue["severity"] != "medium"

    def test_granian_server_no_version(self):
        """'granian' is a plain software name with no version."""
        issues = _check_server_disclosure({"server": "granian"})
        # Exactly one finding: low severity software disclosure
        assert len(issues) == 1
        assert issues[0]["severity"] == "low"
        assert "granian" in issues[0]["message"]

    # ── Benign / CDN values — silently skipped ────────────────────────────────

    def test_cloudflare_skipped(self):
        issues = _check_server_disclosure({"server": "cloudflare"})
        assert issues == []

    def test_empty_server_skipped(self):
        issues = _check_server_disclosure({"server": ""})
        assert issues == []

    def test_netlify_skipped(self):
        issues = _check_server_disclosure({"server": "netlify"})
        assert issues == []

    def test_vercel_skipped(self):
        issues = _check_server_disclosure({"server": "vercel"})
        assert issues == []

    # ── X-Powered-By and X-AspNet-Version ────────────────────────────────────

    def test_x_powered_by_detected(self):
        issues = _check_server_disclosure({"x-powered-by": "PHP/8.1.0"})
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"

    def test_x_aspnet_version_detected(self):
        issues = _check_server_disclosure({"x-aspnet-version": "4.0.30319"})
        assert len(issues) == 1
        assert issues[0]["severity"] == "medium"

    def test_no_headers_no_issues(self):
        issues = _check_server_disclosure({})
        assert issues == []


# ─────────────────────────────────────────────────────────────────────────────
# DKIM Confidence Level
# ─────────────────────────────────────────────────────────────────────────────

class TestDkimConfidence:
    """Validates that DKIM absence via selector enumeration is reported as
    informational with low confidence, not as a confirmed vulnerability."""

    @pytest.mark.asyncio
    async def test_dkim_not_detected_is_info_severity(self):
        """If DKIM is not found under common selectors, severity must be 'info'
        (not 'low', 'medium', or higher) because selector enumeration cannot
        prove DKIM is absent."""
        # Use a real domain that is very unlikely to have DKIM under common
        # selectors (example.com is IANA controlled and has no MX / DKIM)
        # We test the finding shape using a domain we know has MX but a
        # custom selector: we mock the dns_info dict directly via the
        # internal analysis path.
        from app.scanner.dns_checker import _analyze_dns_findings

        # Simulate: domain has MX records but no DKIM found under common selectors
        dns_info = {
            "a_records": ["93.184.216.34"],
            "mx_records": ["10 mail.example.com"],
            "txt_records": [],
            "ns_records": ["ns1.example.com"],
            "spf": "v=spf1 -all",
            "dmarc": "v=DMARC1; p=reject",
            "dkim": None,   # not found under common selectors
        }
        findings = _analyze_dns_findings("example.com", dns_info)

        dkim_findings = [f for f in findings if "DKIM" in f.get("title", "")]
        assert len(dkim_findings) == 1, "Expected exactly one DKIM finding"

        dkim_f = dkim_findings[0]
        assert dkim_f["severity"] == "info", (
            f"DKIM not-detected should be 'info', got '{dkim_f['severity']}'. "
            "Absent common selectors cannot confirm DKIM is unconfigured."
        )
        assert dkim_f["confidence"] == "low", (
            f"DKIM not-detected confidence should be 'low', got '{dkim_f.get('confidence')}'"
        )

    @pytest.mark.asyncio
    async def test_dkim_not_detected_evidence_contains_caveat(self):
        """Evidence string must mention that selector enumeration cannot prove absence."""
        from app.scanner.dns_checker import _analyze_dns_findings

        dns_info = {
            "a_records": ["93.184.216.34"],
            "mx_records": ["10 mail.example.com"],
            "txt_records": [],
            "ns_records": [],
            "spf": "v=spf1 -all",
            "dmarc": "v=DMARC1; p=reject",
            "dkim": None,
        }
        findings = _analyze_dns_findings("example.com", dns_info)
        dkim_f = next((f for f in findings if "DKIM" in f.get("title", "")), None)
        assert dkim_f is not None
        # Evidence should communicate that custom selector may exist
        assert "custom selector" in dkim_f["evidence"].lower() or \
               "does not confirm" in dkim_f["evidence"].lower() or \
               "cannot" in dkim_f["evidence"].lower(), (
            f"DKIM evidence does not mention selector enumeration limitation: {dkim_f['evidence']}"
        )

    @pytest.mark.asyncio
    async def test_dkim_detected_is_info_not_finding(self):
        """When a DKIM selector IS found, the finding should be info / passing control."""
        from app.scanner.dns_checker import _analyze_dns_findings

        dns_info = {
            "a_records": ["93.184.216.34"],
            "mx_records": ["10 mail.example.com"],
            "txt_records": [],
            "ns_records": [],
            "spf": "v=spf1 -all",
            "dmarc": "v=DMARC1; p=reject",
            "dkim": "google: v=DKIM1; k=rsa; p=MIIBIjANBg...",
        }
        findings = _analyze_dns_findings("example.com", dns_info)
        dkim_f = next((f for f in findings if "DKIM" in f.get("title", "")), None)
        assert dkim_f is not None
        assert dkim_f["severity"] == "info"
        assert dkim_f["confidence"] == "high"

    @pytest.mark.asyncio
    async def test_no_mx_records_no_dkim_finding(self):
        """If there are no MX records, DKIM absence is irrelevant — no finding."""
        from app.scanner.dns_checker import _analyze_dns_findings

        dns_info = {
            "a_records": ["93.184.216.34"],
            "mx_records": [],   # No mail → DKIM not relevant
            "txt_records": [],
            "ns_records": [],
            "spf": None,
            "dmarc": None,
            "dkim": None,
        }
        findings = _analyze_dns_findings("example.com", dns_info)
        dkim_findings = [f for f in findings if "DKIM" in f.get("title", "")]
        assert dkim_findings == [], (
            "DKIM finding should not be emitted when there are no MX records"
        )
