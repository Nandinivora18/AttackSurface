"""
Unit tests for Component Intelligence & Lifecycle Engine
=========================================================
Tests version normalization, vendor suffix stripping, confidence scoring,
lifecycle provider caching, offline fallback, and non-conflated finding generation.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.scanner.component_engine import (
    normalize_component_version,
    LifecycleProvider,
    assess_component,
    generate_component_findings,
    build_component_inventory,
    STATE_SUPPORTED,
    STATE_UPDATE_AVAILABLE,
    STATE_SECURITY_SUPPORT_ENDED,
    STATE_END_OF_LIFE,
    STATE_LIFECYCLE_UNKNOWN,
    STATE_VERSION_UNKNOWN,
    CONF_CONFIRMED,
    CONF_HIGH,
    CONF_MEDIUM,
    CONF_LOW,
    CONF_UNKNOWN,
)


class TestVersionNormalization:
    def test_ubuntu_package_suffix_stripped(self):
        norm = normalize_component_version("8.2.26-0ubuntu0.22.04.1", source="X-Powered-By")
        assert norm.normalized_version == "8.2.26"
        assert norm.vendor_suffix == "ubuntu0.22.04.1"
        assert norm.confidence == CONF_HIGH
        assert norm.is_semantic is True

    def test_apache_unix_suffix_stripped(self):
        norm = normalize_component_version("2.4.52 (Unix) OpenSSL/1.1.1m", source="Server")
        assert norm.normalized_version == "2.4.52"
        assert norm.confidence == CONF_HIGH
        assert norm.is_semantic is True

    def test_prefixed_v_normalized(self):
        norm = normalize_component_version("v1.28.0")
        assert norm.normalized_version == "1.28.0"
        assert norm.is_semantic is True

    def test_debian_sury_suffix_stripped(self):
        norm = normalize_component_version("7.4.33-1+deb.sury.org~jammy+1")
        assert norm.normalized_version == "7.4.33"
        assert norm.vendor_suffix is not None
        assert "deb.sury" in norm.vendor_suffix or "sury" in norm.vendor_suffix
        assert norm.is_semantic is True

    def test_empty_or_none_version(self):
        norm1 = normalize_component_version(None)
        assert norm1.normalized_version is None
        assert norm1.confidence == CONF_UNKNOWN
        assert norm1.is_semantic is False

        norm2 = normalize_component_version("")
        assert norm2.normalized_version is None
        assert norm2.confidence == CONF_UNKNOWN
        assert norm2.is_semantic is False

    def test_single_number_not_full_semver(self):
        norm = normalize_component_version("2")
        assert norm.normalized_version == "2"
        assert norm.is_semantic is False
        assert norm.confidence == CONF_LOW


@pytest.mark.asyncio
class TestLifecycleProvider:
    async def test_eol_detection_local_db(self):
        # PHP 5.6 is well-documented EOL in local DB
        provider = LifecycleProvider(redis_client=None)
        # Mock upstream network failure to guarantee local DB fallback
        with patch("httpx.AsyncClient.get", side_effect=Exception("Offline")):
            res = await provider.get_lifecycle("PHP", "5.6.40")
            assert res["status"] == STATE_END_OF_LIFE
            assert res["eol_date"] is not None

    async def test_supported_version_local_db(self):
        provider = LifecycleProvider(redis_client=None)
        with patch("httpx.AsyncClient.get", side_effect=Exception("Offline")):
            res = await provider.get_lifecycle("Python", "3.12.0")
            assert res["status"] in (STATE_SUPPORTED, STATE_UPDATE_AVAILABLE)

    async def test_unknown_technology_local_db(self):
        provider = LifecycleProvider(redis_client=None)
        with patch("httpx.AsyncClient.get", side_effect=Exception("Offline")):
            res = await provider.get_lifecycle("SuperCustomEngine", "1.0.0")
            assert res["status"] == STATE_LIFECYCLE_UNKNOWN

    async def test_none_version_returns_version_unknown(self):
        provider = LifecycleProvider(redis_client=None)
        res = await provider.get_lifecycle("Apache", None)
        assert res["status"] == STATE_VERSION_UNKNOWN
        assert res["eol_date"] is None

    async def test_redis_caching(self):
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None  # cache miss on first call
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {"cycle": "8.1", "eol": "2024-11-25", "latest": "8.1.31", "support": False}
        ]

        provider = LifecycleProvider(redis_client=mock_redis)
        with patch("httpx.AsyncClient.get", return_value=mock_response):
            res = await provider.get_lifecycle("php", "8.1.2")
            assert res["status"] in (STATE_END_OF_LIFE, STATE_SECURITY_SUPPORT_ENDED)
            # Verify cached into Redis
            mock_redis.setex.assert_called_once()


class TestComponentFindingsGeneration:
    def test_eol_finding_contains_backport_notice(self):
        assessment = assess_component(
            tech_name="PHP",
            raw_version="8.0.28-0ubuntu0.20.04.3",
            category="Programming Language",
            source="X-Powered-By",
            evidence="PHP/8.0.28-0ubuntu0.20.04.3",
            lifecycle_info={"status": STATE_END_OF_LIFE, "eol_date": "2023-11-26"},
        )
        findings = generate_component_findings(assessment)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "high"
        assert "End of Life" in f["title"]
        assert "backport" in f["description"].lower()

    def test_update_available_finding(self):
        assessment = assess_component(
            tech_name="Nginx",
            raw_version="1.24.0",
            category="Web Server",
            source="Server",
            evidence="nginx/1.24.0",
            lifecycle_info={"status": STATE_UPDATE_AVAILABLE, "latest_version": "1.26.2"},
        )
        findings = generate_component_findings(assessment)
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"
        assert "Update Available: 1.26.2" in findings[0]["title"]

    def test_supported_version_emits_no_failure_findings(self):
        assessment = assess_component(
            tech_name="Nginx",
            raw_version="1.26.2",
            category="Web Server",
            source="Server",
            evidence="nginx/1.26.2",
            lifecycle_info={"status": STATE_SUPPORTED, "latest_version": "1.26.2"},
        )
        findings = generate_component_findings(assessment)
        assert len(findings) == 0


@pytest.mark.asyncio
class TestBuildComponentInventory:
    async def test_build_inventory_multiple_techs(self):
        techs = {
            "PHP": {"version": "8.1.2-1ubuntu2.14", "category": "Language", "source": "Header"},
            "Apache": {"version": "2.4.52", "category": "Web Server", "source": "Server"},
            "jQuery": {"version": "3.6.0", "category": "JavaScript Library", "source": "Script"},
        }
        cves = [
            {"title": "CVE-2022-31625: Buffer Overflow in PHP", "description": "PHP issue", "severity": "high"}
        ]
        
        with patch("httpx.AsyncClient.get", side_effect=Exception("Offline")):
            inventory, findings = await build_component_inventory(techs, cves, redis_client=None)
            assert len(inventory) == 3
            php_item = next(item for item in inventory if item["technology"] == "PHP")
            assert php_item["normalized_version"] == "8.1.2"
            assert php_item["vendor_suffix"] == "1ubuntu2.14"
            assert php_item["cve_count"] == 1
