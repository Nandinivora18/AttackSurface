"""
Regression tests for the passive scan public port policy (F2).

Verifies:
- port_policy_error(): only 80 and 443 are permitted, scheme/port mismatches
  are rejected deterministically, and the rejection message is exact
- validate_url_target() / _pin_target(): worker-side defense-in-depth rejects
  denied ports before any DNS work or connection attempt
- safe_fetch_http(): target URLs with denied ports never dial the network
- ScanCreate (API schema): port policy is enforced at request-validation time,
  before a scan can be persisted or enqueued
"""
import pytest
from pydantic import ValidationError

from app.schemas.scan import ScanCreate
from app.utils.safe_http import (
    PORT_POLICY_MESSAGE,
    _pin_target,
    async_resolve_and_pin,
    port_policy_error,
    safe_fetch_http,
    validate_url_target,
)

MISMATCH_HTTP_443 = "URL scheme 'http' cannot use port 443; use https:// for port 443."
MISMATCH_HTTPS_80 = "URL scheme 'https' cannot use port 80; use http:// for port 80."

# Public IP literals so validation needs no DNS and no live network.
PUBLIC_IP = "93.184.216.34"


# ---------------------------------------------------------------------------
# port_policy_error() unit behavior
# ---------------------------------------------------------------------------
def test_policy_allows_implicit_and_well_known_ports():
    assert port_policy_error("http", None) is None
    assert port_policy_error("http", 80) is None
    assert port_policy_error("https", None) is None
    assert port_policy_error("https", 443) is None


def test_policy_rejects_non_web_ports():
    for scheme in ("http", "https"):
        for denied in (22, 8080, 5432, 6379, 11211, 0, 65535):
            assert port_policy_error(scheme, denied) == PORT_POLICY_MESSAGE


def test_policy_rejects_scheme_port_mismatch_deterministically():
    assert port_policy_error("http", 443) == MISMATCH_HTTP_443
    assert port_policy_error("https", 80) == MISMATCH_HTTPS_80


# ---------------------------------------------------------------------------
# Worker-side defense-in-depth: validate_url_target
# ---------------------------------------------------------------------------
def test_validate_allows_public_url_without_port():
    ok, reason, sanitized = validate_url_target(f"https://{PUBLIC_IP}/")
    assert ok is True
    assert reason == ""
    assert sanitized == f"https://{PUBLIC_IP}/"


def test_validate_allows_explicit_http_80_and_https_443():
    ok, _, _ = validate_url_target(f"http://{PUBLIC_IP}:80/")
    assert ok is True
    ok2, _, _ = validate_url_target(f"https://{PUBLIC_IP}:443/")
    assert ok2 is True


def test_validate_rejects_non_web_port():
    ok, reason, _ = validate_url_target(f"https://{PUBLIC_IP}:8443/")
    assert ok is False
    assert reason == PORT_POLICY_MESSAGE


def test_validate_rejects_scheme_port_mismatch():
    ok, reason, _ = validate_url_target(f"http://{PUBLIC_IP}:443/")
    assert ok is False
    assert reason == MISMATCH_HTTP_443
    ok2, reason2, _ = validate_url_target(f"https://{PUBLIC_IP}:80/")
    assert ok2 is False
    assert reason2 == MISMATCH_HTTPS_80


def test_validate_rejects_scheme_less_url_with_port():
    ok, reason, _ = validate_url_target(f"{PUBLIC_IP}:8080")
    assert ok is False
    assert reason == PORT_POLICY_MESSAGE


def test_validate_rejects_denied_port_before_dns_work():
    # Hostname is unresolvable, yet the port-is-rejected error surfaces first,
    # proving no resolution is attempted for denied ports.
    ok, reason, _ = validate_url_target("https://this-host-does-not-exist.invalid:8443/")
    assert ok is False
    assert reason == PORT_POLICY_MESSAGE


# ---------------------------------------------------------------------------
# Worker-side defense-in-depth: _pin_target / async_resolve_and_pin
# ---------------------------------------------------------------------------
def test_pin_target_rejects_denied_port():
    ok, reason, _, _, _ = _pin_target(f"https://{PUBLIC_IP}:8080/")
    assert ok is False
    assert reason == PORT_POLICY_MESSAGE


def test_pin_target_rejects_scheme_port_mismatch():
    ok, reason, _, _, _ = _pin_target(f"http://{PUBLIC_IP}:443/")
    assert ok is False
    assert reason == MISMATCH_HTTP_443


@pytest.mark.asyncio
async def test_async_resolve_and_pin_rejects_denied_port_async():
    ok, reason, _, _, _ = await async_resolve_and_pin(f"https://{PUBLIC_IP}:22/")
    assert ok is False
    assert reason == PORT_POLICY_MESSAGE


@pytest.mark.asyncio
async def test_safe_fetch_http_never_dials_denied_port():
    # A non-existent host proves the request never reaches the network: the
    # port gate fires before resolution or connection.
    response, err = await safe_fetch_http(f"https://{PUBLIC_IP}:8443/")
    assert response is None
    assert err == PORT_POLICY_MESSAGE


# ---------------------------------------------------------------------------
# API-level gate: ScanCreate port policy (before scan is persisted/enqueued)
# ---------------------------------------------------------------------------
def test_scancreate_allows_public_urls():
    scan = ScanCreate(url="https://example.com")
    assert scan.url == "https://example.com"
    assert ScanCreate(url="https://example.com:443").url == "https://example.com:443"
    assert ScanCreate(url="http://example.com:80").url == "http://example.com:80"


def test_scancreate_rejects_non_web_port():
    with pytest.raises(ValidationError) as exc:
        ScanCreate(url="https://example.com:8443")
    assert PORT_POLICY_MESSAGE in str(exc.value)


def test_scancreate_rejects_scheme_port_mismatch():
    with pytest.raises(ValidationError):
        ScanCreate(url="http://example.com:443")
    with pytest.raises(ValidationError):
        ScanCreate(url="https://example.com:80")


def test_scancreate_rejects_scheme_less_url_with_port():
    with pytest.raises(ValidationError) as exc:
        ScanCreate(url="example.com:8080")
    assert PORT_POLICY_MESSAGE in str(exc.value)


def test_scancreate_rejects_out_of_range_port():
    with pytest.raises(ValidationError) as exc:
        ScanCreate(url="https://example.com:99999")
    assert "port out of range" in str(exc.value)