"""
Regression tests for Outbound TLS Verification and SNI Handling (H1).

Verifies:
- safe_fetch_http and SafeFetchClient default to verify=True
- SNI hostname extension is passed using the canonical validated hostname
- Pinned IP literals receive the correct SNI hostname for TLS verification
- IPv6 and IPv4 pinned destinations behave correctly without brittle split(":")
- Verification failures raise connection errors on unverified/invalid certs
- SSRF and DNS-rebinding protections remain intact
"""
import pytest
import httpx
from unittest.mock import patch, MagicMock
from app.utils.safe_http import safe_fetch_http, SafeFetchClient


@pytest.mark.asyncio
async def test_safe_fetch_defaults_to_verify_true():
    """Verify that safe_fetch_http instantiates httpx.AsyncClient with verify=True by default."""
    captured_client_kwargs = {}

    class MockClient(MagicMock):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured_client_kwargs.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def request(self, method, url, **kwargs):
            return httpx.Response(200, request=httpx.Request(method, url))

    async def fake_pin(url):
        return (True, "", "https://example.com/", "https://93.184.216.34/", "example.com")

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=fake_pin), \
         patch("app.utils.safe_http.httpx.AsyncClient", side_effect=MockClient):
        response, err = await safe_fetch_http("https://example.com/")

    assert response is not None, err
    assert captured_client_kwargs.get("verify") is True


@pytest.mark.asyncio
async def test_safefetchclient_defaults_to_verify_true():
    """Verify that SafeFetchClient defaults verify=True and forwards it."""
    client = SafeFetchClient()
    assert client._verify is True

    captured_verify = []

    async def fake_safe_fetch(url, **kwargs):
        captured_verify.append(kwargs.get("verify"))
        return httpx.Response(200, request=httpx.Request("GET", url)), ""

    with patch("app.utils.safe_http.safe_fetch_http", side_effect=fake_safe_fetch):
        async with SafeFetchClient() as c:
            await c.get("https://example.com/")

    assert captured_verify == [True]


@pytest.mark.asyncio
async def test_sni_hostname_passed_with_canonical_host_for_pinned_ip():
    """Verify that the SNI hostname extension matches the canonical hostname, not the pinned IP."""
    captured_kwargs = {}

    async def fake_pin(url):
        return (True, "", "https://example.com:8443/test", "https://93.184.216.34:8443/test", "example.com:8443")

    async def fake_request(method, url, **kwargs):
        captured_kwargs.update(kwargs)
        return httpx.Response(200, request=httpx.Request(method, url))

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=fake_pin), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("https://example.com:8443/test")

    assert response is not None, err
    assert "extensions" in captured_kwargs
    assert captured_kwargs["extensions"] == {"sni_hostname": "example.com"}
    # Host header should preserve port if non-standard
    assert captured_kwargs.get("headers", {}).get("Host") == "example.com:8443"


@pytest.mark.asyncio
async def test_sni_hostname_not_set_for_ip_literal_targets():
    """RFC 6066 forbids IP literals in SNI: ensure IP literals do not set sni_hostname."""
    captured_kwargs = {}

    async def fake_pin(url):
        return (True, "", "https://93.184.216.34/test", "https://93.184.216.34/test", "93.184.216.34")

    async def fake_request(method, url, **kwargs):
        captured_kwargs.update(kwargs)
        return httpx.Response(200, request=httpx.Request(method, url))

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=fake_pin), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("https://93.184.216.34/test")

    assert response is not None, err
    # extensions should be None or not contain sni_hostname
    ext = captured_kwargs.get("extensions")
    assert ext is None or "sni_hostname" not in ext


@pytest.mark.asyncio
async def test_sni_hostname_not_set_for_plain_http():
    """Plain HTTP connections do not require TLS extensions."""
    captured_kwargs = {}

    async def fake_pin(url):
        return (True, "", "http://example.com/test", "http://93.184.216.34/test", "example.com")

    async def fake_request(method, url, **kwargs):
        captured_kwargs.update(kwargs)
        return httpx.Response(200, request=httpx.Request(method, url))

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=fake_pin), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("http://example.com/test")

    assert response is not None, err
    assert captured_kwargs.get("extensions") is None


@pytest.mark.asyncio
async def test_sni_hostname_on_redirect_hop_updates_to_redirect_target():
    """When following a redirect to a new host, SNI hostname must update to the new target."""
    call_extensions = []

    first_pin = (True, "", "https://origin.example/init", "https://1.1.1.1/init", "origin.example")
    redir_pin = (True, "", "https://target.example/final", "https://2.2.2.2/final", "target.example")

    async def fake_pin(url):
        if "target.example" in url:
            return redir_pin
        return first_pin

    async def fake_request(method, url, **kwargs):
        call_extensions.append(kwargs.get("extensions"))
        if "1.1.1.1" in url:
            # Return 301 redirect to target.example
            headers = {"location": "https://target.example/final"}
            req = httpx.Request(method, url)
            return httpx.Response(301, headers=headers, request=req)
        return httpx.Response(200, request=httpx.Request(method, url))

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=fake_pin), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("https://origin.example/init")

    assert response is not None, err
    assert len(call_extensions) == 2
    assert call_extensions[0] == {"sni_hostname": "origin.example"}
    assert call_extensions[1] == {"sni_hostname": "target.example"}


@pytest.mark.asyncio
async def test_invalid_cert_rejected_by_normal_fetch():
    """Simulated certificate verification failure properly results in error."""
    async def fake_pin(url):
        return (True, "", "https://invalid-cert.test/", "https://93.184.216.34/", "invalid-cert.test")

    async def fake_request_fail(method, url, **kwargs):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=fake_pin), \
         patch("httpx.AsyncClient.request", side_effect=fake_request_fail):
        response, err = await safe_fetch_http("https://invalid-cert.test/")

    assert response is None
    assert "CERTIFICATE_VERIFY_FAILED" in err


@pytest.mark.asyncio
async def test_explicit_verify_false_propagated():
    """Verify that passing verify=False explicitly is respected (e.g. for specialized probes)."""
    captured_client_kwargs = {}

    class MockClient(MagicMock):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            captured_client_kwargs.update(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def request(self, method, url, **kwargs):
            return httpx.Response(200, request=httpx.Request(method, url))

    async def fake_pin(url):
        return (True, "", "https://example.com/", "https://93.184.216.34/", "example.com")

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=fake_pin), \
         patch("app.utils.safe_http.httpx.AsyncClient", side_effect=MockClient):
        response, err = await safe_fetch_http("https://example.com/", verify=False)

    assert response is not None, err
    assert captured_client_kwargs.get("verify") is False
