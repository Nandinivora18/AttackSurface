"""
SSRF Protection & Target Security Unit Tests
"""

import pytest
import httpx
import ipaddress
from unittest.mock import patch
from app.utils.safe_http import validate_ip_address, validate_url_target, safe_fetch_http


def test_ssrf_forbidden_ip_addresses():
    forbidden_ips = [
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "10.255.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "169.254.169.254",  # AWS / Cloud Metadata
        "224.0.0.1",        # Multicast
        "0.0.0.0",          # Unspecified
        "::1",              # IPv6 Loopback
        "fc00::1",          # IPv6 Unique Local (private)
        "fe80::1",          # IPv6 Link-Local
        "ff02::1",          # IPv6 Multicast
        "::ffff:127.0.0.1", # IPv4-mapped IPv6 loopback
        "::ffff:169.254.169.254", # IPv4-mapped IPv6 metadata
        "::ffff:10.0.0.1",  # IPv4-mapped IPv6 private
    ]

    for ip in forbidden_ips:
        valid, reason = validate_ip_address(ip)
        assert valid is False, f"Expected {ip} to be rejected, but passed: {reason}"


def test_ssrf_forbidden_non_public_networks():
    """CGNAT, benchmarking, and TEST-NET ranges are non-public destinations."""
    non_public_ips = [
        "100.64.0.1",      # CGNAT / shared address space
        "100.127.255.254", # CGNAT
        "198.18.0.1",      # Benchmarking
        "198.19.255.254",  # Benchmarking
        "192.0.0.9",       # IETF protocol assignment (PCP anycast)
        "192.0.2.1",       # TEST-NET-1
        "198.51.100.1",    # TEST-NET-2
        "203.0.113.1",     # TEST-NET-3
        "255.255.255.255", # Limited broadcast
    ]

    for ip in non_public_ips:
        valid, reason = validate_ip_address(ip)
        assert valid is False, f"Expected {ip} to be rejected, but passed: {reason}"


def test_resolve_and_validate_host_blocks_localhost_aliases():
    from app.utils.safe_http import resolve_and_validate_host
    for host in ("localhost", "localhost.localdomain", "internal", "loopback", "metadata"):
        safe, reason, ips = resolve_and_validate_host(host)
        assert safe is False, f"Expected {host} to be rejected, got: {reason}"


def test_resolve_and_validate_host_allows_public():
    from app.utils.safe_http import resolve_and_validate_host
    safe, reason, ips = resolve_and_validate_host("example.com")
    assert safe is True, f"Expected example.com to be allowed, got: {reason}"
    assert len(ips) >= 1


def test_validate_url_target_fails_closed_on_dns_failure():
    """DNS resolution failure must reject the target (no connection attempted)."""
    valid, reason, clean = validate_url_target("https://this-domain-does-not-exist-xyz.invalid")
    assert valid is False
    assert "could not be resolved" in reason or "resolve" in reason.lower()
    assert clean is None


def test_ssrf_forbidden_urls():
    forbidden_urls = [
        "http://localhost",
        "http://127.0.0.1/admin",
        "http://127.0.0.1:8080",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "ftp://example.com/file.txt",
        "gopher://127.0.0.1:70",
        "http://admin:password@example.com/resource",
    ]

    for url in forbidden_urls:
        valid, reason, _ = validate_url_target(url)
        assert valid is False, f"Expected {url} to be rejected by SSRF validation, but passed: {reason}"


def test_ssrf_valid_public_urls():
    valid_urls = [
        "https://example.com",
        "http://example.com/about",
        "https://github.com/api/v3",
    ]

    for url in valid_urls:
        valid, reason, clean_url = validate_url_target(url)
        assert valid is True, f"Expected {url} to be valid, but failed: {reason}"
        assert clean_url is not None


# ─── Async SSRF regression tests ────────────────────────────────────────────────
# Verify the async path (_is_ssrf_safe_url in scans.py and async_validate_url_target
# in safe_http.py) preserves all existing blocking behavior.

@pytest.mark.asyncio
async def test_async_ssrf_blocks_loopback():
    """async_validate_url_target must block loopback URLs."""
    from app.utils.safe_http import async_validate_url_target
    valid, reason, _ = await async_validate_url_target("http://127.0.0.1/secret")
    assert valid is False
    assert "127.0.0.1" in reason or "loopback" in reason.lower() or "forbidden" in reason.lower()


@pytest.mark.asyncio
async def test_async_ssrf_blocks_localhost():
    """async_validate_url_target must block localhost."""
    from app.utils.safe_http import async_validate_url_target
    valid, reason, _ = await async_validate_url_target("http://localhost/admin")
    assert valid is False


@pytest.mark.asyncio
async def test_async_ssrf_blocks_private_ipv4():
    """async_validate_url_target must block private IPv4 ranges."""
    from app.utils.safe_http import async_validate_url_target
    private_urls = [
        "http://10.0.0.1/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
    ]
    for url in private_urls:
        valid, reason, _ = await async_validate_url_target(url)
        assert valid is False, f"Expected {url} to be blocked but was allowed. Reason: {reason}"


@pytest.mark.asyncio
async def test_async_ssrf_blocks_link_local_metadata():
    """async_validate_url_target must block cloud metadata (169.254.169.254)."""
    from app.utils.safe_http import async_validate_url_target
    valid, reason, _ = await async_validate_url_target("http://169.254.169.254/latest/meta-data/")
    assert valid is False


@pytest.mark.asyncio
async def test_async_ssrf_allows_public_hostname():
    """async_validate_url_target must allow genuine public hostnames."""
    from app.utils.safe_http import async_validate_url_target
    valid, reason, clean_url = await async_validate_url_target("https://example.com")
    assert valid is True, f"Expected example.com to be allowed, but got: {reason}"
    assert clean_url is not None


@pytest.mark.asyncio
async def test_async_ssrf_rejects_dns_failure():
    """DNS lookup failures must be rejected (fail-closed, no connection attempted).

    Verifies the synchronous DNS validation logic (_ssrf_check_blocking) that
    asyncio.to_thread delegates to. Patching inside to_thread threads is not
    reliable with unittest.mock, so we test the underlying function directly.
    """
    import socket as _socket
    from app.routers.scans import _ssrf_check_blocking
    # Patch getaddrinfo inside the scans module where _ssrf_check_blocking looks it up
    with patch("app.routers.scans.socket.getaddrinfo",
               side_effect=_socket.gaierror("NXDOMAIN")):
        # Note: call synchronously — this is the function asyncio.to_thread executes
        valid, reason = _ssrf_check_blocking("this-domain-does-not-exist-xyz.invalid")
    assert valid is False, f"Expected DNS failure to be rejected, got valid=True: {reason}"
    assert "could not be resolved" in reason or "resolve" in reason.lower()


@pytest.mark.asyncio
async def test_scans_router_ssrf_validator_is_async():
    """_is_ssrf_safe_url in scans.py must be an async coroutine (not sync)."""
    import inspect
    from app.routers.scans import _is_ssrf_safe_url
    assert inspect.iscoroutinefunction(_is_ssrf_safe_url), (
        "_is_ssrf_safe_url must be an async function to avoid blocking the event loop"
    )


@pytest.mark.asyncio
async def test_scans_router_ssrf_blocks_private():
    """_is_ssrf_safe_url in scans.py must block private IPs via asyncio.to_thread."""
    from app.routers.scans import _is_ssrf_safe_url
    safe, msg = await _is_ssrf_safe_url("http://192.168.0.1/")
    assert safe is False
    assert "192.168.0.1" in msg or "private" in msg.lower() or "internal" in msg.lower()


@pytest.mark.asyncio
async def test_scans_router_ssrf_allows_public():
    """_is_ssrf_safe_url in scans.py must allow public URLs."""
    from app.routers.scans import _is_ssrf_safe_url
    safe, msg = await _is_ssrf_safe_url("https://example.com")
    assert safe is True, f"Expected example.com to pass SSRF check, got: {msg}"


# ─── safe_fetch_http redirect safety tests ────────────────────────────────────
# Every redirect hop must be re-validated: a public start URL that redirects to a
# non-public destination must abort the fetch, legitimate public redirects must
# succeed, and loops must be detected.

def _mock_redirect_response(status_code: int, location: str, url: str) -> "httpx.Response":
    request = httpx.Request("GET", url)
    return httpx.Response(status_code, headers={"location": location}, request=request)


def _mock_ok_response(url: str) -> "httpx.Response":
    return httpx.Response(200, text="ok", request=httpx.Request("GET", url))


def _mock_pin_validator(private_substrings=("169.254.169.254", "192.168", "10.0", "internal")):
    """async_resolve_and_pin stand-in: rejects private/internal hosts, allows the rest.
    Returns (safe, reason, canonical_url, pinned_connection_url, host_header)."""
    from urllib.parse import urlparse

    async def fake(url: str):
        u = (url or "").lower()
        if any(s in u for s in private_substrings):
            return (False, f"Destination {u} is private/internal.", None, None, None)
        host = urlparse(url).hostname or ""
        return (True, "", url, url, host)

    return fake


@pytest.mark.asyncio
async def test_safe_fetch_blocks_public_to_private_redirect():
    """A public page redirecting to a cloud-metadata/private host must be blocked."""
    from app.utils.safe_http import safe_fetch_http

    responses = {
        "http://public.example/start": _mock_redirect_response(
            302, "http://169.254.169.254/latest/meta-data/", "http://public.example/start"
        ),
    }

    async def fake_request(method, url, **kwargs):
        return responses.get(url, _mock_ok_response(url))

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=_mock_pin_validator()), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("http://public.example/start")

    assert response is None, f"Expected blocked redirect, got response {response}"
    assert "blocked redirect" in err or "redirect" in err.lower()


@pytest.mark.asyncio
async def test_safe_fetch_allows_legitimate_public_redirect():
    """Public-to-public redirects are followed and exposed via response.history."""
    from app.utils.safe_http import safe_fetch_http

    responses = {
        "http://public.example/start": _mock_redirect_response(
            301, "https://final.example/page", "http://public.example/start"
        ),
        "https://final.example/page": _mock_ok_response("https://final.example/page"),
    }

    async def fake_request(method, url, **kwargs):
        return responses.get(url, _mock_ok_response(url))

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=_mock_pin_validator()), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("http://public.example/start")

    assert response is not None, err
    assert response.status_code == 200
    assert len(response.history) == 1


@pytest.mark.asyncio
async def test_safe_fetch_follows_multiple_public_redirect_hops():
    """Multiple consecutive public redirect hops are followed safely."""
    from app.utils.safe_http import safe_fetch_http

    responses = {
        "http://a.example/1": _mock_redirect_response(302, "/2", "http://a.example/1"),
        "http://a.example/2": _mock_redirect_response(301, "/3", "http://a.example/2"),
        "http://a.example/3": _mock_ok_response("http://a.example/3"),
    }

    async def fake_request(method, url, **kwargs):
        return responses.get(url, _mock_ok_response(url))

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=_mock_pin_validator()), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("http://a.example/1")

    assert response is not None, err
    assert response.status_code == 200
    assert len(response.history) == 2


@pytest.mark.asyncio
async def test_safe_fetch_detects_redirect_loop():
    """A redirect loop must abort the fetch instead of looping forever."""
    from app.utils.safe_http import safe_fetch_http

    responses = {
        "http://loop.example/a": _mock_redirect_response(302, "/b", "http://loop.example/a"),
        "http://loop.example/b": _mock_redirect_response(302, "/a", "http://loop.example/b"),
    }

    async def fake_request(method, url, **kwargs):
        return responses.get(url, _mock_ok_response(url))

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=_mock_pin_validator()), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("http://loop.example/a")

    assert response is None
    assert "Redirect loop detected" in err


def test_ssrf_nat64_prefix_validation():
    """Verify RFC 6052 NAT64 translated IPv6 addresses are validated based on the embedded IPv4."""
    # Public IPv4 translated via NAT64 (e.g. 103.20.212.130 -> 64:ff9b::6714:d482)
    valid, _ = validate_ip_address("64:ff9b::6714:d482")
    assert valid is True

    # Loopback translated via NAT64 (127.0.0.1 -> 64:ff9b::7f00:1)
    valid, reason = validate_ip_address("64:ff9b::7f00:1")
    assert valid is False
    assert "restricted network" in reason or "private" in reason or "loopback" in reason

    # Private IPv4 translated via NAT64 (10.0.0.1 -> 64:ff9b::a00:1)
    valid, reason = validate_ip_address("64:ff9b::a00:1")
    assert valid is False
    assert "restricted network" in reason or "private" in reason

    # Cloud metadata translated via NAT64 (169.254.169.254 -> 64:ff9b::a9fe:a9fe)
    valid, reason = validate_ip_address("64:ff9b::a9fe:a9fe")
    assert valid is False
    assert "restricted network" in reason or "private" in reason


# ─── Expanded IPv6 / address-translation boundary coverage ───────────────────
# Verify every textual representation that ipaddress or the OS resolver could
# normalize differently is classified against the ACTUAL bits that would be
# dialed (IPv4-compatible ::/96, IPv4-translated, 6to4, Teredo, doc ranges).

def test_ssrf_ipv4_compatible_ipv6_addresses_blocked():
    """Deprecated IPv4-compatible IPv6 (::a.b.c.d → ::/96) must be refused."""
    for ip in ("::127.0.0.1", "::10.0.0.1", "::169.254.169.254", "::192.168.1.1"):
        valid, reason = validate_ip_address(ip)
        assert valid is False, f"IPv4-compatible '{ip}' must be blocked: {reason}"


def test_ssrf_ipv4_translated_ipv6_addresses_blocked():
    """IPv4-translated (non-mapped) ::ffff:0:a.b.c.d must be refused."""
    valid, reason = validate_ip_address("::ffff:0:127.0.0.1")
    assert valid is False, reason


def test_ssrf_6to4_teredo_embedded_private_blocked():
    """6to4 (2002::/16) and Teredo (2001::/32) embedding private IPv4 refused."""
    for ip in ("2002:7f00:1::", "2002:a00:1::", "2001::7f00:1"):
        valid, reason = validate_ip_address(ip)
        assert valid is False, f"'{ip}' must be blocked: {reason}"


def test_ssrf_ipv6_documentation_range_blocked():
    """2001:db8::/32 (documentation, non-routable) is not a scan destination."""
    valid, reason = validate_ip_address("2001:db8::1")
    assert valid is False, reason


def test_ssrf_metadata_ipv4_mapped_variants_blocked():
    """The cloud-metadata host must be blocked in every mapped/compatible form."""
    for ip in ("169.254.169.254", "::ffff:169.254.169.254",
               "64:ff9b::a9fe:a9fe", "::a9fe:a9fe"):
        valid, reason = validate_ip_address(ip)
        assert valid is False, f"'{ip}' must be blocked: {reason}"


# ─── Port / malformed-target hardening ────────────────────────────────────────

def test_validate_url_target_rejects_out_of_range_port():
    """parsed.port raises ValueError for out-of-range ports — must fail closed, not 500."""
    valid, reason, clean = validate_url_target("http://example.com:99999/path")
    assert valid is False
    assert "port" in reason.lower()
    assert clean is None


def test_pin_target_rejects_out_of_range_port():
    from app.utils.safe_http import _pin_target
    valid, reason, canonical, conn, host = _pin_target("http://example.com:99999/path")
    assert valid is False
    assert "port" in reason.lower()
    assert conn is None and host is None


# ─── DNS-rebinding / TOCTOU boundary ──────────────────────────────────────────
# The fetchers must DIAL the validated IP literal, never hand the raw hostname
# to the HTTP client (which would re-resolve DNS at connect time and could be
# rebound to a private address).

def test_pin_target_builds_validated_ip_connection_url():
    """_pin_target returns an IP-literal connection URL + original Host header."""
    from app.utils.safe_http import _pin_target
    valid, reason, canonical, conn, host = _pin_target("https://example.com/about?q=1")
    assert valid is True, reason
    assert canonical == "https://example.com/about?q=1"
    from urllib.parse import urlparse
    cp = urlparse(conn)
    assert cp.scheme == "https"
    # The connection URL host must be the VALIDATED public IP literal, not the hostname
    ipaddress.ip_address(cp.hostname)  # must parse as a pure IP literal
    assert cp.hostname != "example.com"
    assert "/about" in conn and "q=1" in conn
    assert host == "example.com"


def test_pin_target_blocks_private_destination():
    from app.utils.safe_http import _pin_target
    valid, reason, canonical, conn, host = _pin_target("http://169.254.169.254/latest/meta-data/")
    assert valid is False
    assert conn is None


def test_pin_same_host_swaps_only_the_host():
    from app.utils.safe_http import pin_same_host
    out = pin_same_host("https://example.com/find?id=7", "https://93.184.216.34/")
    assert out == "https://93.184.216.34/find?id=7"


@pytest.mark.asyncio
async def test_safe_fetch_dials_validated_ip_not_hostname():
    """The HTTP client must receive the pinned IP URL + original Host header."""
    from app.utils.safe_http import safe_fetch_http

    async def fake_pin(url):
        return (True, "", "http://example.com/x", "http://93.184.216.34/x", "example.com")

    captured = {}

    async def fake_request(method, url, **kwargs):
        captured["url"] = url
        captured["host"] = kwargs.get("headers", {}).get("Host")
        return _mock_ok_response(url)

    with patch("app.utils.safe_http.async_resolve_and_pin", side_effect=fake_pin), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("http://example.com/x")

    assert response is not None, err
    assert captured["url"] == "http://93.184.216.34/x"   # validated IP is dialed
    assert captured["host"] == "example.com"             # original hostname preserved


@pytest.mark.asyncio
async def test_async_resolve_and_pin_blocks_private_and_returns_5_tuple():
    from app.utils.safe_http import async_resolve_and_pin
    valid, reason, canonical, conn, host = await async_resolve_and_pin("http://127.0.0.1/secret")
    assert valid is False
    assert conn is None and host is None


# ─── IPv6 representation-equivalence proofs (final pass) ─────────────────────
# Every textual form the OS resolver / ipaddress could normalize differently must
# be classified against the ACTUAL bits that would be dialed, BEFORE any connect.
# Covered sets: IPv4-mapped (::ffff:0:0/96), IPv4-compatible (::/96), NAT64,
# 6to4/Teredo, doc ranges — in dotted, hex, and fully-expanded notation.

def test_ssrf_ipv4_mapped_hex_and_long_forms_blocked():
    """IPv4-mapped IPv6 in hex and fully-expanded notation must be refused."""
    for ip in ("::ffff:7f00:1",            # ::ffff:127.0.0.1 (hex)
               "0:0:0:0:0:ffff:127.0.0.1", # fully expanded loopback
               "::ffff:a00:1",             # ::ffff:10.0.0.1 (hex)
               "0:0:0:0:0:ffff:169.254.169.254"):  # fully expanded metadata
        valid, reason = validate_ip_address(ip)
        assert valid is False, f"'{ip}' must be blocked: {reason}"


def test_ssrf_ipv4_compatible_hex_and_mixed_forms_blocked():
    """IPv4-compatible ::/96 (incl. hex) is the deprecated 127.0.0.1 form."""
    for ip in ("::127.0.0.1", "0:0:0:0:0:0:127.0.0.1", "::7f00:1",
               "::7f:1", "::10.1.2.3", "::169.254.169.254"):
        valid, reason = validate_ip_address(ip)
        assert valid is False, f"'{ip}' must be blocked: {reason}"


def test_resolve_and_validate_host_rejects_v4_compatible_and_mapped_literals():
    """The literal fast-path must reject the same forms the resolver path would."""
    from app.utils.safe_http import resolve_and_validate_host
    for ip in ("::127.0.0.1", "::10.0.0.1", "::169.254.169.254",
               "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254"):
        safe, reason, ips = resolve_and_validate_host(ip)
        assert safe is False, f"'{ip}' must be rejected: {reason}"


def test_pin_target_rejects_v4_compatible_and_mapped_literal_urls():
    """The connection-pinner (async_resolve_and_pin) must refuse every form."""
    from app.utils.safe_http import _pin_target
    for url in ("http://[::127.0.0.1]/",
                "http://[::10.0.0.1]/admin",
                "http://[::7f00:1]/",
                "https://[::ffff:127.0.0.1]/",
                "http://[::ffff:169.254.169.254]/latest/meta-data/",
                "http://[0:0:0:0:0:ffff:127.0.0.1]/"):
        valid, reason, canonical, conn, host = _pin_target(url)
        assert valid is False, f"'{url}' must be rejected: {reason}"
        assert conn is None and host is None, f"'{url}' must yield no connection URL"


@pytest.mark.asyncio
async def test_safe_fetch_never_constructs_http_client_for_restricted_literals():
    """Fail-closed proof: for every restricted literal the HTTP client context is
    never even entered — no socket is opened because validation rejects first."""
    from app.utils.safe_http import safe_fetch_http
    entered = []

    async def counting_enter(self):
        entered.append(self)
        return self

    async def fake_exit(self, exc_type, exc, tb):
        return False

    restricted = (
        "http://[::127.0.0.1]/", "http://[::10.0.0.1]/",
        "https://[::ffff:127.0.0.1]/", "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://localhost/x", "http://127.0.0.1/x",
    )
    with patch.object(httpx.AsyncClient, "__aenter__", counting_enter), \
         patch.object(httpx.AsyncClient, "__aexit__", fake_exit):
        for url in restricted:
            response, err = await safe_fetch_http(url)
            assert response is None, f"'{url}' must be blocked, got {response}"
            assert err, f"'{url}' must include a rejection reason"

    assert not entered, "The HTTP client must never be constructed for restricted targets"


# ─── Deterministic DNS-rebinding / TOCTOU proof (final pass) ──────────────────
# The validator resolves the hostname EXACTLY ONCE (to a public IP), and the
# connection URL handed to the HTTP client is that validated IP literal. Even if
# the authoritative DNS were to rebind to a private IP immediately afterward, the
# client could never dial it because the hostname is never re-resolved at connect
# time — verified with a mocked resolver that would return the metadata IP on a
# second lookup.

@pytest.mark.asyncio
async def test_dns_rebinding_connect_step_cannot_re_resolve_hostname():
    """Deterministic TOCTOU proof against DNS rebinding.

    Every connect in safe_fetch_http is preceded by an async_resolve_and_pin of
    the current URL, and the HTTP client is handed an IP-literal connection URL
    (never the hostname). Therefore:
      (1) with stable DNS the client dials the validated PUBLIC IP literal and
          the original hostname is preserved in the Host header;
      (2) if the attacker's DNS REBINDS the hostname to a private/metadata IP
          after the pre-loop validation, the pre-connect re-pin rejects it and
          the private IP is never dialed.
    """
    import socket as _socket
    from urllib.parse import urlparse
    from app.utils.safe_http import safe_fetch_http

    resolved_hostnames = []
    rebind_after_first = False

    def fake_getaddrinfo(host, port, *args, **kwargs):
        resolved_hostnames.append(host)
        if host == "rebind.example":
            # On the SECOND resolution (the pre-connect re-pin) the attacker
            # rebinds to the cloud-metadata IP.
            if rebind_after_first and resolved_hostnames.count("rebind.example") > 1:
                return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "",
                         ("169.254.169.254", port))]
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "",
                     ("93.184.216.34", port))]
        if host == "93.184.216.34":  # IP-literal resolution is a pass-through
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (host, port))]
        raise _socket.gaierror(f"{host}: Name or service not known")

    captured = {}

    async def fake_request(method, url, **kwargs):
        captured["url"] = url
        captured["host"] = (kwargs.get("headers") or {}).get("Host")
        return _mock_ok_response(url)

    # Phase 1 — stable DNS: the client dials the validated PUBLIC IP literal.
    with patch("app.utils.safe_http.socket.getaddrinfo", side_effect=fake_getaddrinfo), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response, err = await safe_fetch_http("http://rebind.example/x")

    assert response is not None, err
    dialed = urlparse(captured["url"])
    ipaddress.ip_address(dialed.hostname), "dialed URL must be a pure IP literal"
    assert dialed.hostname == "93.184.216.34", captured["url"]
    assert "169.254.169.254" not in captured["url"]
    assert captured["host"] == "rebind.example", "original Host header must be preserved"

    # Phase 2 — DNS rebind: second resolution yields the metadata IP. The
    # pre-connect re-pin must reject it; nothing may be dialed.
    resolved_hostnames.clear()
    captured.clear()
    rebind_after_first = True
    with patch("app.utils.safe_http.socket.getaddrinfo", side_effect=fake_getaddrinfo), \
         patch("httpx.AsyncClient.request", side_effect=fake_request):
        response2, err2 = await safe_fetch_http("http://rebind.example/x")

    assert response2 is None, "a rebound-to-private target must be rejected"
    assert not captured.get("url"), (
        "the rebound private IP must never be handed to the HTTP client"
    )


