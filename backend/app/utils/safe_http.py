"""
Safe HTTP Client & SSRF Safeguard Layer for SentinelScan
Enforces per-hop IP resolution validation, manual redirect safety, credentials stripping,
and protection against DNS rebinding and TOCTOU vulnerabilities.

Design note:
  validate_url_target()        — synchronous (kept for tests and sync callers)
  resolve_and_validate_host()  — sync hostname → (safe, reason, resolved_ips);
                                  single authoritative DNS + IP validation.
  async_validate_url_target()  — async wrapper; runs blocking DNS off the event loop
                                  via asyncio.to_thread(). Use this in all async paths.
  async_resolve_and_pin()      — validate + IP-pin the connection destination
                                  (defeats DNS-rebinding TOCTOU); returns the
                                  validated-IP connection URL + original Host.
  safe_fetch_http()            — async; uses async_resolve_and_pin internally.
  SafeFetchClient              — async context manager drop-in for httpx.AsyncClient
                                  that routes every get() through safe_fetch_http.

Fail-closed policy: any DNS resolution error, unexpected exception, or non-public
resolved address rejects the target. Connection is never attempted on rejection.
"""

import asyncio
import socket
import ipaddress
from urllib.parse import urlparse, urljoin
import httpx
from typing import Tuple, Optional, Dict, List


FORBIDDEN_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private IPv4
    ipaddress.ip_network("172.16.0.0/12"),     # Private IPv4
    ipaddress.ip_network("192.168.0.0/16"),    # Private IPv4
    ipaddress.ip_network("169.254.0.0/16"),    # Link-Local / Cloud Metadata
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("0.0.0.0/8"),         # Unspecified
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT / Shared address space
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmarking
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (documentation)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (documentation)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (documentation)
    ipaddress.ip_network("255.255.255.255/32"),# Limited broadcast
    ipaddress.ip_network("::1/128"),           # IPv6 Loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-Local
    ipaddress.ip_network("ff00::/8"),          # IPv6 Multicast
]

# Hostname literals that must never be treated as external targets.
LOCALHOST_ALIASES = {
    "localhost", "localhost.localdomain", "local", "loopback", "internal",
    "ip6-localhost", "ip6-loopback", "metadata", "metadata.google.internal",
}


# RFC 6052 IPv4/IPv6 translation Well-Known Prefix (NAT64 / DNS64)
NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")


def validate_ip_address(ip_str: str) -> Tuple[bool, str]:
    """Check if an IP string belongs to any forbidden loopback/private/link-local/multicast range."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)

        # Check IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        # Check IPv4/IPv6 translation NAT64 Well-Known Prefix (RFC 6052 64:ff9b::/96)
        elif isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in NAT64_PREFIX:
            # Extract the embedded IPv4 from the lowest 32 bits
            ip_obj = ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)

        for net in FORBIDDEN_IP_NETWORKS:
            if ip_obj in net:
                return False, f"Destination IP {ip_str} falls within restricted network {net}."

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False, f"Destination IP {ip_str} is private, loopback, or reserved."

        return True, ""
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"


def resolve_and_validate_host(hostname: str) -> Tuple[bool, str, List[str]]:
    """
    Single authoritative hostname → IP validation routine.

    Resolves the hostname (or parses an IP literal) and validates EVERY resolved
    destination. Fail-closed: any DNS failure, unexpected error, or non-public
    resolved IP rejects the target, and the failure reason is returned for
    surfacing to the user / report.

    Returns (is_safe, reason, resolved_ips).
    """
    hostname = (hostname or "").strip().strip("[]").lower()
    if not hostname:
        return False, "URL contains no valid host destination.", []

    if hostname in LOCALHOST_ALIASES:
        return False, f"Target '{hostname}' resolves to a local loopback address.", []

    resolved_ips: List[str] = []

    # Fast path: hostname is a direct IP literal (IPv4/IPv6/IPv4-mapped).
    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        ip_obj = None
    if ip_obj is not None:
        valid, reason = validate_ip_address(hostname)
        if not valid:
            return False, reason, []
        return True, "", [hostname]

    # Hostname path — resolve via system resolver.
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        # NXDOMAIN / SERVFAIL / resolver timeout — fail closed.
        return False, (
            f"Target hostname '{hostname}' could not be resolved. "
            "Please verify the URL is correct and the domain exists."
        ), []
    except Exception as e:
        # Unexpected resolver failure — fail closed rather than guessing.
        return False, (
            f"Target hostname '{hostname}' could not be resolved "
            f"({type(e).__name__}: {e})."
        ), []

    if not addresses:
        return False, f"Could not resolve IP for hostname '{hostname}'.", []

    for _family, _type, _proto, _canonname, sockaddr in addresses:
        ip_str = sockaddr[0]
        resolved_ips.append(ip_str)
        valid, reason = validate_ip_address(ip_str)
        if not valid:
            return False, f"Host '{hostname}' resolves to a non-public destination: {reason}", resolved_ips

    return True, "", resolved_ips


def validate_url_target(url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Parse URL scheme, strip credentials, and resolve hostname to validate IP destinations.
    Returns (is_valid, error_reason, sanitized_url).
    """
    raw = url.strip()
    if any(raw.startswith(s) for s in ("file://", "ftp://", "gopher://", "dict://")):
        scheme = raw.split("://")[0]
        return False, f"Forbidden URL scheme '{scheme}'. Only http and https are allowed.", None

    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        parsed = urlparse(raw)
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}", None

    if parsed.scheme not in ("http", "https"):
        return False, f"Forbidden URL scheme '{parsed.scheme}'. Only http and https are allowed.", None

    if parsed.username or parsed.password:
        return False, "URLs containing embedded user authentication credentials are not allowed.", None

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "URL contains no valid host destination.", None

    safe, reason, _ = resolve_and_validate_host(hostname)
    if not safe:
        return False, reason, None

    # Build sanitized URL without credentials
    try:
        port = parsed.port
    except ValueError:
        return False, f"Malformed URL: port out of range 0-65535 in '{raw}'.", None
    port_str = f":{port}" if port and port not in (80, 443) else ""
    sanitized = f"{parsed.scheme}://{hostname}{port_str}{parsed.path or '/'}"
    if parsed.query:
        sanitized += f"?{parsed.query}"

    return True, "", sanitized


async def async_validate_url_target(url: str) -> Tuple[bool, str, Optional[str]]:
    """
    Async-safe wrapper around validate_url_target.

    Runs the blocking socket.getaddrinfo call inside asyncio.to_thread() so
    the FastAPI / scanner event loop is never blocked — even when DNS is slow.

    The sync validate_url_target is the single source of SSRF logic.
    This wrapper does NOT duplicate that logic.
    """
    return await asyncio.to_thread(validate_url_target, url)


def _pin_target(url: str) -> Tuple[bool, str, Optional[str], Optional[str], Optional[str]]:
    """
    Validate URL AND pin the connection destination to a validated public IP.

    DNS rebinding defence: validate_url_target() resolves and validates the
    hostname, but an HTTP client that is handed the hostname URL performs its
    OWN DNS lookup at connect time — allowing an attacker-controlled hostname
    to resolve to a public IP during validation and a private/metadata IP when
    the client connects (classic TOCTOU).

    This helper returns a connection URL that uses the validated IP literal so
    the HTTP client cannot re-resolve the hostname, plus the original Host
    header value (hostname[:port]) to preserve server-name routing semantics.

    Returns (is_safe, reason, canonical_url, pinned_connection_url, host_header).
    canonical_url keeps the original hostname and is used for redirect base
    resolution / loop detection; pinned_connection_url is what the client dials.
    """
    raw = url.strip()
    if any(raw.startswith(s) for s in ("file://", "ftp://", "gopher://", "dict://")):
        scheme = raw.split("://")[0]
        return False, f"Forbidden URL scheme '{scheme}'. Only http and https are allowed.", None, None, None

    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw

    try:
        parsed = urlparse(raw)
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}", None, None, None

    if parsed.scheme not in ("http", "https"):
        return False, f"Forbidden URL scheme '{parsed.scheme}'. Only http and https are allowed.", None, None, None

    if parsed.username or parsed.password:
        return False, "URLs containing embedded user authentication credentials are not allowed.", None, None, None

    try:
        port = parsed.port
    except ValueError:
        return False, f"Malformed URL: port out of range 0-65535 in '{raw}'.", None, None, None

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, "URL contains no valid host destination.", None, None, None

    safe, reason, resolved_ips = resolve_and_validate_host(hostname)
    if not safe or not resolved_ips:
        return False, reason, None, None, None

    ip = resolved_ips[0]
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"Invalid destination IP '{ip}' for host '{hostname}'.", None, None, None

    ip_literal = f"[{ip}]" if isinstance(ip_obj, ipaddress.IPv6Address) else ip
    port_str = f":{port}" if port and port not in (80, 443) else ""
    canonical = f"{parsed.scheme}://{hostname}{port_str}{parsed.path or '/'}"
    pinned = f"{parsed.scheme}://{ip_literal}{port_str}{parsed.path or '/'}"
    if parsed.query:
        canonical += f"?{parsed.query}"
        pinned += f"?{parsed.query}"

    host_header = f"{hostname}:{port}" if port and port not in (80, 443) else hostname
    return True, "", canonical, pinned, host_header


async def async_resolve_and_pin(url: str) -> Tuple[bool, str, Optional[str], Optional[str], Optional[str]]:
    """
    Async-safe wrapper around _pin_target (runs blocking DNS off the event loop).

    Returns (is_safe, reason, canonical_url, pinned_connection_url, host_header).
    See _pin_target for the DNS-rebinding rationale.
    """
    return await asyncio.to_thread(_pin_target, url)


def pin_same_host(target_url: str, conn_url: str) -> str:
    """
    Re-pin a same-origin URL (different path/query) to an already-validated
    connection URL: swap the target's scheme+host[:port] for the pinned
    connection's, keeping the target's path and query. Used by scanners that
    validate a base URL once then fetch several same-host variants.
    """
    t = urlparse(target_url)
    c = urlparse(conn_url)
    rebuilt = urlparse(conn_url, scheme=t.scheme)
    return f"{rebuilt.scheme}://{rebuilt.netloc}{t.path or '/'}" + (f"?{t.query}" if t.query else "")


async def safe_fetch_http(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0,
    max_redirects: int = 5,
    user_agent: str = "SentinelScan-Security-Scanner/2.0",
    verify: bool = True,
) -> Tuple[Optional[httpx.Response], str]:
    """
    Performs safe HTTP fetching with per-redirect destination validation,
    protecting against SSRF redirects, loops, TOCTOU DNS rebinding, and
    IP pinning (the connection is always dialed to the validated public IP).

    Uses async_resolve_and_pin for every hop so DNS lookups never
    block the event loop and every hop is re-validated + re-pinned.

    Certificate verification defaults to True (system CA trust store).
    When connecting to pinned IP literals over HTTPS, the original canonical
    hostname is supplied via SNI extensions so certificate validation matches
    the intended target rather than the pinned IP address.
    """
    valid, reason, current_url, conn_url, host_header = await async_resolve_and_pin(url)
    if not valid or not conn_url or host_header is None:
        return None, reason

    req_headers = {"User-Agent": user_agent}
    if headers:
        req_headers.update(headers)

    visited_urls = set()
    redirect_count = 0
    redirect_chain: list[httpx.Response] = []

    async with httpx.AsyncClient(follow_redirects=False, timeout=timeout, verify=verify) as client:
        while redirect_count <= max_redirects:
            # Loop detection on the canonical (hostname) URL keeps hosts stable
            # even though the pinned connection URL uses the validated IP.
            if current_url in visited_urls:
                return None, f"Redirect loop detected at '{current_url}'."
            visited_urls.add(current_url)

            # Re-validate + pin before each hop (async — non-blocking)
            valid, err_msg, current_url, conn_url, host_header = await async_resolve_and_pin(current_url)
            if not valid or not conn_url or host_header is None:
                return None, f"SSRF Security Violation on redirect hop: {err_msg}"

            hop_headers = dict(req_headers)
            hop_headers["Host"] = host_header

            # Preserve SNI and TLS certificate validation against the canonical hostname.
            # Reuses the canonical hostname already produced by SentinelScan's existing
            # URL/SSRF validation pipeline (not host_header.split(':')).
            req_extensions = {}
            canonical_host = urlparse(current_url).hostname
            if canonical_host and urlparse(conn_url).scheme == "https":
                is_ip = False
                try:
                    ipaddress.ip_address(canonical_host)
                    is_ip = True
                except (ValueError, TypeError):
                    is_ip = False
                if not is_ip:
                    req_extensions["sni_hostname"] = canonical_host

            try:
                response = await client.request(
                    method,
                    conn_url,
                    headers=hop_headers,
                    extensions=req_extensions if req_extensions else None,
                )
            except Exception as e:
                return None, f"Connection failure to '{current_url}': {str(e)}"

            # Handle Manual Redirects
            if response.status_code in (301, 302, 303, 307, 308):
                redirect_count += 1
                if redirect_count > max_redirects:
                    return None, f"Exceeded maximum redirect limit of {max_redirects} hops."

                location = response.headers.get("location")
                if not location:
                    response.history = redirect_chain
                    return response, ""

                new_url = urljoin(current_url, location)
                is_redir_safe, redir_err, redir_url, redir_conn, redir_host = await async_resolve_and_pin(new_url)
                if not is_redir_safe or not redir_conn or redir_host is None:
                    return None, f"SSRF Safeguard blocked redirect to '{new_url}': {redir_err}"

                redirect_chain.append(response)
                current_url = redir_url
                conn_url = redir_conn
                host_header = redir_host
                continue

            # Attach the followed redirect chain (ordered, oldest first) so callers
            # inspecting response.history (e.g. soft-404 detection) behave as if
            # httpx follow_redirects=True had been used.
            response.history = redirect_chain
            return response, ""

    return None, f"Exceeded maximum redirect limit of {max_redirects} hops."


class SafeFetchClient:
    """
    Async context manager drop-in for httpx.AsyncClient used by scanner modules.

    Every get() is routed through safe_fetch_http, so the initial target AND each
    redirect hop are SSRF-validated per-hop. On a rejected or unreachable
    destination it raises httpx.ConnectError (or httpx.TimeoutException for
    timeouts), matching the exception contract the scanner modules already handle.

    Unlike httpx.AsyncClient, redirects are followed automatically and the chain is
    exposed via response.history — identical to follow_redirects=True semantics.
    """

    def __init__(
        self,
        timeout: float = 10.0,
        headers: Optional[Dict[str, str]] = None,
        max_redirects: int = 5,
        verify: bool = True,
    ):
        self._timeout = timeout
        self._headers = headers
        self._max_redirects = max_redirects
        self._verify = verify

    async def __aenter__(self) -> "SafeFetchClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False

    async def get(self, url: str) -> httpx.Response:
        response, err = await safe_fetch_http(
            url,
            headers=self._headers,
            timeout=self._timeout,
            max_redirects=self._max_redirects,
            verify=self._verify,
        )
        if response is None:
            if "timeout" in err.lower() or "timed out" in err.lower():
                raise httpx.TimeoutException(err)
            raise httpx.ConnectError(err)
        return response
