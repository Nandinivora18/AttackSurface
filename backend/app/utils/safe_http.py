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
  BoundedAsyncClient           — httpx.AsyncClient subclass that bounds every
                                  fully-buffered response body at
                                  MAX_HTTP_RESPONSE_BYTES (see read_body_bounded).

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


# Maximum response body any scanner HTTP client may materialize in memory.
# Conservative 1 MiB cap (aligned with the crawler's existing max_response_size
# default); a body larger than this is truncated and flagged rather than fully
# buffered. Applied centrally in BoundedAsyncClient so every scanner fetch is
# covered regardless of which client class the module constructs.
MAX_HTTP_RESPONSE_BYTES = 1_048_576

# Passive scan port policy: only standard web ports (HTTP 80 / HTTPS 443)
# are ever contacted. Ports implied by the scheme are allowed implicitly; any
# other explicit port is rejected before resolution or connection is attempted.
PORT_POLICY_MESSAGE = "Only HTTP/HTTPS web ports 80 and 443 are supported."


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


def port_policy_error(scheme: str, port: Optional[int]) -> Optional[str]:
    """
    Enforce the passive scanner's public port policy (HTTP 80 / HTTPS 443 only).

    Returns a user-facing rejection reason when the URL uses a denied port, or
    None when the request should be permitted. Centralized so the API schema,
    validate_url_target(), and _pin_target() can never drift apart.

    Scheme/port mismatches (http://host:443, https://host:80) are rejected
    deterministically rather than silently rewritten, because changing the
    effective scheme of a scanned URL would change its TLS expectations.
    """
    if port is None:
        return None
    if port not in (80, 443):
        return PORT_POLICY_MESSAGE
    if scheme == "http" and port == 443:
        return "URL scheme 'http' cannot use port 443; use https:// for port 443."
    if scheme == "https" and port == 80:
        return "URL scheme 'https' cannot use port 80; use http:// for port 80."
    return None


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

    # Port policy runs before any DNS work: denied ports are rejected outright
    # without resolving or contacting the target.
    try:
        port = parsed.port
    except ValueError:
        return False, f"Malformed URL: port out of range 0-65535 in '{raw}'.", None
    policy_msg = port_policy_error(parsed.scheme, port)
    if policy_msg:
        return False, policy_msg, None

    safe, reason, _ = resolve_and_validate_host(hostname)
    if not safe:
        return False, reason, None

    # Build sanitized URL without credentials
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

    policy_msg = port_policy_error(parsed.scheme, port)
    if policy_msg:
        return False, policy_msg, None, None, None

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


async def read_body_bounded(
    response: httpx.Response, limit: int = MAX_HTTP_RESPONSE_BYTES
) -> Tuple[bytes, bool]:
    """
    Capture a response body without ever holding more than `limit` bytes.

    Reads via a single streaming iterator and stops pulling the moment the cap
    is reached. One extra probe of the same iterator distinguishes a body that
    ends exactly at the cap (safe, truncated=False) from one that continues
    past it (truncated=True). The underlying stream is always closed so pooled
    connections and chunked responses are released cleanly.

    Content-Length is never trusted alone: a declared length over the cap
    short-circuits the body entirely (status and headers are preserved), but a
    missing or lying Content-Length is still bounded by the streaming cap.

    Returns (content_bytes, truncated).
    """
    try:
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except (TypeError, ValueError):
                declared = None
        else:
            declared = None

        if declared is not None and declared > limit:
            # Declared body is clearly over the cap: keep status + headers and
            # skip the body read entirely. A materialized body is still capped
            # rather than trusted, so a lying Content-Length cannot bypass us.
            stored = getattr(response, "_content", None)
            if stored is not None:
                return stored[:limit], len(stored) > limit
            return b"", True

        chunks: List[bytes] = []
        total = 0
        truncated = False
        iterator = response.aiter_bytes()
        while total < limit:
            try:
                chunk = await iterator.__anext__()
            except StopAsyncIteration:
                break
            if not chunk:
                continue
            room = limit - total
            if len(chunk) > room:
                # Overshoot: keep only the slice that fits the cap.
                chunks.append(chunk[:room])
                truncated = True
                break
            chunks.append(chunk)
            total += len(chunk)

        if total >= limit and not truncated:
            # Probe the same iterator once more: silence means the body ends
            # exactly at the cap, any data means it is actually over it.
            try:
                await iterator.__anext__()
            except StopAsyncIteration:
                pass
            else:
                truncated = True

        return b"".join(chunks), truncated
    finally:
        await response.aclose()


def _bounded_response(
    raw: httpx.Response,
    request: httpx.Request,
    content: bytes,
    truncated: bool,
) -> httpx.Response:
    """
    Rebuild a materialized httpx.Response carrying only the bounded body.

    Preserves status, headers (hence cookies and content-type), the original
    request, and any redirected-response history. The captured body is replaced
    with the bounded snapshot and a `body_truncated` flag is stamped into
    extensions so callers can detect and report truncation.
    """
    extensions = dict(raw.extensions)
    extensions["body_truncated"] = truncated
    return httpx.Response(
        status_code=raw.status_code,
        headers=raw.headers,
        content=content,
        request=request,
        extensions=extensions,
        history=list(raw.history) if raw.history else None,
    )


class BoundedAsyncClient(httpx.AsyncClient):
    """
    httpx.AsyncClient that never materializes an unbounded response body.

    Every fully-buffered request (get/request/post/etc., i.e. stream=False) is
    intercepted at send(): the response is streamed, capped at
    MAX_HTTP_RESPONSE_BYTES, and rebuilt as a bounded materialized response.
    Content-Length is advisory only; the streaming cap is authoritative.

    When a caller explicitly requests stream=True the raw streaming response is
    returned untouched, since ownership of the stream has been handed over and
    a cap can no longer be enforced after the fact.

    get()/request() and friends are inherited unchanged, so tests patching
    httpx.AsyncClient.get / httpx.AsyncClient.request at the class level
    continue to intercept via normal MRO lookup.
    """

    async def send(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
        auth: Optional[httpx.Auth] = httpx.USE_CLIENT_DEFAULT,
        follow_redirects: bool = httpx.USE_CLIENT_DEFAULT,
    ) -> httpx.Response:
        if stream:
            return await super().send(
                request,
                stream=True,
                auth=auth,
                follow_redirects=follow_redirects,
            )
        raw = await super().send(
            request,
            stream=True,
            auth=auth,
            follow_redirects=follow_redirects,
        )
        content, truncated = await read_body_bounded(raw, MAX_HTTP_RESPONSE_BYTES)
        return _bounded_response(raw, request, content, truncated)


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

    async with BoundedAsyncClient(follow_redirects=False, timeout=timeout, verify=verify) as client:
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
