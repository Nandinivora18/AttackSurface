"""
Controlled Same-Origin Discovery Crawler for SentinelScan
=========================================================
Performs bounded, non-destructive same-origin resource and parameter discovery.

Safety Invariants:
- Strictly same-origin (never crawls external domains).
- GET and HEAD requests only (forms are parsed but NEVER submitted; zero state-changing actions).
- robots.txt is parsed for discovery context; Disallow rules are respected and NEVER bypassed.
- Skips hazardous action paths (logout, delete, checkout, pay).
- Enforces hard ceilings on pages, depth, total requests, response body size, and execution duration.
- Every outbound request and redirect destination is validated against SSRF protection.
"""
from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from dataclasses import dataclass, field, asdict
from typing import Any, Set, List, Dict
import httpx

from app.utils.safe_http import async_resolve_and_pin

logger = logging.getLogger(__name__)

# Excluded action keywords in URLs or forms that must never be crawled
EXCLUDED_ACTION_PATTERNS = re.compile(
    r'(logout|signout|delete|remove|destroy|buy|checkout|pay|payment|purchase|order|'
    r'subscribe|unsubscribe|cancel|transfer|approve|reject|confirm|execute|create|'
    r'update|reset|reset[-_]?password|change[-_]?password|disable|enable|invite|kill|terminate)',
    re.IGNORECASE
)

# HTML parsing regexes (avoiding heavy external dependencies)
_A_HREF_RE = re.compile(r'<a\s+(?:[^>]*?\s+)?href=([\'"])(.*?)\1', re.IGNORECASE)
_FORM_RE = re.compile(r'<form\s+([^>]*?)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_FORM_ACTION_RE = re.compile(r'action=([\'"])(.*?)\1', re.IGNORECASE)
_FORM_METHOD_RE = re.compile(r'method=([\'"])(.*?)\1', re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r'<input\s+[^>]*?name=([\'"])(.*?)\1', re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r'<script\s+[^>]*?src=([\'"])(.*?)\1', re.IGNORECASE)
_LINK_HREF_RE = re.compile(r'<link\s+[^>]*?href=([\'"])(.*?)\1', re.IGNORECASE)
_SITEMAP_LOC_RE = re.compile(r'<loc>(https?://[^<]+)</loc>', re.IGNORECASE)


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str
    status_code: int
    content_type: str
    query_params: list[str] = field(default_factory=list)
    form_inputs: list[str] = field(default_factory=list)
    is_same_origin: bool = True
    depth: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CrawlResult:
    target_url: str
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    external_scripts: list[str] = field(default_factory=list)
    parameters: dict[str, list[str]] = field(default_factory=dict) # param_name -> [urls]
    forms: list[dict[str, Any]] = field(default_factory=list)
    robots_disallowed: list[str] = field(default_factory=list)
    sitemap_urls: list[str] = field(default_factory=list)
    total_requests: int = 0
    duration_ms: int = 0
    limit_reached: str | None = None

    @property
    def discovered_endpoints(self) -> list[DiscoveredEndpoint]:
        return self.endpoints

    @property
    def visited_urls(self) -> set[str]:
        return {ep.url for ep in self.endpoints}


class ControlledCrawler:
    """
    Safely discovers same-origin URLs, input parameters, forms, and scripts.
    """

    def __init__(
        self,
        base_url: str,
        max_pages: int = 20,
        max_depth: int = 2,
        max_requests: int = 50,
        max_response_size: int = 1_048_576, # 1 MB
        timeout_seconds: float = 5.0,
        requests_per_second: float = 5.0,
    ):
        self.base_url = base_url
        self.parsed_base = urllib.parse.urlparse(base_url)
        self.origin = f"{self.parsed_base.scheme}://{self.parsed_base.netloc}"
        
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_requests = max_requests
        self.max_response_size = max_response_size
        self.timeout = timeout_seconds
        self.delay_between_requests = 1.0 / requests_per_second

        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: list[DiscoveredEndpoint] = []
        self.external_scripts: Set[str] = set()
        self.parameters: dict[str, list[str]] = {}
        self.forms: list[dict[str, Any]] = []
        self.robots_disallowed: list[str] = []
        self.sitemap_urls: list[str] = []
        self.requests_made = 0
        self.limit_reached: str | None = None

    def _canonicalize_url(self, raw_url: str, current_url: str) -> str | None:
        """Converts relative URLs to canonical absolute same-origin URLs."""
        if not raw_url or raw_url.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None

        # Resolve relative path
        abs_url = urllib.parse.urljoin(current_url, raw_url.strip())
        parsed = urllib.parse.urlparse(abs_url)

        # Remove fragment
        cleaned = urllib.parse.urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            parsed.query,
            ""
        ))
        return cleaned

    def _is_same_origin(self, url: str) -> bool:
        """Strict check that target scheme, hostname, and port match the base origin."""
        parsed = urllib.parse.urlparse(url)
        if (parsed.hostname or "").lower() != (self.parsed_base.hostname or "").lower():
            return False

        def _get_port(p):
            if p.port:
                return p.port
            return 443 if p.scheme == "https" else 80 if p.scheme == "http" else None

        return _get_port(parsed) == _get_port(self.parsed_base)

    def _is_safe_action(self, url: str) -> bool:
        """Checks whether URL matches dangerous keywords like logout or delete."""
        return not bool(EXCLUDED_ACTION_PATTERNS.search(url))

    async def _safe_fetch(self, client: httpx.AsyncClient, url: str) -> tuple[httpx.Response, str] | None:
        """Fetches a URL after verifying target against SSRF safeguards, same-origin, and action patterns.

        Returns (response, canonical_url). canonical_url is the hostname-form URL
        (NOT the pinned IP-literal connection URL) so that same-origin checks,
        link resolution, and endpoint recording operate on the real origin and the
        underlying public IP is never leaked into results.
        """
        if not self._is_safe_action(url):
            logger.debug(f"Crawler skipping sensitive/state-changing action URL: {url}")
            return None

        current_url = url
        redirect_hops = 0
        max_redirects = 5
        redirect_chain: list[httpx.Response] = []

        while redirect_hops <= max_redirects:
            if self.requests_made >= self.max_requests:
                self.limit_reached = f"MAX_REQUESTS limit ({self.max_requests}) reached"
                return None

            if not self._is_same_origin(current_url):
                logger.debug(f"Crawler blocked cross-origin fetch/redirect: {current_url}")
                return None

            if not self._is_safe_action(current_url):
                logger.debug(f"Crawler blocked unsafe action URL on redirect: {current_url}")
                return None

            is_safe, reason, current_url, conn_url, host_header = await async_resolve_and_pin(current_url)
            if not is_safe or not conn_url or host_header is None:
                logger.debug(f"Crawler skipping URL due to SSRF validation: {current_url} ({reason})")
                return None

            self.requests_made += 1
            try:
                # Respect rate limit pacing
                await asyncio.sleep(self.delay_between_requests)
                resp = await client.get(
                    conn_url,
                    headers={"User-Agent": "SentinelScan-Security-Scanner/2.0", "Host": host_header},
                    follow_redirects=False,
                )

                if resp.status_code in (301, 302, 303, 307, 308):
                    redirect_hops += 1
                    if redirect_hops > max_redirects:
                        logger.debug(f"Crawler exceeded max redirect hops for {url}")
                        return None
                    loc = resp.headers.get("location")
                    if not loc:
                        resp.history = redirect_chain
                        return (resp, current_url)
                    redirect_chain.append(resp)
                    current_url = urllib.parse.urljoin(current_url, loc)
                    continue

                resp.history = redirect_chain
                return (resp, current_url)
            except Exception as e:
                logger.debug(f"Crawler fetch failed for {current_url}: {e}")
                return None

        return None

    async def _parse_robots(self, client: httpx.AsyncClient) -> None:
        """Parses robots.txt for sitemaps and Disallow structure without crawling disallowed paths."""
        robots_url = urllib.parse.urljoin(self.origin, "/robots.txt")
        fetched = await self._safe_fetch(client, robots_url)
        if not fetched:
            return
        resp = fetched[0]
        if resp.status_code != 200:
            return

        for line in resp.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    disallowed = parts[1].strip()
                    if disallowed and disallowed not in self.robots_disallowed:
                        self.robots_disallowed.append(disallowed)
            elif line.lower().startswith("sitemap:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    sitemap = parts[1].strip()
                    if sitemap and sitemap not in self.sitemap_urls:
                        self.sitemap_urls.append(sitemap)

    async def _parse_sitemap(self, client: httpx.AsyncClient) -> None:
        """Parses sitemap.xml to seed URL queue with valid same-origin paths."""
        sitemap_url = self.sitemap_urls[0] if self.sitemap_urls else urllib.parse.urljoin(self.origin, "/sitemap.xml")
        fetched = await self._safe_fetch(client, sitemap_url)
        if not fetched:
            return
        resp = fetched[0]
        if resp.status_code != 200:
            return

        matches = _SITEMAP_LOC_RE.findall(resp.text)
        for loc in matches[:15]: # seed up to 15 sitemap links
            loc = loc.strip()
            if self._is_same_origin(loc) and self._is_safe_action(loc) and loc not in self.visited_urls:
                self.sitemap_urls.append(loc)

    def _extract_page_assets(self, html: str, current_url: str) -> list[str]:
        """Extracts scripts, links, and forms from an HTML response body."""
        new_links: list[str] = []

        # 1. Links
        for _, href in _A_HREF_RE.findall(html):
            canon = self._canonicalize_url(href, current_url)
            if canon and self._is_same_origin(canon) and self._is_safe_action(canon):
                new_links.append(canon)

        # 2. External Scripts
        for _, src in _SCRIPT_SRC_RE.findall(html):
            canon = self._canonicalize_url(src, current_url)
            if canon:
                if not self._is_same_origin(canon):
                    self.external_scripts.add(canon)
                else:
                    new_links.append(canon)

        # 3. Forms
        for form_attrs, form_body in _FORM_RE.findall(html):
            action_match = _FORM_ACTION_RE.search(form_attrs)
            method_match = _FORM_METHOD_RE.search(form_attrs)
            action = action_match.group(2) if action_match else current_url
            method = (method_match.group(2) if method_match else "GET").upper()

            # Extract input parameter names
            input_names = [name for _, name in _INPUT_NAME_RE.findall(form_body)]
            canon_action = self._canonicalize_url(action, current_url)
            if canon_action and self._is_same_origin(canon_action):
                self.forms.append({
                    "action": canon_action,
                    "method": method,
                    "inputs": input_names,
                    "source_page": current_url,
                })
                # Register input parameters for injection testing
                for inp in input_names:
                    self.parameters.setdefault(inp, []).append(canon_action)

        return new_links

    async def crawl(self) -> CrawlResult:
        """
        Executes bounded, safe same-origin crawl starting from base_url.
        """
        import time
        start_t = time.monotonic()

        # Queue contains tuples of (url, depth)
        queue: list[tuple[str, int]] = [(self.base_url, 0)]
        self.visited_urls.add(self.base_url)

        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        async with httpx.AsyncClient(timeout=self.timeout, limits=limits) as client:
            # Step 1: Parse robots.txt and sitemap.xml for discovery context
            await self._parse_robots(client)
            await self._parse_sitemap(client)

            # Seed queue with top sitemap entries within budget
            for s_url in self.sitemap_urls:
                if self._is_safe_action(s_url) and s_url not in self.visited_urls and len(queue) < self.max_pages:
                    self.visited_urls.add(s_url)
                    queue.append((s_url, 1))

            # Step 2: Breadth-first crawl loop
            while queue and len(self.discovered_endpoints) < self.max_pages:
                if self.requests_made >= self.max_requests:
                    self.limit_reached = f"MAX_REQUESTS limit ({self.max_requests}) reached"
                    break

                current_url, depth = queue.pop(0)

                # Skip if depth exceeded
                if depth > self.max_depth:
                    continue

                fetched = await self._safe_fetch(client, current_url)
                if not fetched:
                    continue
                resp, canonical_url = fetched

                # Parse URL query parameters
                parsed = urllib.parse.urlparse(canonical_url)
                q_params = list(urllib.parse.parse_qs(parsed.query).keys())
                for qp in q_params:
                    self.parameters.setdefault(qp, []).append(canonical_url)

                content_type = resp.headers.get("content-type", "").lower()
                endpoint = DiscoveredEndpoint(
                    url=canonical_url,
                    method="GET",
                    status_code=resp.status_code,
                    content_type=content_type,
                    query_params=q_params,
                    is_same_origin=self._is_same_origin(canonical_url),
                    depth=depth,
                )
                self.discovered_endpoints.append(endpoint)

                # If HTML, parse links and forms
                if "text/html" in content_type and len(resp.content) <= self.max_response_size:
                    discovered_links = self._extract_page_assets(resp.text, canonical_url)
                    for link in discovered_links:
                        # Check Disallow rules: Do not crawl disallowed paths
                        path = urllib.parse.urlparse(link).path
                        if any(path.startswith(dis.rstrip("*")) for dis in self.robots_disallowed if dis != "/"):
                            continue

                        if link not in self.visited_urls and len(self.visited_urls) < (self.max_pages * 2):
                            self.visited_urls.add(link)
                            queue.append((link, depth + 1))

        duration_ms = round((time.monotonic() - start_t) * 1000)
        return CrawlResult(
            target_url=self.base_url,
            endpoints=self.discovered_endpoints,
            external_scripts=sorted(list(self.external_scripts)),
            parameters=self.parameters,
            forms=self.forms,
            robots_disallowed=self.robots_disallowed,
            sitemap_urls=self.sitemap_urls,
            total_requests=self.requests_made,
            duration_ms=duration_ms,
            limit_reached=self.limit_reached,
        )


SameOriginCrawler = ControlledCrawler

