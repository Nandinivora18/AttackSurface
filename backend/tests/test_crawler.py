"""
Tests for Controlled Same-Origin Crawler
========================================
Validates safety bounds, same-origin enforcement, robots.txt handling,
action path exclusion, and resource discovery.
"""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from app.scanner.crawler import ControlledCrawler, DiscoveredEndpoint, CrawlResult


@pytest.fixture
def crawler():
    return ControlledCrawler(
        base_url="https://example.com/portal",
        max_pages=5,
        max_depth=2,
        max_requests=10,
        requests_per_second=100.0, # Fast for testing
    )


def test_canonicalize_url(crawler):
    # Relative path
    assert crawler._canonicalize_url("/about", "https://example.com/portal") == "https://example.com/about"
    # Relative to current path
    assert crawler._canonicalize_url("team", "https://example.com/portal/") == "https://example.com/portal/team"
    # Strips fragment
    assert crawler._canonicalize_url("/faq#section2", "https://example.com") == "https://example.com/faq"
    # Preserves query
    assert crawler._canonicalize_url("/search?q=test", "https://example.com") == "https://example.com/search?q=test"
    # Rejects unsupported schemes
    assert crawler._canonicalize_url("javascript:void(0)", "https://example.com") is None
    assert crawler._canonicalize_url("mailto:admin@example.com", "https://example.com") is None
    assert crawler._canonicalize_url("tel:+123456789", "https://example.com") is None
    assert crawler._canonicalize_url("#anchor", "https://example.com") is None


def test_is_same_origin(crawler):
    assert crawler._is_same_origin("https://example.com/page") is True
    assert crawler._is_same_origin("https://example.com:443/page") is True
    # Different scheme (http vs https) is not same-origin per RFC 6454
    assert crawler._is_same_origin("http://example.com/page") is False
    assert crawler._is_same_origin("https://subdomain.example.com/page") is False
    assert crawler._is_same_origin("https://evil.com/page") is False


def test_is_safe_action(crawler):
    # Safe paths
    assert crawler._is_safe_action("https://example.com/about") is True
    assert crawler._is_safe_action("https://example.com/products/item-123") is True
    assert crawler._is_safe_action("https://example.com/contact") is True

    # Excluded dangerous action verbs
    assert crawler._is_safe_action("https://example.com/logout") is False
    assert crawler._is_safe_action("https://example.com/user/signout") is False
    assert crawler._is_safe_action("https://example.com/cart/checkout") is False
    assert crawler._is_safe_action("https://example.com/account/delete") is False
    assert crawler._is_safe_action("https://example.com/api/pay") is False
    assert crawler._is_safe_action("https://example.com/profile/destroy") is False
    assert crawler._is_safe_action("https://example.com/auth/reset-password") is False


def test_extract_page_assets(crawler):
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.min.js"></script>
        <script src="/static/js/app.js"></script>
    </head>
    <body>
        <a href="/dashboard">Dashboard</a>
        <a href="/logout">Log Out</a>
        <a href="https://external.com/docs">External Docs</a>
        
        <form action="/search" method="GET">
            <input type="text" name="query" />
            <input type="hidden" name="category" value="sec" />
        </form>

        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
        </form>
    </body>
    </html>
    """

    links = crawler._extract_page_assets(html, "https://example.com/home")

    # Links should include same-origin safe links and local script
    assert "https://example.com/dashboard" in links
    assert "https://example.com/static/js/app.js" in links
    # Excluded action pattern should NOT be in links
    assert "https://example.com/logout" not in links
    # External link should NOT be in links
    assert "https://external.com/docs" not in links

    # External scripts should capture CDN
    assert "https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.min.js" in crawler.external_scripts

    # Forms should be parsed
    assert len(crawler.forms) == 2
    assert crawler.forms[0]["action"] == "https://example.com/search"
    assert crawler.forms[0]["method"] == "GET"
    assert "query" in crawler.forms[0]["inputs"]
    assert "category" in crawler.forms[0]["inputs"]

    assert crawler.forms[1]["action"] == "https://example.com/login"
    assert crawler.forms[1]["method"] == "POST"
    assert "username" in crawler.forms[1]["inputs"]
    assert "password" in crawler.forms[1]["inputs"]

    # Parameter registry should contain discovered form inputs
    assert "query" in crawler.parameters
    assert "username" in crawler.parameters


@pytest.mark.asyncio
async def test_crawl_flow_with_mocked_responses():
    crawler = ControlledCrawler(
        base_url="https://app.test",
        max_pages=3,
        max_depth=1,
        max_requests=5,
        requests_per_second=1000.0,
    )

    # Mock safe_http validation to allow app.test
    with patch("app.scanner.crawler.async_resolve_and_pin", new_callable=AsyncMock) as mock_val:
        def _pin_target(url):
            return (True, "OK", url, url.replace("https://app.test", "https://93.184.216.34"), "app.test")
        mock_val.side_effect = _pin_target

        mock_robots = httpx.Response(
            200,
            text="User-agent: *\nDisallow: /admin\nSitemap: https://app.test/sitemap.xml",
            request=httpx.Request("GET", "https://app.test/robots.txt"),
        )
        mock_sitemap = httpx.Response(
            200,
            text="<urlset><url><loc>https://app.test/page1</loc></url></urlset>",
            request=httpx.Request("GET", "https://app.test/sitemap.xml"),
        )
        mock_root = httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text='<html><body><a href="/page1">Page 1</a><a href="/admin">Admin</a></body></html>',
            request=httpx.Request("GET", "https://app.test"),
        )
        mock_page1 = httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            text='<html><body><a href="/page2?id=10">Page 2</a></body></html>',
            request=httpx.Request("GET", "https://app.test/page1"),
        )

        async def fake_get(url, *args, **kwargs):
            u = url.rstrip("/")
            if "robots.txt" in u:
                return mock_robots
            elif "sitemap.xml" in u:
                return mock_sitemap
            elif u.endswith("93.184.216.34") or u.endswith("https://app.test"):
                return mock_root
            elif "page1" in u:
                return mock_page1
            return httpx.Response(404, request=httpx.Request("GET", url))

        with patch("httpx.AsyncClient.get", side_effect=fake_get):
            result = await crawler.crawl()

            assert isinstance(result, CrawlResult)
            assert "/admin" in result.robots_disallowed
            # Disallowed /admin must not be in discovered endpoints
            endpoint_urls = [ep.url for ep in result.endpoints]
            assert "https://app.test/admin" not in endpoint_urls
            assert any("page1" in u for u in endpoint_urls)
            assert len(result.endpoints) <= 3


@pytest.mark.asyncio
async def test_crawler_ssrf_blocked():
    crawler = ControlledCrawler(base_url="https://evil-redirect.test")

    with patch("app.scanner.crawler.async_resolve_and_pin", new_callable=AsyncMock) as mock_val:
        mock_val.return_value = (False, "Target resolves to private network", None, None, None)

        with patch("httpx.AsyncClient.get") as mock_get:
            result = await crawler.crawl()
            assert mock_get.call_count == 0
            assert len(result.endpoints) == 0


def test_extended_dangerous_action_verbs(crawler):
    """Verify all prohibited state-changing verbs are blocked by _is_safe_action."""
    prohibited_samples = [
        "https://example.com/account/cancel",
        "https://example.com/api/transfer",
        "https://example.com/billing/payment",
        "https://example.com/admin/approve",
        "https://example.com/admin/reject",
        "https://example.com/order/confirm",
        "https://example.com/scripts/execute",
        "https://example.com/user/create",
        "https://example.com/profile/update",
        "https://example.com/auth/reset",
        "https://example.com/user/disable",
        "https://example.com/user/enable",
        "https://example.com/team/invite",
        "https://example.com/proc/kill",
        "https://example.com/session/terminate",
        "https://example.com/auth/change-password",
    ]
    for url in prohibited_samples:
        assert crawler._is_safe_action(url) is False, f"Expected {url} to be blocked as unsafe action"


@pytest.mark.asyncio
async def test_crawler_blocks_cross_origin_redirect():
    """Crawler must not follow redirects to a different origin."""
    crawler = ControlledCrawler(base_url="https://example.com")
    mock_redirect = httpx.Response(
        302,
        headers={"Location": "https://attacker.com/evil"},
        request=httpx.Request("GET", "https://example.com/redirect"),
    )

    with patch("app.scanner.crawler.async_resolve_and_pin", new_callable=AsyncMock) as mock_val:
        mock_val.return_value = (True, "OK", "https://example.com/redirect", "https://example.com/redirect", "example.com")
        with patch("httpx.AsyncClient.get", return_value=mock_redirect) as mock_get:
            resp = await crawler._safe_fetch(httpx.AsyncClient(), "https://example.com/redirect")
            # Must return None (blocked) and never request attacker.com
            assert resp is None
            assert mock_get.call_count == 1


@pytest.mark.asyncio
async def test_crawler_blocks_redirect_to_unsafe_action():
    """Crawler must not follow redirects to state-changing URLs (e.g. /logout)."""
    crawler = ControlledCrawler(base_url="https://example.com")
    mock_redirect = httpx.Response(
        302,
        headers={"Location": "https://example.com/logout"},
        request=httpx.Request("GET", "https://example.com/safe-gateway"),
    )

    with patch("app.scanner.crawler.async_resolve_and_pin", new_callable=AsyncMock) as mock_val:
        mock_val.return_value = (True, "OK", "https://example.com/safe-gateway", "https://example.com/safe-gateway", "example.com")
        with patch("httpx.AsyncClient.get", return_value=mock_redirect) as mock_get:
            resp = await crawler._safe_fetch(httpx.AsyncClient(), "https://example.com/safe-gateway")
            # Must return None (blocked) and never request /logout
            assert resp is None
            assert mock_get.call_count == 1


@pytest.mark.asyncio
async def test_crawler_blocks_redirect_to_private_ip():
    """Crawler must block redirect hops that resolve to private/internal IPs."""
    crawler = ControlledCrawler(base_url="https://example.com")
    mock_redirect = httpx.Response(
        302,
        headers={"Location": "https://example.com/internal-redirect"},
        request=httpx.Request("GET", "https://example.com/landing"),
    )

    async def mock_resolve_pin(target_url):
        if "internal-redirect" in target_url:
            return (False, "Destination IP 127.0.0.1 is loopback", None, None, None)
        return (True, "OK", target_url, target_url, "example.com")

    with patch("app.scanner.crawler.async_resolve_and_pin", side_effect=mock_resolve_pin):
        with patch("httpx.AsyncClient.get", return_value=mock_redirect) as mock_get:
            resp = await crawler._safe_fetch(httpx.AsyncClient(), "https://example.com/landing")
            # Must return None (blocked) and never request internal-redirect
            assert resp is None
            assert mock_get.call_count == 1


@pytest.mark.asyncio
async def test_crawler_enforces_max_requests():
    """Crawler stops immediately when max_requests ceiling is reached."""
    crawler = ControlledCrawler(base_url="https://example.com", max_requests=2, max_pages=10)
    mock_page = httpx.Response(
        200,
        headers={"Content-Type": "text/html"},
        text='<html><body><a href="/p1">P1</a><a href="/p2">P2</a><a href="/p3">P3</a></body></html>',
        request=httpx.Request("GET", "https://example.com"),
    )

    with patch("app.scanner.crawler.async_resolve_and_pin", new_callable=AsyncMock) as mock_val:
        mock_val.return_value = (True, "OK", "https://example.com", "https://example.com", "example.com")
        with patch("httpx.AsyncClient.get", return_value=mock_page):
            result = await crawler.crawl()
            assert crawler.requests_made <= 2
            assert result.limit_reached is not None

