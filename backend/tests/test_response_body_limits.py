"""
Regression tests for bounded response-body buffering (F1).

Verifies:
- read_body_bounded() never materializes more than MAX_HTTP_RESPONSE_BYTES
- A body bigger than the cap is truncated and flagged, never fully buffered
- A body that ends exactly at the cap is NOT flagged as truncated
- Content-Length is advisory only: a lying or missing length cannot bypass
  the streaming cap
- The underlying stream is always closed (pooled connections released)
- BoundedAsyncClient caps every fully-buffered request (get/request/...) while
  preserving status, headers and redirect history
- stream=True passthrough still returns the raw streaming response
"""
import pytest
import httpx

from app.utils.safe_http import (
    BoundedAsyncClient,
    MAX_HTTP_RESPONSE_BYTES,
    read_body_bounded,
)

CHUNK = 1024
MAX = MAX_HTTP_RESPONSE_BYTES


def _counting_stream(total: int, chunk_size: int = CHUNK, record_owner=None):
    """AsyncByteStream that counts how many chunks are pulled and reports aclose."""

    class CountingStream(httpx.AsyncByteStream):
        def __init__(self):
            self.pulled = 0
            self.closed = False

        def __aiter__(self):
            return self

        async def __anext__(self):
            if self.served >= self.total:
                raise StopAsyncIteration
            n = min(self.chunk_size, self.total - self.served)
            self.pulled += 1
            self.served += n
            return b"x" * n

        async def aclose(self):
            self.closed = True

    stream = CountingStream()
    stream.total = total
    stream.chunk_size = chunk_size
    stream.served = 0
    if record_owner is not None:
        record_owner.append(stream)
    return stream


def _streamed_response(total: int, chunk_size: int = CHUNK, headers=None, owner=None):
    req = httpx.Request("GET", "https://example.com/")
    return httpx.Response(
        200,
        headers=headers or {},
        stream=_counting_stream(total, chunk_size, owner),
        request=req,
    )


@pytest.mark.asyncio
async def test_small_body_read_fully_not_truncated():
    owner = []
    resp = _streamed_response(100, owner=owner)
    content, truncated = await read_body_bounded(resp, MAX)
    assert content == b"x" * 100
    assert truncated is False
    assert owner[0].closed is True


@pytest.mark.asyncio
async def test_empty_body_not_truncated():
    resp = _streamed_response(0)
    content, truncated = await read_body_bounded(resp, MAX)
    assert content == b""
    assert truncated is False


@pytest.mark.asyncio
async def test_over_limit_body_truncated_at_cap():
    owner = []
    resp = _streamed_response(MAX + 5000, owner=owner)
    content, truncated = await read_body_bounded(resp, MAX)
    assert len(content) == MAX
    assert truncated is True
    assert owner[0].closed is True


@pytest.mark.asyncio
async def test_exactly_at_limit_not_truncated():
    owner = []
    resp = _streamed_response(MAX, owner=owner)
    content, truncated = await read_body_bounded(resp, MAX)
    assert len(content) == MAX
    assert truncated is False
    assert owner[0].closed is True


@pytest.mark.asyncio
async def test_streaming_stops_at_cap_despite_larger_body():
    """Proves we never pull the whole body: pull count stays near cap/chunk."""
    owner = []
    resp = _streamed_response(MAX * 3, owner=owner)
    content, truncated = await read_body_bounded(resp, MAX)
    assert len(content) == MAX
    assert truncated is True
    # cap bytes in chunk-sized pieces + at most one probe chunk.
    assert owner[0].pulled <= (MAX // CHUNK) + 1


@pytest.mark.asyncio
async def test_single_huge_chunk_is_capped():
    owner = []
    resp = _streamed_response(MAX * 3, chunk_size=MAX * 3, owner=owner)
    content, truncated = await read_body_bounded(resp, MAX)
    assert len(content) == MAX
    assert truncated is True


@pytest.mark.asyncio
async def test_lying_content_length_cannot_bypass_cap():
    owner = []
    # Declared length is tiny, but the body is huge.
    resp = _streamed_response(MAX + 5000, headers={"content-length": "100"}, owner=owner)
    content, truncated = await read_body_bounded(resp, MAX)
    assert len(content) == MAX
    assert truncated is True


@pytest.mark.asyncio
async def test_declared_length_over_cap_skips_body():
    owner = []
    resp = _streamed_response(MAX + 5000, headers={"content-length": str(MAX + 5000)}, owner=owner)
    content, truncated = await read_body_bounded(resp, MAX)
    assert content == b""
    assert truncated is True
    assert owner[0].pulled == 0
    assert owner[0].closed is True


@pytest.mark.asyncio
async def test_materialized_content_with_declared_length_over_cap_is_capped():
    big = b"y" * (MAX + 9999)
    resp = httpx.Response(
        200,
        content=big,
        headers={"content-length": str(len(big))},
        request=httpx.Request("GET", "https://example.com/"),
    )
    content, truncated = await read_body_bounded(resp, MAX)
    assert len(content) == MAX
    assert truncated is True


@pytest.mark.asyncio
async def test_bounded_client_caps_get_and_stamps_extension():
    def route(request):
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            stream=_counting_stream(MAX + 12345),
            request=request,
        )

    async with BoundedAsyncClient(transport=httpx.MockTransport(route)) as client:
        resp = await client.get("https://example.com/")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "text/plain"
    assert len(resp.content) == MAX
    assert resp.extensions.get("body_truncated") is True
    # .text must still decode the bounded materialized body.
    assert resp.text == "x" * MAX


@pytest.mark.asyncio
async def test_bounded_client_preserves_small_body_and_headers():
    def route(request):
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "x-server": "test"},
            content=b'{"ok": true}',
            request=request,
        )

    async with BoundedAsyncClient(transport=httpx.MockTransport(route)) as client:
        resp = await client.get("https://example.com/")

    assert resp.json() == {"ok": True}
    assert resp.headers["x-server"] == "test"
    assert resp.extensions.get("body_truncated") is False


@pytest.mark.asyncio
async def test_bounded_client_preserves_redirect_history():
    def route(request):
        if request.url.path == "/start":
            return httpx.Response(
                302,
                headers={"location": "https://example.com/end"},
                stream=_counting_stream(0),
                request=request,
            )
        return httpx.Response(
            200,
            content=b"final",
            request=request,
        )

    async with BoundedAsyncClient(
        transport=httpx.MockTransport(route), follow_redirects=True
    ) as client:
        resp = await client.get("https://example.com/start")

    assert resp.status_code == 200
    assert resp.content == b"final"
    assert len(resp.history) == 1
    assert resp.history[0].status_code == 302


@pytest.mark.asyncio
async def test_stream_true_passthrough_is_untouched():
    def route(request):
        return httpx.Response(
            200,
            stream=_counting_stream(5000),
            request=request,
        )

    async with BoundedAsyncClient(transport=httpx.MockTransport(route)) as client:
        resp = await client.send(
            httpx.Request("GET", "https://example.com/"), stream=True
        )

    # Raw streaming response: no body_truncated stamp, live stream present.
    assert resp.extensions.get("body_truncated") is None
    body = b""
    async for chunk in resp.aiter_bytes():
        body += chunk
    assert len(body) == 5000
    await resp.aclose()


@pytest.mark.asyncio
async def test_bounded_client_small_exact_and_over_sizes():
    def route(request):
        n = request.headers["x-n-size"]
        return httpx.Response(
            200,
            stream=_counting_stream(int(n)),
            request=request,
        )

    async with BoundedAsyncClient(transport=httpx.MockTransport(route)) as client:
        small = await client.get("https://example.com/", headers={"x-n-size": "10"})
        exact = await client.get("https://example.com/", headers={"x-n-size": str(MAX)})
        over = await client.get(
            "https://example.com/", headers={"x-n-size": str(MAX + 1)}
        )

    assert len(small.content) == 10 and small.extensions["body_truncated"] is False
    assert len(exact.content) == MAX and exact.extensions["body_truncated"] is False
    assert len(over.content) == MAX and over.extensions["body_truncated"] is True