from __future__ import annotations

import gzip
import zlib
from collections.abc import AsyncGenerator
from contextlib import aclosing
from itertools import repeat

import anyio
import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.middleware.compression import CompressionMiddleware
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.responses import PlainTextResponse, Response, StreamingResponse
from starlette.types import Receive, Scope, Send

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    ("accepted", "status"),
    [("deflate, identity;q=0", 200), ("*", 200), (None, 200), ("", 406), ("deflate;q=0", 406)],
)
async def test_preencoded_response(accepted: str | None, status: int) -> None:
    app = CompressionMiddleware(Response(zlib.compress(b"hello"), headers={"content-encoding": "deflate"}))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        client.headers.clear()
        response = await client.get("/", headers={} if accepted is None else {"accept-encoding": accepted})
    assert response.status_code == status
    assert response.content == (b"hello" if status == 200 else b"Not Acceptable")
    assert response.headers.get("content-encoding") == ("deflate" if status == 200 else None)


@pytest.mark.parametrize("accepted", ["gzip, deflate, identity;q=0", "gzip", "deflate"])
async def test_preencoded_chain(accepted: str) -> None:
    app = CompressionMiddleware(
        Response(zlib.compress(gzip.compress(b"hello")), headers={"content-encoding": "gzip, deflate"})
    )
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": accepted})
    assert response.status_code == (200 if accepted.startswith("gzip, deflate") else 406)
    assert response.content == (b"hello" if response.status_code == 200 else b"Not Acceptable")


@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br"])
@pytest.mark.parametrize("size", [0, 5])
async def test_small_body_requires_encoding(encoding: str, size: int) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * size))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": f"{encoding}, identity;q=0"})
    assert response.status_code == 200
    assert response.content == b"x" * size
    assert response.headers["content-encoding"] == encoding
    assert response.headers["vary"] == "Accept-Encoding"


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("status,media_type", [(200, "text/event-stream"), (206, "text/plain")])
async def test_excluded_response_requires_identity(method: str, status: int, media_type: str) -> None:
    completed: list[bool] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", media_type.encode())],
                "trailers": True,
            }
        )
        try:
            for _ in repeat(None):  # pragma: no branch - The infinite stream terminates only by cancellation.
                await anyio.sleep(0)
                await send({"type": "http.response.body", "body": b"x" * 4000, "more_body": True})
        finally:
            completed.append(True)
            await send({"type": "http.response.trailers", "headers": []})

    async with AsyncClient(transport=ASGITransport(CompressionMiddleware(app)), base_url="http://test") as client:
        with anyio.fail_after(1):
            response = await client.request(method, "/", headers={"accept-encoding": "gzip, identity;q=0"})
    assert response.status_code == 406
    assert response.content == (b"Not Acceptable" if method == "GET" else b"")
    assert response.headers["content-length"] == "14"
    assert completed == [True]


@pytest.mark.parametrize("spec_version", ["2.0", "2.4"])
async def test_rejected_streaming_response_cleanup(spec_version: str) -> None:
    completed: list[bool] = []

    async def stream() -> AsyncGenerator[bytes, None]:
        try:
            yield b"event"
        finally:
            completed.append(True)

    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        scope = {**scope, "asgi": {"spec_version": spec_version}}
        async with aclosing(stream()) as body:
            await StreamingResponse(body, media_type="text/event-stream")(scope, receive, send)

    app = CompressionMiddleware(ServerErrorMiddleware(endpoint))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        with anyio.fail_after(1):
            response = await client.get("/", headers={"accept-encoding": "gzip, identity;q=0"})
    assert response.status_code == 406
    assert response.text == "Not Acceptable"
    assert completed == [True]


@pytest.mark.parametrize("vary", ["Origin, accept-encoding", "*"])
async def test_vary_is_not_duplicated(vary: str) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 4000, headers={"vary": vary}))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "gzip"})
    assert response.headers["vary"] == vary
