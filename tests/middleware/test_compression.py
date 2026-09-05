from __future__ import annotations

import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.middleware.compression import CompressionMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import Message, Receive, Scope, Send

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize(
    ("accept_encoding", "encoding", "status"),
    [
        ("gzip", "gzip", 200),
        ("zstd", "zstd", 200),
        ("gzip, zstd", "zstd", 200),
        ("zstd;q=0.2, gzip;q=0.8", "gzip", 200),
        ("gzip;q=0, zstd", "zstd", 200),
        ("GZIP; Q=1.000", "gzip", 200),
        ("gzip;q=0", None, 200),
        ("x-gzip-like", None, 200),
        ("br", "br", 200),
        ("gzip, br", "br", 200),
        ("gzip, br, zstd", "zstd", 200),
        ("br;q=1, zstd;q=0.5", "br", 200),
        ("br;q=0, gzip", "gzip", 200),
        ("br;q=0.5, gzip;q=1", "gzip", 200),
        ("BR", "br", 200),
        ("", None, 200),
        ("identity", None, 200),
        ("gzip;q=0.1, identity;q=0.5", None, 200),
        ("gzip, identity", "gzip", 200),
        ("*", "zstd", 200),
        ("*;q=1, zstd;q=0", "br", 200),
        ("*;q=1, zstd;q=0, br;q=0", "gzip", 200),
        ("*;q=0, gzip;q=0.5", "gzip", 200),
        ("*;q=0, identity;q=0.5", None, 200),
        ("gzip;q=invalid", None, 200),
        ("gzip;q=nan", None, 200),
        ("gzip;q=1.1", None, 200),
        ("gzip;q=-1", None, 200),
        ("gzip;q=0.1234", None, 200),
        ("gzip;q=0;foo=bar", None, 200),
        ("*;q=0", None, 406),
        ("unknown, identity;q=0", None, 406),
    ],
)
async def test_negotiation(accept_encoding: str, encoding: str | None, status: int) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 4000))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": accept_encoding})
    assert response.status_code == status
    assert response.headers.get("content-encoding") == encoding
    assert response.headers["vary"] == "Accept-Encoding"
    assert response.text == ("Not Acceptable" if status == 406 else "x" * 4000)
    if encoding is not None:
        assert int(response.headers["content-length"]) < 4000


async def test_repeated_accept_encoding_headers() -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 4000))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers=[("accept-encoding", "gzip;q=0.5"), ("accept-encoding", "zstd")])
    assert response.headers["content-encoding"] == "zstd"


async def test_missing_accept_encoding() -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 4000))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        client.headers.clear()
        response = await client.get("/")
    assert "content-encoding" not in response.headers
    assert response.headers["vary"] == "Accept-Encoding"


@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br", "identity"])
@pytest.mark.parametrize(
    ("size", "status", "headers"),
    [
        (499, 200, {}),
        (4000, 206, {"content-range": "bytes 0-3999/5000"}),
        (4000, 200, {"content-encoding": "custom"}),
        (4000, 200, {"content-type": "Text/Event-Stream; charset=utf-8"}),
        (4000, 200, {"content-type": "audio/mpeg"}),
    ],
)
async def test_bypass(encoding: str, size: int, status: int, headers: dict[str, str]) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * size, status_code=status, headers=headers))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": f"{encoding}, custom"})
    assert response.status_code == status
    assert response.text == "x" * size
    assert response.headers.get("content-encoding") == headers.get("content-encoding")
    assert int(response.headers["content-length"]) == size
    assert "vary" not in response.headers


@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br"])
async def test_minimum_size_and_exclusions(encoding: str) -> None:
    app = CompressionMiddleware(
        PlainTextResponse("x" * 500, media_type="image/png", headers={"vary": "Origin"}),
        exclude_content_types=(),
    )
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": encoding})
    assert response.text == "x" * 500
    assert response.headers["content-encoding"] == encoding
    assert response.headers["vary"] == "Origin, Accept-Encoding"


@pytest.mark.parametrize("scope_type", ["websocket", "lifespan"])
async def test_non_http(scope_type: str) -> None:
    events: list[Message] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        assert scope["type"] == scope_type
        await send(await receive())

    async def receive() -> Message:
        return {"type": "example"}

    async def send(message: Message) -> None:
        events.append(message)

    await CompressionMiddleware(app)({"type": scope_type}, receive, send)
    assert events == [{"type": "example"}]
