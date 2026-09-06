from __future__ import annotations

from pathlib import Path

import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.middleware.compression import CompressionMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.responses import FileResponse, PlainTextResponse, Response
from starlette.staticfiles import StaticFiles
from starlette.types import Message, Receive, Scope, Send

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("middleware", [CompressionMiddleware, GZipMiddleware])
@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br", "identity"])
@pytest.mark.parametrize("status", [204, 205, 304])
async def test_bodyless_response(
    middleware: type[CompressionMiddleware] | type[GZipMiddleware], encoding: str, status: int
) -> None:
    events: list[Message] = []
    wrapped = middleware(Response(status_code=status), minimum_size=0)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        async def record(message: Message) -> None:
            events.append(message)
            await send(message)

        await wrapped(scope, receive, record)

    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": encoding})
    assert response.status_code == status
    assert response.content == b""
    assert "content-encoding" not in response.headers
    assert response.headers.get("content-length") in (None, "0")
    assert events[1]["body"] == b""
    if status == 204:
        assert "content-length" not in response.headers


@pytest.mark.parametrize("middleware", [CompressionMiddleware, GZipMiddleware])
@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br", "identity"])
async def test_file_metadata(
    tmp_path: Path, middleware: type[CompressionMiddleware] | type[GZipMiddleware], encoding: str
) -> None:
    path = tmp_path / "body.txt"
    path.write_bytes(b"x" * 4000)

    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        await FileResponse(path)(scope, receive, send)

    async with AsyncClient(transport=ASGITransport(middleware(endpoint)), base_url="http://test") as client:
        plain = await client.get("/", headers={"accept-encoding": "identity"})
        get = await client.get("/", headers={"accept-encoding": encoding})
        head = await client.head("/", headers={"accept-encoding": encoding})
        ranged = await client.get(
            "/", headers={"accept-encoding": encoding, "range": "bytes=0-9", "if-range": get.headers["etag"]}
        )
    assert get.content == b"x" * 4000
    assert head.content == b""
    assert head.headers.get("content-length") in (None, get.headers["content-length"])
    assert head.headers["vary"] == get.headers["vary"] == "Accept-Encoding"
    compressed = "content-encoding" in get.headers
    assert get.headers["etag"] == ("W/" if compressed else "") + plain.headers["etag"]
    assert head.headers["etag"] == get.headers["etag"]
    assert ranged.status_code == (200 if compressed else 206)
    assert ranged.content == (b"x" * 4000 if compressed else b"x" * 10)


@pytest.mark.parametrize("middleware", [CompressionMiddleware, GZipMiddleware])
@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br", "identity"])
async def test_not_modified_metadata(
    tmp_path: Path, middleware: type[CompressionMiddleware] | type[GZipMiddleware], encoding: str
) -> None:
    (tmp_path / "body.txt").write_bytes(b"x" * 4000)
    app = middleware(StaticFiles(directory=tmp_path))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        get = await client.get("/body.txt", headers={"accept-encoding": encoding})
        conditional = await client.get(
            "/body.txt", headers={"accept-encoding": encoding, "if-none-match": get.headers["etag"]}
        )
    assert conditional.status_code == 304
    assert conditional.content == b""
    assert conditional.headers["vary"] == get.headers["vary"] == "Accept-Encoding"
    assert conditional.headers["etag"] == get.headers["etag"]
    assert "content-length" not in conditional.headers


@pytest.mark.parametrize("etag", ['"strong"', 'W/"weak"'])
@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br", "identity"])
async def test_etag_strength(etag: str, encoding: str) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 4000, headers={"etag": etag}))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": encoding})
    assert response.headers["etag"] == ("W/" + etag if encoding != "identity" and not etag.startswith("W/") else etag)
