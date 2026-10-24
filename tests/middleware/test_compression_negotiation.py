from __future__ import annotations

import base64
import gzip
import hashlib
import sys
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
from starlette.types import Message, Receive, Scope, Send

if sys.version_info >= (3, 14):  # pragma: no cover - Depends on the Python version.
    from compression.zstd import ZstdDecompressor, ZstdDict
else:  # pragma: no cover - Depends on the Python version.
    from backports.zstd import ZstdDecompressor, ZstdDict

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
            for _ in repeat(None):  # pragma: no branch - The infinite stream terminates only by cancellation.
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


@pytest.mark.parametrize("vary", [["Origin, accept-encoding"], ["*"], ["Origin", "*"], ["Origin", "Accept-Encoding"]])
async def test_vary_is_not_duplicated(vary: list[str]) -> None:
    endpoint = PlainTextResponse("x" * 4000)
    for value in vary:
        endpoint.headers.append("vary", value)
    app = CompressionMiddleware(endpoint)
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "gzip"})
    assert response.headers.get_list("vary") == vary


DICTIONARY = b'{"id": 0, "name": "", "email": "", "roles": ["admin", "member"], "active": true}' * 20
AVAILABLE_DICTIONARY = ":" + base64.b64encode(hashlib.sha256(DICTIONARY).digest()).decode() + ":"


def dcz_decoder(dictionary: bytes) -> ZstdDecompressor:
    return ZstdDecompressor(zstd_dict=ZstdDict(dictionary, is_raw=True).as_prefix)


def dcz_header(dictionary: bytes) -> bytes:
    return b"\x5e\x2a\x4d\x18\x20\x00\x00\x00" + hashlib.sha256(dictionary).digest()


@pytest.mark.parametrize("accepted", ["dcz, zstd, gzip", "gzip, deflate, br, zstd, dcb, dcz", "dcz"])
@pytest.mark.parametrize("zstd", [None, False])
async def test_dictionary_compression(accepted: str, zstd: bool | None) -> None:
    body = '{"id": 7, "name": "Ada", "email": "ada@example.com", "roles": ["admin"], "active": true}' * 50
    app = CompressionMiddleware(PlainTextResponse(body), dictionaries=[DICTIONARY], gzip=False, brotli=False, zstd=zstd)
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get(
            "/", headers={"accept-encoding": accepted, "available-dictionary": AVAILABLE_DICTIONARY}
        )
    assert response.status_code == 200
    assert response.headers["content-encoding"] == "dcz"
    assert response.headers["vary"] == "Accept-Encoding, Available-Dictionary"
    assert response.headers["content-length"] == str(len(response.content))
    assert response.content[:40] == dcz_header(DICTIONARY)
    assert dcz_decoder(DICTIONARY).decompress(response.content[40:]) == body.encode()
    assert len(response.content) < len(body) // 10


@pytest.mark.parametrize(
    ("accepted", "available", "encoding"),
    [
        ("dcz, zstd", None, "zstd"),
        ("dcz, zstd", "not-a-byte-sequence", "zstd"),
        ("dcz, zstd", ":not base64!:", "zstd"),
        ("dcz, zstd", ":" + base64.b64encode(hashlib.sha256(b"other").digest()).decode() + ":", "zstd"),
        ("zstd, gzip", AVAILABLE_DICTIONARY, "zstd"),
        ("gzip", AVAILABLE_DICTIONARY, "gzip"),
    ],
)
async def test_dictionary_fallback(accepted: str, available: str | None, encoding: str) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 4000), dictionaries=[DICTIONARY])
    headers = {"accept-encoding": accepted}
    if available is not None:
        headers["available-dictionary"] = available
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers=headers)
    assert response.text == "x" * 4000
    assert response.headers["content-encoding"] == encoding
    assert response.headers["vary"] == "Accept-Encoding, Available-Dictionary"


async def test_dictionary_streaming() -> None:
    chunks = [b"x" * 400, b"", DICTIONARY[:300], b""]
    events: list[Message] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        for index, chunk in enumerate(chunks):
            await send({"type": "http.response.body", "body": chunk, "more_body": index < len(chunks) - 1})

    middleware = CompressionMiddleware(app, dictionaries=[DICTIONARY])

    async def recording_app(scope: Scope, receive: Receive, send: Send) -> None:
        async def record(message: Message) -> None:
            events.append(message)
            await send(message)

        await middleware(scope, receive, record)

    async with AsyncClient(transport=ASGITransport(recording_app), base_url="http://test") as client:
        response = await client.get(
            "/", headers={"accept-encoding": "dcz, zstd", "available-dictionary": AVAILABLE_DICTIONARY}
        )
    assert response.headers["content-encoding"] == "dcz"
    assert "content-length" not in response.headers
    assert len(events) == len(chunks) + 1
    assert events[1]["body"][:40] == dcz_header(DICTIONARY)
    decoder = dcz_decoder(DICTIONARY)
    assert decoder.decompress(events[1]["body"][40:]) == chunks[0]
    for message, chunk in zip(events[2:], chunks[1:]):
        assert decoder.decompress(message["body"]) == chunk
    assert decoder.eof
