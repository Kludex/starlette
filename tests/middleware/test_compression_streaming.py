from __future__ import annotations

import sys
import zlib

import anyio
import brotli
import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.middleware.compression import CompressionMiddleware
from starlette.responses import PlainTextResponse
from starlette.types import Message, Receive, Scope, Send

if sys.version_info >= (3, 14):  # pragma: no cover - Depends on the Python version.
    from compression.zstd import ZstdDecompressor
else:  # pragma: no cover - Depends on the Python version.
    from backports.zstd import ZstdDecompressor

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br", "identity"])
@pytest.mark.parametrize("thread_minimum_size", [0, 131072])
async def test_streaming(encoding: str, thread_minimum_size: int) -> None:
    chunks = [b"", b"x" * 400, b"", b"y" * 400, b""]
    events: list[Message] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"800")]})
        for index, chunk in enumerate(chunks):
            await send({"type": "http.response.body", "body": chunk, "more_body": index < len(chunks) - 1})

    middleware = CompressionMiddleware(app, thread_minimum_size=thread_minimum_size)

    async def recording_app(scope: Scope, receive: Receive, send: Send) -> None:
        async def record(message: Message) -> None:
            events.append(message)
            await send(message)

        await middleware(scope, receive, record)

    async with AsyncClient(transport=ASGITransport(recording_app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": encoding})
    assert response.content == b"".join(chunks)
    assert response.headers["vary"] == "Accept-Encoding"
    assert len(events) == len(chunks) + 1
    if encoding == "identity":
        assert "content-encoding" not in response.headers
        assert response.headers["content-length"] == "800"
        assert [message["body"] for message in events[1:]] == chunks
    else:
        assert response.headers["content-encoding"] == encoding
        assert "content-length" not in response.headers
        if encoding == "br":
            brotli_decoder = brotli.Decompressor()
            for message, chunk in zip(events[1:], chunks):
                assert brotli_decoder.process(message["body"]) == chunk
            assert brotli_decoder.is_finished()
        else:
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else ZstdDecompressor()
            for message, chunk in zip(events[1:], chunks):
                assert decoder.decompress(message["body"]) == chunk
            assert decoder.eof


@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br"])
async def test_concurrent_and_repeated_responses(encoding: str) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        for _ in range(3):
            await send({"type": "http.response.body", "body": scope["path"].encode() * 500, "more_body": True})
            await anyio.sleep(0)
        await send({"type": "http.response.body", "body": b""})

    middleware = CompressionMiddleware(app, thread_minimum_size=0)
    async with AsyncClient(transport=ASGITransport(middleware), base_url="http://test") as client:

        async def request(path: str) -> None:
            response = await client.get(path, headers={"accept-encoding": encoding})
            assert response.content == path.encode() * 1500
            assert response.headers["content-encoding"] == encoding

        async with anyio.create_task_group() as task_group:
            for index in range(8):
                task_group.start_soon(request, f"/{index}")
        await request("/again")


@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br"])
async def test_large_response(encoding: str) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 131072))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        for _ in range(2):
            response = await client.get("/", headers={"accept-encoding": encoding})
            assert response.content == b"x" * 131072
            assert response.headers["content-encoding"] == encoding


@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br"])
async def test_pathsend(encoding: str) -> None:
    events: list[Message] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.pathsend", "path": "/example.txt"})

    async def receive() -> Message:
        return {"type": "http.request"}  # pragma: no cover - This application does not read the request.

    async def send(message: Message) -> None:
        events.append(message)

    await CompressionMiddleware(app)(
        {"type": "http", "headers": [(b"accept-encoding", encoding.encode())]}, receive, send
    )
    assert events == [
        {"type": "http.response.start", "status": 200, "headers": [(b"vary", b"Accept-Encoding")]},
        {"type": "http.response.pathsend", "path": "/example.txt"},
    ]
