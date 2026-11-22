from __future__ import annotations

import threading
import zlib

import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.middleware.compression import CompressionMiddleware, Compressor
from starlette.responses import PlainTextResponse
from starlette.types import Receive, Scope, Send


@pytest.mark.anyio
@pytest.mark.parametrize("thread_minimum_size", [0, 131072])
async def test_custom_compressor(thread_minimum_size: int) -> None:
    factories: list[int] = []
    threads: list[int] = []

    def factory() -> Compressor:
        factories.append(threading.get_ident())
        compressor = zlib.compressobj()

        def compress(body: bytes, more_body: bool) -> bytes:
            threads.append(threading.get_ident())
            return compressor.compress(body) + compressor.flush(zlib.Z_SYNC_FLUSH if more_body else zlib.Z_FINISH)

        return compress

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"x" * 4000, "more_body": True})
        await send({"type": "http.response.body", "body": b"y" * 4000})

    middleware = CompressionMiddleware(
        app, thread_minimum_size=thread_minimum_size, extra_compressors={"Deflate": factory}
    )
    async with AsyncClient(transport=ASGITransport(middleware), base_url="http://test") as client:
        for _ in range(2):
            response = await client.get("/", headers={"accept-encoding": "gzip, deflate"})
            assert response.content == b"x" * 4000 + b"y" * 4000
            assert response.headers["content-encoding"] == "deflate"
    assert len(factories) == 2
    assert len(threads) == 4
    assert all((thread != threading.get_ident()) == (thread_minimum_size == 0) for thread in factories + threads)


@pytest.mark.anyio
@pytest.mark.parametrize("chunk_size", [4000, 131072])
async def test_buffered_custom_compressor(chunk_size: int) -> None:
    threads: list[int] = []

    def factory() -> Compressor:
        buffer = bytearray()

        def compress(body: bytes, more_body: bool) -> bytes:
            threads.append(threading.get_ident())
            buffer.extend(body)
            return b"" if more_body else zlib.compress(bytes(buffer))

        return compress

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"", "more_body": True})
        for _ in range(40):
            await send({"type": "http.response.body", "body": b"x" * chunk_size, "more_body": True})
        await send({"type": "http.response.body", "body": b""})

    middleware = CompressionMiddleware(app, extra_compressors={"deflate": factory})
    async with AsyncClient(transport=ASGITransport(middleware), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "deflate"})
    assert response.content == b"x" * chunk_size * 40
    assert response.headers["content-encoding"] == "deflate"
    assert threads[0] == threading.get_ident()
    for index, thread in enumerate(threads[1:-1], start=1):
        assert (thread != threading.get_ident()) == (index * chunk_size >= 131072)
    assert threads[-1] != threading.get_ident()


@pytest.mark.anyio
@pytest.mark.parametrize("size", [0, 499, 4000])
async def test_lazy_factory(size: int) -> None:
    def factory() -> Compressor:
        raise ValueError("Factory called")

    app = CompressionMiddleware(PlainTextResponse("x" * size), extra_compressors={"custom": factory})
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "identity"})
        assert response.text == "x" * size
        if size < 500:
            response = await client.get("/", headers={"accept-encoding": "custom"})
            assert response.text == "x" * size
        else:
            with pytest.raises(ValueError, match="Factory called"):
                await client.get("/", headers={"accept-encoding": "custom"})


@pytest.mark.parametrize("encoding", ["", "*", "identity", "GZIP", "zstd", "br", "bad token", "a;b", "a\r\nb"])
def test_invalid_custom_encoding(encoding: str) -> None:
    def factory() -> Compressor:
        raise AssertionError(
            "Compressor must not be created during configuration"
        )  # pragma: no cover - Invalid config.

    with pytest.raises(ValueError, match="Invalid or reserved compression encoding"):
        CompressionMiddleware(PlainTextResponse(""), extra_compressors={encoding: factory})


def test_duplicate_custom_encoding() -> None:
    def factory() -> Compressor:
        raise AssertionError(
            "Compressor must not be created during configuration"
        )  # pragma: no cover - Invalid config.

    with pytest.raises(ValueError, match="Invalid or reserved compression encoding"):
        CompressionMiddleware(PlainTextResponse(""), extra_compressors={"Custom": factory, "custom": factory})
