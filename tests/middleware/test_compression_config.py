from __future__ import annotations

import sys

import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.middleware.compression import CompressionConfig, CompressionMiddleware
from starlette.responses import PlainTextResponse


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("gzip", "zstd", "encoding"),
    [(False, False, None), (False, {}, "zstd"), ({}, False, "gzip"), (True, True, "zstd")],
)
async def test_config(gzip: bool | CompressionConfig, zstd: bool | CompressionConfig, encoding: str | None) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 4000), gzip=gzip, zstd=zstd, brotli=False)
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "gzip, zstd"})
    assert response.text == "x" * 4000
    assert response.headers.get("content-encoding") == encoding
    assert ("vary" in response.headers) == (encoding is not None)


@pytest.mark.anyio
@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br"])
async def test_compression_levels(encoding: str) -> None:
    lengths: list[int] = []
    for level in [-5, 9] if encoding == "zstd" else [0, 9]:
        app = CompressionMiddleware(
            PlainTextResponse("x" * 4000),
            compresslevel=100,
            gzip={"compresslevel": max(0, level)},
            zstd={"compresslevel": level},
            brotli={"compresslevel": max(0, level)},
        )
        async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
            response = await client.get("/", headers={"accept-encoding": encoding})
        assert response.text == "x" * 4000
        lengths.append(int(response.headers["content-length"]))
    assert lengths[0] > lengths[1]


@pytest.mark.parametrize("minimum_size", [-1, -500])
def test_invalid_minimum_size(minimum_size: int) -> None:
    with pytest.raises(ValueError, match="minimum_size must be non-negative"):
        CompressionMiddleware(PlainTextResponse(""), minimum_size=minimum_size)


def test_invalid_thread_minimum_size() -> None:
    with pytest.raises(ValueError, match="thread_minimum_size must be non-negative"):
        CompressionMiddleware(PlainTextResponse(""), thread_minimum_size=-1)


@pytest.mark.parametrize("level", [-1, 10])
def test_invalid_gzip_level(level: int) -> None:
    with pytest.raises(ValueError, match="Gzip compresslevel must be between 0 and 9"):
        CompressionMiddleware(PlainTextResponse(""), gzip={"compresslevel": level}, zstd=False)


def test_invalid_zstd_level() -> None:
    with pytest.raises(ValueError, match="Zstandard compresslevel must be between"):
        CompressionMiddleware(PlainTextResponse(""), zstd={"compresslevel": 100})


@pytest.mark.anyio
async def test_missing_zstd(monkeypatch: pytest.MonkeyPatch) -> None:
    module = "compression.zstd" if sys.version_info >= (3, 14) else "backports.zstd"
    monkeypatch.setitem(sys.modules, module, None)
    app = CompressionMiddleware(PlainTextResponse("x" * 4000))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "zstd, gzip"})
    assert response.headers["content-encoding"] == "gzip"
    assert response.text == "x" * 4000
    with pytest.raises(RuntimeError, match=r"pip install starlette\[zstd\]"):
        CompressionMiddleware(PlainTextResponse(""), zstd=True)


@pytest.mark.anyio
@pytest.mark.parametrize("brotli", [None, True, {}, {"compresslevel": 11}, False])
async def test_brotli_config(brotli: bool | CompressionConfig | None) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * 4000), gzip=False, zstd=False, brotli=brotli)
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "br, gzip"})
    assert response.text == "x" * 4000
    assert response.headers.get("content-encoding") == (None if brotli is False else "br")


@pytest.mark.parametrize("level", [-1, 12])
def test_invalid_brotli_level(level: int) -> None:
    with pytest.raises(ValueError, match="Brotli compresslevel must be between 0 and 11"):
        CompressionMiddleware(PlainTextResponse(""), brotli={"compresslevel": level})


@pytest.mark.anyio
async def test_missing_brotli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "brotli", None)
    app = CompressionMiddleware(PlainTextResponse("x" * 4000))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "br, gzip"})
    assert response.headers["content-encoding"] == "gzip"
    assert response.text == "x" * 4000
    configs: tuple[bool | CompressionConfig, ...] = (True, {})
    for config in configs:
        with pytest.raises(RuntimeError, match=r"pip install starlette\[brotli\]"):
            CompressionMiddleware(PlainTextResponse(""), brotli=config)
    app = CompressionMiddleware(PlainTextResponse("x" * 4000), brotli=False)
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "br, gzip"})
    assert response.headers["content-encoding"] == "gzip"
