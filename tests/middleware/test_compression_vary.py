from __future__ import annotations

import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.middleware.compression import CompressionMiddleware
from starlette.responses import PlainTextResponse

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("encoding", ["gzip", "zstd", "br"])
@pytest.mark.parametrize("size", [0, 5, 499])
async def test_small_response_variants(encoding: str, size: int) -> None:
    app = CompressionMiddleware(PlainTextResponse("x" * size, headers={"cache-control": "public, max-age=60"}))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        plain = await client.get("/", headers={"accept-encoding": encoding})
        compressed = await client.get("/", headers={"accept-encoding": f"{encoding}, identity;q=0"})
    assert plain.content == compressed.content == b"x" * size
    assert "content-encoding" not in plain.headers
    assert compressed.headers["content-encoding"] == encoding
    assert plain.headers.get("vary") == compressed.headers["vary"] == "Accept-Encoding"


@pytest.mark.parametrize("headers", [{"content-encoding": "custom"}, {"content-type": "image/png"}])
async def test_excluded_response_variants(headers: dict[str, str]) -> None:
    app = CompressionMiddleware(PlainTextResponse("hello", headers=headers))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        accepted = await client.get("/", headers={"accept-encoding": "gzip, custom"})
        rejected = await client.get("/", headers={"accept-encoding": "*;q=0"})
    assert accepted.status_code == 200
    assert rejected.status_code == 406
    assert accepted.headers.get("vary") == rejected.headers["vary"] == "Accept-Encoding"
