from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from starlette.middleware.compression import CompressionMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

pytestmark = pytest.mark.anyio


async def capture(app: ASGIApp, scope: Scope) -> list[Message]:
    events: list[Message] = []

    async def receive() -> Message:
        return {"type": "http.request"}  # pragma: no cover - These applications do not read the request.

    async def send(message: Message) -> None:
        events.append(message)

    await app(scope, receive, send)
    return events


@pytest.mark.parametrize("middleware", [CompressionMiddleware, GZipMiddleware])
@pytest.mark.parametrize("encoding", ["gzip", "identity"])
async def test_control_events(middleware: type[CompressionMiddleware] | type[GZipMiddleware], encoding: str) -> None:
    hints: Message = {"type": "http.response.early_hint", "links": [b"</style.css>; rel=preload"]}
    debug: Message = {"type": "http.response.debug", "info": {"template": "index.html"}}
    push: Message = {"type": "http.response.push", "path": "/style.css", "headers": []}
    trailers: list[Message] = [
        {"type": "http.response.trailers", "headers": [(b"server-timing", b"app;dur=10")], "more_trailers": True},
        {"type": "http.response.trailers", "headers": [(b"x-checksum", b"test")]},
    ]

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(hints)
        await send(debug)
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send(push)
        await send({"type": "http.response.body", "body": b"x" * 4000, "more_body": True})
        await send({"type": "http.response.body"})
        for trailer in trailers:
            await send(trailer)

    events = await capture(middleware(app), {"type": "http", "headers": [(b"accept-encoding", encoding.encode())]})
    assert events[:2] == [hints, debug]
    assert events[2]["type"] == "http.response.start"
    assert events[2]["trailers"] is True
    assert events[3] == push
    assert events[6:] == trailers
    body = b"".join(event.get("body", b"") for event in events[4:6])
    assert (gzip.decompress(body) if encoding == "gzip" else body) == b"x" * 4000


@pytest.mark.parametrize("middleware", [CompressionMiddleware, GZipMiddleware])
@pytest.mark.parametrize("encoding", ["gzip", "identity"])
async def test_zerocopy_fallback(
    tmp_path: Path, middleware: type[CompressionMiddleware] | type[GZipMiddleware], encoding: str
) -> None:
    path = tmp_path / "body.txt"
    path.write_bytes(b"x" * 4000)
    scope: Scope = {
        "type": "http",
        "headers": [(b"accept-encoding", encoding.encode())],
        "extensions": {"http.response.zerocopysend": {}, "http.response.trailers": {}},
    }
    with path.open("rb") as file:
        zero: Message = {"type": "http.response.zerocopysend", "file": file, "more_body": True}

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            assert "http.response.trailers" in scope["extensions"]
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"prefix", "more_body": True})
            if "http.response.zerocopysend" in scope["extensions"]:
                await send(zero)
            else:
                await send({"type": "http.response.body", "body": file.read(), "more_body": True})
            await send({"type": "http.response.body", "body": b"suffix"})

        events = await capture(middleware(app), scope)
    assert "http.response.zerocopysend" in scope["extensions"]
    assert len(events) == 4
    if encoding == "gzip":
        assert dict(events[0]["headers"])[b"content-encoding"] == b"gzip"
        assert gzip.decompress(b"".join(event["body"] for event in events[1:])) == b"prefix" + b"x" * 4000 + b"suffix"
    else:
        assert events[1]["body"] == b"prefix"
        assert events[2] == zero
        assert events[3]["body"] == b"suffix"


@pytest.mark.parametrize("extension", ["http.response.pathsend", "http.response.zerocopysend"])
@pytest.mark.parametrize("accepted", ["gzip", "gzip, identity;q=0"])
async def test_file_extension_negotiation(tmp_path: Path, extension: str, accepted: str) -> None:
    path = tmp_path / "body.txt"
    path.write_bytes(b"x" * 4000)
    with path.open("rb") as file:
        transfer: Message = {
            "type": extension,
            **({"path": str(path)} if extension.endswith("pathsend") else {"file": file}),
        }

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"4000")]})
            await send(transfer)

        events = await capture(
            CompressionMiddleware(app), {"type": "http", "headers": [(b"accept-encoding", accepted.encode())]}
        )
    assert events[0]["type"] == "http.response.start"
    assert events[0]["status"] == (200 if accepted == "gzip" else 406)
    assert events[1] == (transfer if accepted == "gzip" else {"type": "http.response.body", "body": b"Not Acceptable"})


async def test_body_before_start() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.body", "body": b"hello"})

    with pytest.raises(AssertionError, match="Response body received before response start"):
        await capture(CompressionMiddleware(app), {"type": "http", "headers": []})
