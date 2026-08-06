from __future__ import annotations

import asyncio
from typing import Any

import httpx2 as httpx
import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.brotli import BrotliMiddleware, Mode
from starlette.requests import Request
from starlette.responses import ContentStream, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route, WebSocketRoute
from starlette.types import Message, Receive, Scope, Send
from starlette.websockets import WebSocket
from tests.types import TestClientFactory

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app(**mw_kwargs: Any) -> Starlette:
    """Build a Starlette app with several routes wrapped in BrotliMiddleware."""

    async def big(request: Request) -> Response:
        # 4000 bytes of highly compressible text.
        return PlainTextResponse("a" * 4000)

    async def small(request: Request) -> Response:
        # 20 bytes, below the default minimum_size=400.
        return PlainTextResponse("hello world, small!")

    async def stream(request: Request) -> Response:
        async def gen() -> ContentStream:
            for i in range(5):
                # Each chunk is large enough to be worth compressing.
                yield f"chunk-{i}-".encode() + b"x" * 1000

        return StreamingResponse(gen(), media_type="text/plain")

    async def sse(request: Request) -> Response:
        async def gen() -> ContentStream:
            yield b"data: hello\n\n"
            yield b"data: world\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    async def size_endpoint(request: Request) -> Response:
        n = int(request.query_params["n"])
        return PlainTextResponse("a" * n)

    routes = [
        Route("/big", big),
        Route("/small", small),
        Route("/stream", stream),
        Route("/sse", sse),
        Route("/size", size_endpoint),
    ]
    middleware = [Middleware(BrotliMiddleware, **mw_kwargs)]
    return Starlette(routes=routes, middleware=middleware)


def _compressed_len(r: httpx.Response) -> int:
    """Return the on-wire compressed body length.

    httpx auto-decompresses brotli/gzip, so r.content is the decompressed
    payload. The Content-Length header carries the compressed (on-wire) length
    for non-streaming responses.
    """
    cl = r.headers.get("content-length")
    assert cl is not None
    return int(cl)


# ---------------------------------------------------------------------------
# Brotli path
# ---------------------------------------------------------------------------


def test_brotli_responses(test_client_factory: TestClientFactory) -> None:
    app = _make_app()
    client = test_client_factory(app)
    response = client.get("/big", headers={"accept-encoding": "br"})
    assert response.status_code == 200
    assert response.text == "a" * 4000
    assert response.headers["Content-Encoding"] == "br"
    assert response.headers["Vary"] == "Accept-Encoding"
    assert int(response.headers["Content-Length"]) < 4000


def test_brotli_not_in_accept_encoding(test_client_factory: TestClientFactory) -> None:
    # BrotliMiddleware does not wrap the inner app with IdentityResponder when
    # neither br nor gzip is accepted, so it passes the response through
    # verbatim (no Vary header, no compression, original Content-Length).
    app = _make_app()
    client = test_client_factory(app)
    response = client.get("/big", headers={"accept-encoding": "identity"})
    assert response.status_code == 200
    assert response.text == "a" * 4000
    assert "Content-Encoding" not in response.headers
    assert "Vary" not in response.headers
    assert int(response.headers["Content-Length"]) == 4000


def test_brotli_ignored_for_small_responses(test_client_factory: TestClientFactory) -> None:
    app = _make_app()
    client = test_client_factory(app)
    response = client.get("/small", headers={"accept-encoding": "br"})
    assert response.status_code == 200
    assert response.text == "hello world, small!"
    assert "Content-Encoding" not in response.headers
    assert "Vary" not in response.headers
    assert int(response.headers["Content-Length"]) == len("hello world, small!")


def test_brotli_minimum_size_boundary(test_client_factory: TestClientFactory) -> None:
    # minimum_size=400; verify the boundary is inclusive (>=400 compresses).
    app = _make_app(minimum_size=400)
    client = test_client_factory(app)
    r_just_below = client.get("/size", params={"n": 399}, headers={"accept-encoding": "br"})
    r_boundary = client.get("/size", params={"n": 400}, headers={"accept-encoding": "br"})

    assert "content-encoding" not in r_just_below.headers
    assert r_just_below.content == b"a" * 399
    assert r_boundary.headers["content-encoding"] == "br"
    assert r_boundary.content == b"a" * 400


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


def test_brotli_streaming_response(test_client_factory: TestClientFactory) -> None:
    app = _make_app()
    client = test_client_factory(app)
    response = client.get("/stream", headers={"accept-encoding": "br"})
    assert response.status_code == 200
    assert response.text == "".join(f"chunk-{i}-" + "x" * 1000 for i in range(5))
    assert response.headers["Content-Encoding"] == "br"
    assert response.headers["Vary"] == "Accept-Encoding"
    assert "Content-Length" not in response.headers


def test_brotli_streaming_response_identity(test_client_factory: TestClientFactory) -> None:
    # Accept-Encoding: identity -> BrotliMiddleware passes through unchanged
    # (no IdentityResponder wrapping, so no Vary header).
    app = _make_app()
    client = test_client_factory(app)
    response = client.get("/stream", headers={"accept-encoding": "identity"})
    assert response.status_code == 200
    assert response.text == "".join(f"chunk-{i}-" + "x" * 1000 for i in range(5))
    assert "Content-Encoding" not in response.headers
    assert "Vary" not in response.headers
    assert "Content-Length" not in response.headers


# ---------------------------------------------------------------------------
# GZip fallback
# ---------------------------------------------------------------------------


def test_brotli_gzip_only_uses_gzip_fallback(test_client_factory: TestClientFactory) -> None:
    app = _make_app()
    client = test_client_factory(app)
    response = client.get("/big", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Vary"] == "Accept-Encoding"
    assert int(response.headers["Content-Length"]) < 4000
    assert response.text == "a" * 4000


def test_brotli_gzip_fallback_disabled(test_client_factory: TestClientFactory) -> None:
    app = _make_app(gzip_fallback=False)
    client = test_client_factory(app)
    response = client.get("/big", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    # gzip_fallback=False -> no compression when only gzip is accepted.
    assert "Content-Encoding" not in response.headers
    assert response.text == "a" * 4000


def test_brotli_wins_over_gzip_when_both_accepted(test_client_factory: TestClientFactory) -> None:
    app = _make_app()
    client = test_client_factory(app)
    response = client.get("/big", headers={"accept-encoding": "br, gzip"})
    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "br"


# ---------------------------------------------------------------------------
# Bypass paths
# ---------------------------------------------------------------------------


def test_brotli_ignored_for_responses_with_encoding_set() -> None:
    """Verify the 'content_encoding_set' bypass via a direct ASGI call.

    We can't use TestClient here because httpx would try to decompress the
    response body (which advertises Content-Encoding: gzip but is actually
    plaintext). Instead we capture the raw ASGI messages and assert that:
      - Content-Encoding: gzip is preserved (not overwritten with br)
      - The body is forwarded unchanged (no brotli re-compression)
    """
    received: list[Message] = []

    async def inner_app(scope: Scope, receive: Receive, send: Send) -> None:
        _ = await receive()  # consume the (empty) request body
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                    (b"content-encoding", b"gzip"),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"a" * 4000,
                "more_body": False,
            }
        )

    async def capturing_send(message: Message) -> None:
        received.append(message)

    async def run() -> None:
        mw = BrotliMiddleware(inner_app)
        scope: Scope = {
            "type": "http",
            "method": "GET",
            "path": "/already",
            "headers": [(b"accept-encoding", b"br")],
            "query_string": b"",
            "extensions": {},
            "http_version": "1.1",
            "scheme": "http",
            "server": ("test", 80),
            "client": ("test", 0),
            "root_path": "",
        }

        async def receive() -> Message:
            return {"type": "http.request", "body": b"", "more_body": False}

        await mw(scope, receive, capturing_send)

    asyncio.run(run())

    assert len(received) == 2
    start = received[0]
    body = received[1]
    assert start["type"] == "http.response.start"
    headers = dict(start["headers"])
    # Content-Encoding: gzip must be preserved (not overwritten with br).
    assert headers[b"content-encoding"] == b"gzip"
    # Body must be forwarded unchanged (not re-compressed).
    assert body["body"] == b"a" * 4000


def test_brotli_ignored_on_server_sent_events(test_client_factory: TestClientFactory) -> None:
    app = _make_app()
    client = test_client_factory(app)
    response = client.get("/sse", headers={"accept-encoding": "br"})
    assert response.status_code == 200
    assert response.text == "data: hello\n\ndata: world\n\n"
    assert "Content-Encoding" not in response.headers
    assert "Content-Length" not in response.headers


def test_brotli_excluded_handlers_skip_compression(test_client_factory: TestClientFactory) -> None:
    app = _make_app(excluded_handlers=[r"^/big$"])
    client = test_client_factory(app)
    response = client.get("/big", headers={"accept-encoding": "br"})
    assert response.status_code == 200
    assert "Content-Encoding" not in response.headers
    assert response.text == "a" * 4000


def test_brotli_pathsend_event_is_passed_through_unchanged() -> None:
    """Directly exercise the pathsend branch of IdentityResponder via a custom
    ASGI app that emits http.response.pathsend events.

    TestClient does not advertise the pathsend extension, so FileResponse
    would fall back to normal file reads (and get compressed).
    """
    received: list[Message] = []

    async def inner_app(scope: Scope, receive: Receive, send: Send) -> None:
        # Emit a normal start + a pathsend event (what FileResponse does when
        # the server advertises pathsend support).
        _ = await receive()  # consume the (empty) request body
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send(
            {
                "type": "http.response.pathsend",
                "path": "/tmp/some-file.txt",
            }
        )

    async def capturing_send(message: Message) -> None:
        received.append(message)

    async def run() -> None:
        mw = BrotliMiddleware(inner_app)
        scope: Scope = {
            "type": "http",
            "method": "GET",
            "path": "/file",
            "headers": [(b"accept-encoding", b"br")],
            "query_string": b"",
            "extensions": {"http.response.pathsend": {}},
            "http_version": "1.1",
            "scheme": "http",
            "server": ("test", 80),
            "client": ("test", 0),
            "root_path": "",
        }

        async def receive() -> Message:
            return {"type": "http.request", "body": b"", "more_body": False}

        await mw(scope, receive, capturing_send)

    asyncio.run(run())

    # The pathsend branch must:
    #  - forward the initial start message unchanged
    #  - forward the pathsend event unchanged
    #  - NOT set Content-Encoding: br (no compression)
    assert len(received) == 2
    assert received[0]["type"] == "http.response.start"
    assert received[0]["status"] == 200
    headers = dict(received[0]["headers"])
    assert b"content-encoding" not in headers
    assert received[1]["type"] == "http.response.pathsend"
    assert received[1]["path"] == "/tmp/some-file.txt"


# ---------------------------------------------------------------------------
# Threading
# ---------------------------------------------------------------------------


def test_brotli_compression_in_thread(test_client_factory: TestClientFactory) -> None:
    # thread_minimum_size=1 forces EVERY body through anyio.to_thread, exercising
    # the worker-thread path on the smallest possible input.
    app = _make_app(thread_minimum_size=1)
    client = test_client_factory(app)
    response = client.get("/big", headers={"accept-encoding": "br"})
    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "br"
    assert response.text == "a" * 4000
    assert int(response.headers["Content-Length"]) < 4000


def test_brotli_streaming_compression_in_thread(test_client_factory: TestClientFactory) -> None:
    app = _make_app(thread_minimum_size=1)
    client = test_client_factory(app)
    response = client.get("/stream", headers={"accept-encoding": "br"})
    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "br"
    assert response.text == "".join(f"chunk-{i}-" + "x" * 1000 for i in range(5))


# ---------------------------------------------------------------------------
# Quality
# ---------------------------------------------------------------------------


def test_brotli_quality_affects_size(test_client_factory: TestClientFactory) -> None:
    # Higher quality => smaller (or equal) output for highly compressible input.
    # Build two apps at q=0 and q=11 and compare compressed sizes.
    app_q0 = _make_app(quality=0)
    app_q11 = _make_app(quality=11)
    c0 = test_client_factory(app_q0)
    c11 = test_client_factory(app_q11)
    r0 = c0.get("/big", headers={"accept-encoding": "br"})
    r11 = c11.get("/big", headers={"accept-encoding": "br"})

    assert r0.headers["content-encoding"] == "br"
    assert r11.headers["content-encoding"] == "br"
    # Both must roundtrip correctly (httpx decompresses).
    assert r0.text == "a" * 4000
    assert r11.text == "a" * 4000
    # And q=11 should be at least as small as q=0 (on-wire size).
    assert _compressed_len(r11) <= _compressed_len(r0)


# ---------------------------------------------------------------------------
# Mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode_name", ["text", "generic", "font"])
def test_brotli_mode_string_is_accepted(test_client_factory: TestClientFactory, mode_name: str) -> None:
    # Just verify construction + a round-trip works for each mode.
    app = _make_app(mode=mode_name)
    client = test_client_factory(app)
    response = client.get("/big", headers={"accept-encoding": "br"})
    assert response.status_code == 200
    assert response.headers["Content-Encoding"] == "br"
    assert response.text == "a" * 4000


def test_brotli_mode_constants_match_brotli() -> None:
    assert Mode.text == 1
    assert Mode.generic == 0
    assert Mode.font == 2


# ---------------------------------------------------------------------------
# Non-HTTP scope
# ---------------------------------------------------------------------------


def test_brotli_websocket_scope_passes_through(test_client_factory: TestClientFactory) -> None:
    # BrotliMiddleware should not interfere with websocket handshakes.
    async def ws_endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("hello")
        await websocket.close()

    app = Starlette(
        routes=[WebSocketRoute("/ws", ws_endpoint)],
        middleware=[Middleware(BrotliMiddleware)],
    )
    client = test_client_factory(app)
    with client.websocket_connect("/ws") as ws:
        msg = ws.receive_text()
    assert msg == "hello"
