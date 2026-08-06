from __future__ import annotations

import hashlib
import zlib
from pathlib import Path

import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware, GZipResponder
from starlette.requests import Request
from starlette.responses import ContentStream, FileResponse, PlainTextResponse, StreamingResponse
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send
from tests.types import TestClientFactory


def test_gzip_responses(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("x" * 4000, status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(GZipMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.text == "x" * 4000
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Vary"] == "Accept-Encoding"
    assert int(response.headers["Content-Length"]) < 4000


def test_gzip_not_in_accept_encoding(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("x" * 4000, status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(GZipMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "identity"})
    assert response.status_code == 200
    assert response.text == "x" * 4000
    assert "Content-Encoding" not in response.headers
    assert response.headers["Vary"] == "Accept-Encoding"
    assert int(response.headers["Content-Length"]) == 4000


def test_gzip_ignored_for_small_responses(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(GZipMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.text == "OK"
    assert "Content-Encoding" not in response.headers
    assert "Vary" not in response.headers
    assert int(response.headers["Content-Length"]) == 2


def test_gzip_streaming_response(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> StreamingResponse:
        async def generator(bytes: bytes, count: int) -> ContentStream:
            for index in range(count):
                yield bytes

        streaming = generator(bytes=b"x" * 400, count=10)
        return StreamingResponse(streaming, status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(GZipMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.text == "x" * 4000
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Vary"] == "Accept-Encoding"
    assert "Content-Length" not in response.headers


def test_gzip_compression_in_thread(test_client_factory: TestClientFactory) -> None:
    payload = "x" * (128 * 1024)

    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse(payload, status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        # Ensure the response body takes the worker-thread compression path.
        middleware=[Middleware(GZipMiddleware, thread_minimum_size=len(payload))],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.text == payload
    assert response.headers["Content-Encoding"] == "gzip"
    assert int(response.headers["Content-Length"]) < len(payload)


def test_gzip_streaming_compression_in_thread(test_client_factory: TestClientFactory) -> None:
    chunk = hashlib.shake_256(b"starlette-gzip-stream").digest(256 * 1024)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"tail"})

    # Ensure the streamed chunk takes the worker-thread compression path.
    middleware = GZipMiddleware(app, thread_minimum_size=len(chunk))
    events: list[Message] = []

    async def recording_app(scope: Scope, receive: Receive, send: Send) -> None:
        async def record(message: Message) -> None:
            events.append(message)
            await send(message)

        await middleware(scope, receive, record)

    client = test_client_factory(recording_app)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.content == chunk + b"tail"
    assert response.headers["Content-Encoding"] == "gzip"

    assert len(events) == 3
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    assert decompressor.decompress(events[1]["body"]) == chunk
    assert decompressor.decompress(events[2]["body"]) == b"tail"


def test_gzip_streaming_response_identity(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> StreamingResponse:
        async def generator(bytes: bytes, count: int) -> ContentStream:
            for index in range(count):
                yield bytes

        streaming = generator(bytes=b"x" * 400, count=10)
        return StreamingResponse(streaming, status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(GZipMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "identity"})
    assert response.status_code == 200
    assert response.text == "x" * 4000
    assert "Content-Encoding" not in response.headers
    assert response.headers["Vary"] == "Accept-Encoding"
    assert "Content-Length" not in response.headers


def test_gzip_ignored_for_responses_with_encoding_set(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> StreamingResponse:
        async def generator(bytes: bytes, count: int) -> ContentStream:
            for index in range(count):
                yield bytes

        streaming = generator(bytes=b"x" * 400, count=10)
        return StreamingResponse(streaming, status_code=200, headers={"Content-Encoding": "text"})

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(GZipMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "gzip, text"})
    assert response.status_code == 200
    assert response.text == "x" * 4000
    assert response.headers["Content-Encoding"] == "text"
    assert "Vary" not in response.headers
    assert "Content-Length" not in response.headers


def test_gzip_ignored_on_server_sent_events(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> StreamingResponse:
        async def generator(bytes: bytes, count: int) -> ContentStream:
            for _ in range(count):
                yield bytes

        streaming = generator(bytes=b"x" * 400, count=10)
        return StreamingResponse(streaming, status_code=200, media_type="text/event-stream")

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(GZipMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.text == "x" * 4000
    assert "Content-Encoding" not in response.headers
    assert "Content-Length" not in response.headers


@pytest.mark.anyio
async def test_gzip_ignored_for_pathsend_responses(tmpdir: Path) -> None:
    path = tmpdir / "example.txt"
    with path.open("w") as file:
        file.write("<file content>")

    events: list[Message] = []

    async def endpoint_with_pathsend(request: Request) -> FileResponse:
        _ = await request.body()
        return FileResponse(path)

    app = Starlette(
        routes=[Route("/", endpoint=endpoint_with_pathsend)],
        middleware=[Middleware(GZipMiddleware)],
    )

    scope = {
        "type": "http",
        "version": "3",
        "method": "GET",
        "path": "/",
        "headers": [(b"accept-encoding", b"gzip, text")],
        "extensions": {"http.response.pathsend": {}},
    }

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Message) -> None:
        events.append(message)

    await app(scope, receive, send)

    assert len(events) == 2
    assert events[0]["type"] == "http.response.start"
    assert events[1]["type"] == "http.response.pathsend"


def test_gzip_ignored_on_range_responses(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    path = tmp_path / "example.txt"
    path.write_text("x" * 4000)

    def homepage(request: Request) -> FileResponse:
        return FileResponse(path)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(GZipMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"accept-encoding": "gzip", "range": "bytes=0-1999"})
    assert response.status_code == 206
    assert response.content == b"x" * 2000
    assert "Content-Encoding" not in response.headers
    assert int(response.headers["Content-Length"]) == 2000


def test_gzip_streaming_response_emits_output_per_chunk(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"data: first\n\n", "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": True})
        await send({"type": "http.response.body", "body": b"data: last\n\n"})

    middleware = GZipMiddleware(app)
    events: list[Message] = []

    async def recording_app(scope: Scope, receive: Receive, send: Send) -> None:
        async def record(message: Message) -> None:
            events.append(message)
            await send(message)

        await middleware(scope, receive, record)

    client = test_client_factory(recording_app)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.text == "data: first\n\ndata: last\n\n"
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Vary"] == "Accept-Encoding"
    assert "Content-Length" not in response.headers

    assert len(events) == 4
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    assert decompressor.decompress(events[1]["body"]) == b"data: first\n\n"
    assert decompressor.decompress(events[2]["body"]) == b""
    assert decompressor.decompress(events[3]["body"]) == b"data: last\n\n"
    assert decompressor.eof


@pytest.mark.parametrize(
    "content_type",
    [b"application/zip", b"audio/mpeg", b"font/woff2", b"image/png", b"video/mp4"],
)
def test_gzip_default_exclude_content_types(content_type: bytes, test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", content_type)]})
        await send({"type": "http.response.body", "body": b"x" * 4000})

    middleware = GZipMiddleware(app)

    client = test_client_factory(middleware)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.content == b"x" * 4000
    assert "Content-Encoding" not in response.headers
    assert "Vary" not in response.headers


def test_gzip_compresses_svg_by_default(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"image/svg+xml")]})
        await send({"type": "http.response.body", "body": b"x" * 4000})

    middleware = GZipMiddleware(app)

    client = test_client_factory(middleware)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.content == b"x" * 4000
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Vary"] == "Accept-Encoding"


def test_gzip_custom_exclude_content_types(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/zip")]})
        await send({"type": "http.response.body", "body": b"x" * 4000})

    middleware = GZipMiddleware(app, exclude_content_types=("application/zip",))

    client = test_client_factory(middleware)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.content == b"x" * 4000
    assert "Content-Encoding" not in response.headers
    assert "Vary" not in response.headers


def test_gzip_cleared_exclude_content_types(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/event-stream")]})
        await send({"type": "http.response.body", "body": b"x" * 4000})

    middleware = GZipMiddleware(app, exclude_content_types=())

    client = test_client_factory(middleware)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.content == b"x" * 4000
    assert response.headers["Content-Encoding"] == "gzip"
    assert response.headers["Vary"] == "Accept-Encoding"


def test_gzip_exclude_content_types_for_identity_client(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/zip")]})
        await send({"type": "http.response.body", "body": b"x" * 4000})

    middleware = GZipMiddleware(app, exclude_content_types=("application/zip",))

    client = test_client_factory(middleware)
    response = client.get("/", headers={"accept-encoding": "identity"})
    assert response.status_code == 200
    assert response.content == b"x" * 4000
    assert "Content-Encoding" not in response.headers
    assert "Vary" not in response.headers


@pytest.mark.parametrize(
    ("exclude_content_types", "content_type"),
    [
        pytest.param(("text/event-stream",), b"Text/Event-Stream; charset=utf-8", id="header-is-normalized"),
        pytest.param(("Application/ZIP; charset=utf-8",), b"application/zip", id="configured-value-is-normalized"),
        pytest.param(("image/*",), b"image/png", id="wildcard"),
    ],
)
def test_gzip_exclude_content_types_matching(
    exclude_content_types: tuple[str, ...], content_type: bytes, test_client_factory: TestClientFactory
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", content_type)]})
        await send({"type": "http.response.body", "body": b"x" * 4000})

    middleware = GZipMiddleware(app, exclude_content_types=exclude_content_types)

    client = test_client_factory(middleware)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.content == b"x" * 4000
    assert "Content-Encoding" not in response.headers
    assert "Vary" not in response.headers


def test_gzip_responder_normalizes_content_types(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/zip")]})
        await send({"type": "http.response.body", "body": b"x" * 4000})

    responder = GZipResponder(app, 500, exclude_content_types=("Application/ZIP; charset=utf-8",))

    client = test_client_factory(responder)
    response = client.get("/", headers={"accept-encoding": "gzip"})
    assert response.status_code == 200
    assert response.content == b"x" * 4000
    assert "Content-Encoding" not in response.headers
