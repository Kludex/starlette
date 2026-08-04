from __future__ import annotations

import gzip
import hashlib
from pathlib import Path

import anyio
import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import ContentStream, FileResponse, PlainTextResponse, StreamingResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from tests.types import TestClientFactory


async def collect_gzip_response(app: ASGIApp) -> list[Message]:
    messages: list[Message] = []
    scope: Scope = {"type": "http", "headers": [(b"accept-encoding", b"gzip")]}

    async def receive() -> Message:
        raise AssertionError("The app must not receive a request body")  # pragma: no cover

    async def send(message: Message) -> None:
        messages.append(message)

    await app(scope, receive, send)
    return messages


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


@pytest.mark.anyio
async def test_gzip_offloads_without_using_default_capacity_limiter() -> None:
    payload = b"x" * (32 * 1024)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    limiter = anyio.to_thread.current_default_thread_limiter()
    borrowers = [object() for _ in range(int(limiter.total_tokens))]
    for borrower in borrowers:
        await limiter.acquire_on_behalf_of(borrower)

    try:
        with anyio.fail_after(5):
            messages = await collect_gzip_response(GZipMiddleware(app))
    finally:
        for borrower in borrowers:
            limiter.release_on_behalf_of(borrower)

    compressed = messages[1]["body"]
    assert isinstance(compressed, bytes)
    assert gzip.decompress(compressed) == payload


@pytest.mark.anyio
async def test_gzip_offloaded_streaming_chunk_is_compressed_eagerly() -> None:
    chunk = hashlib.shake_256(b"starlette-gzip-stream").digest(256 * 1024)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"tail"})

    messages = await collect_gzip_response(GZipMiddleware(app, minimum_size=10 * 1024 * 1024))

    first_body = messages[1]["body"]
    assert isinstance(first_body, bytes)
    assert len(first_body) > 200 * 1024
    compressed = b"".join(message["body"] for message in messages[1:])
    assert gzip.decompress(compressed) == chunk + b"tail"


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
