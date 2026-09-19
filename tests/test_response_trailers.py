from __future__ import annotations

from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import aclosing

import pytest

from starlette.background import BackgroundTask
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import ClientDisconnect, Request
from starlette.responses import Response, StreamingResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from tests.types import TestClientFactory


@pytest.mark.parametrize("depth", [0, 1, 2])
@pytest.mark.parametrize("spec_version", ["2.0", "2.4"])
def test_streaming_trailers(test_client_factory: TestClientFactory, depth: int, spec_version: str) -> None:
    events: list[str] = []

    async def body() -> AsyncIterator[bytes]:
        yield b"hello"
        events.append("body")

    async def trailers() -> dict[str, str]:
        events.append("trailers")
        return {"X-Result": "done"}

    async def background() -> None:
        events.append("background")

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        scope["asgi"] = {"spec_version": spec_version}
        response = StreamingResponse(
            body(), headers={"Trailer": "X-Result"}, trailers=trailers, background=BackgroundTask(background)
        )
        await response(scope, receive, send)

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        return await call_next(request)

    wrapped: ASGIApp = app
    for _ in range(depth):
        wrapped = BaseHTTPMiddleware(wrapped, dispatch=dispatch)
    response = test_client_factory(wrapped).get("/", headers={"te": "trailers"})
    assert response.content == b"hello"
    assert response.extensions["http.response.trailers"] == [(b"x-result", b"done")]
    assert events == ["body", "trailers", "background"]


@pytest.mark.parametrize("declaration", ["", ":status", "content-length", "x foo", "x-test,", "x-test\r\nother"])
def test_invalid_trailer_declaration(declaration: str) -> None:
    async def trailers() -> dict[str, str]:
        return {}  # pragma: no cover - Invalid configuration never invokes the callback.

    with pytest.raises(ValueError, match="Declare valid trailer"):
        StreamingResponse(iter(()), headers={"trailer": declaration}, trailers=trailers)


@pytest.mark.parametrize("status", [101, 204, 304])
def test_bodyless_status(status: int) -> None:
    async def trailers() -> dict[str, str]:
        return {}  # pragma: no cover - Invalid configuration never invokes the callback.

    with pytest.raises(ValueError, match="permits a body"):
        StreamingResponse(iter(()), status_code=status, headers={"trailer": "x-test"}, trailers=trailers)


@pytest.mark.parametrize("failure", ["body", "callback", "undeclared", "linebreak", "empty"])
@pytest.mark.parametrize("middleware", [True, False])
def test_trailer_callback_failures(test_client_factory: TestClientFactory, failure: str, middleware: bool) -> None:
    events: list[str] = []

    async def body() -> AsyncIterator[bytes]:
        yield b"hello"
        if failure == "body":
            raise ValueError("body failed")

    async def trailers() -> dict[str, str]:
        events.append("trailers")
        if failure == "callback":
            raise ValueError("callback failed")
        if failure == "undeclared":
            return {"other": "value"}
        if failure == "linebreak":
            return {"x-test": "one\r\ntwo"}
        return {}

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await StreamingResponse(body(), headers={"trailer": "x-test"}, trailers=trailers)(scope, receive, send)

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        return await call_next(request)

    client = test_client_factory(BaseHTTPMiddleware(app, dispatch=dispatch) if middleware else app)
    if failure == "empty":
        response = client.get("/")
        assert response.content == b"hello"
        assert response.extensions["http.response.trailers"] == []
    else:
        with pytest.raises(ValueError):
            client.get("/")
    assert events == ([] if failure == "body" else ["trailers"])


@pytest.mark.parametrize("background", [True, False])
def test_head_trailers(test_client_factory: TestClientFactory, background: bool) -> None:
    events: list[str] = []

    async def trailers() -> dict[str, str]:
        pytest.fail("HEAD must not produce trailers")  # pragma: no cover - HEAD must skip the callback.

    async def task() -> None:
        events.append("background")

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await StreamingResponse(
            iter([b"body"]),
            headers={"trailer": "x-test"},
            trailers=trailers,
            background=BackgroundTask(task) if background else None,
        )(scope, receive, send)

    response = test_client_factory(app).head("/")
    assert response.content == b""
    assert "trailer" not in response.headers
    assert "http.response.trailers" not in response.extensions
    assert events == (["background"] if background else [])


@pytest.mark.parametrize("scenario", ["unsupported", "length", "websocket", "http2"])
def test_trailer_capabilities(test_client_factory: TestClientFactory, scenario: str) -> None:
    sent: list[Message] = []

    async def trailers() -> dict[str, str]:
        return {"x-test": "done"}

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        scope = dict(scope)
        if scenario == "unsupported":
            scope["extensions"] = {}
        if scenario == "websocket":
            scope["type"] = "websocket"
        if scenario == "http2":
            scope["http_version"] = "2"

        async def capture(message: Message) -> None:
            sent.append(message)
            await send(message)

        await StreamingResponse(
            iter([b"hello"]), headers={"trailer": "x-test", "content-length": "5"}, trailers=trailers
        )(scope, receive, capture)

    client = test_client_factory(app)
    if scenario == "http2":
        response = client.get("/")
        assert response.content == b"hello"
        assert response.extensions["http.response.trailers"] == [(b"x-test", b"done")]
    else:
        with pytest.raises(ValueError if scenario == "length" else RuntimeError):
            client.get("/")
        assert sent == []


@pytest.mark.anyio
@pytest.mark.parametrize("fail_at", ["http.response.body", "http.response.trailers"])
async def test_trailer_disconnect(fail_at: str) -> None:
    events: list[str] = []

    async def trailers() -> dict[str, str]:
        events.append("trailers")
        return {"x-test": "done"}

    async def receive() -> Message:
        pytest.fail("ASGI 2.4 uses send failures to detect disconnects")  # pragma: no cover - Send detects disconnects.

    async def send(message: Message) -> None:
        if message["type"] == fail_at:
            raise OSError("disconnected")

    async def body() -> AsyncGenerator[bytes, None]:
        yield b"hello"

    async with aclosing(body()) as stream:
        response = StreamingResponse(stream, headers={"trailer": "x-test"}, trailers=trailers)
        with pytest.raises(ClientDisconnect):
            await response(
                {
                    "type": "http",
                    "method": "GET",
                    "http_version": "2",
                    "asgi": {"spec_version": "2.4"},
                    "extensions": {"http.response.trailers": {}},
                },
                receive,
                send,
            )
    assert events == (["trailers"] if fail_at == "http.response.trailers" else [])
