from collections.abc import AsyncIterator
from typing import Any

import anyio
import pytest

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send
from tests.types import TestClientFactory


def test_handler(
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("Something went wrong")

    def error_500(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse({"detail": "Server Error"}, status_code=500)

    app = ServerErrorMiddleware(app, handler=error_500)
    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 500
    assert response.json() == {"detail": "Server Error"}


def test_debug_text(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/plain")
    assert "RuntimeError: Something went wrong" in response.text


def test_debug_html(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.get("/", headers={"Accept": "text/html, */*"})
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/html")
    assert "RuntimeError" in response.text


def test_debug_after_response_sent(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response(b"", status_code=204)
        await response(scope, receive, send)
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        client.get("/")


def test_debug_not_http(test_client_factory: TestClientFactory) -> None:
    """
    DebugMiddleware should just pass through any non-http messages as-is.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app)

    with pytest.raises(RuntimeError):
        client = test_client_factory(app)
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_background_task(test_client_factory: TestClientFactory) -> None:
    accessed_error_handler = False

    def error_handler(request: Request, exc: Exception) -> Any:
        nonlocal accessed_error_handler
        accessed_error_handler = True

    def raise_exception() -> None:
        raise Exception("Something went wrong")

    async def endpoint(request: Request) -> Response:
        task = BackgroundTask(raise_exception)
        return Response(status_code=204, background=task)

    app = Starlette(
        routes=[Route("/", endpoint=endpoint)],
        exception_handlers={Exception: error_handler},
    )

    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 204
    assert accessed_error_handler


def spec_2_4_scope() -> Scope:
    return {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "asgi": {"spec_version": "2.4"},
    }


class ServerDisconnectError(OSError):
    pass


@pytest.mark.anyio
async def test_client_disconnect_while_sending_error_response() -> None:
    error = RuntimeError("Something went wrong")

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        raise error

    async def receive() -> Message:
        raise NotImplementedError

    async def send(message: Message) -> None:
        # Simulate an ASGI spec 2.4 server whose client has already disconnected.
        raise ServerDisconnectError("Disconnected")

    with pytest.raises(RuntimeError) as exc:
        await ServerErrorMiddleware(app)(spec_2_4_scope(), receive, send)

    # The application's error must not be replaced by the server's disconnect error.
    assert exc.value is error


@pytest.mark.anyio
async def test_client_disconnect_stops_streaming_error_response() -> None:
    error = RuntimeError("Something went wrong")

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        raise error

    async def stream_forever() -> AsyncIterator[bytes]:
        while True:
            yield b"chunk"

    def error_500(request: Request, exc: Exception) -> StreamingResponse:
        return StreamingResponse(stream_forever(), status_code=500)

    async def receive() -> Message:
        raise NotImplementedError

    async def send(message: Message) -> None:
        # Simulate an ASGI spec 2.4 server whose client disconnected mid-response.
        if message["type"] == "http.response.body":
            raise ServerDisconnectError("Disconnected")

    # Streaming responses rely on send() raising to stop under ASGI spec 2.4.
    with anyio.fail_after(5), pytest.raises(RuntimeError) as exc:
        await ServerErrorMiddleware(app, handler=error_500)(spec_2_4_scope(), receive, send)

    assert exc.value is error


@pytest.mark.anyio
async def test_error_response_os_error_is_not_suppressed() -> None:
    response_error = OSError("Disk failure")

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("Something went wrong")

    async def failing_stream() -> AsyncIterator[bytes]:
        raise response_error
        yield b""  # pragma: no cover

    def error_500(request: Request, exc: Exception) -> StreamingResponse:
        return StreamingResponse(failing_stream(), status_code=500)

    async def receive() -> Message:
        raise NotImplementedError

    async def send(message: Message) -> None:
        pass

    # Only the server's disconnect error is suppressed, not errors from the error response itself.
    with pytest.raises(OSError) as exc:
        await ServerErrorMiddleware(app, handler=error_500)(spec_2_4_scope(), receive, send)

    assert exc.value is response_error
