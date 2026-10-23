from __future__ import annotations

from collections.abc import Awaitable, Callable

import pytest

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.body_limit import MAX_BODY_SIZE_SCOPE_KEY, RequestBodyLimitMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Mount, Route, Router
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from tests.types import TestClientFactory


async def echo(request: Request) -> Response:
    return Response(await request.body())


def test_body_size_limit(test_client_factory: TestClientFactory) -> None:
    app = RequestBodyLimitMiddleware(
        Starlette(routes=[Route("/", echo, methods=["POST"])]),
        max_body_size=5,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"12345")
    assert response.status_code == 200
    assert response.content == b"12345"

    response = client.post("/", content=b"123456")
    assert response.status_code == 413
    assert response.text == "Content Too Large"


def test_content_length_is_checked_without_reading_body(
    test_client_factory: TestClientFactory,
) -> None:
    async def endpoint(request: Request) -> PlainTextResponse:
        return PlainTextResponse("response")

    app = Starlette(
        routes=[Route("/", endpoint, methods=["POST"])],
        max_body_size=5,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"123456")
    assert response.status_code == 413
    assert response.text == "Content Too Large"


def test_route_override_applies_when_middleware_defers_response_start(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> PlainTextResponse:
        return PlainTextResponse("response")

    async def passthrough(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        return await call_next(request)

    app = Starlette(
        routes=[Route("/", endpoint, methods=["POST"], max_body_size=10)],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=passthrough)],
        max_body_size=5,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"12345678")
    assert response.status_code == 200
    assert response.text == "response"


@pytest.mark.anyio
async def test_content_length_rejects_before_receiving_body() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()

    async def receive() -> Message:
        raise AssertionError("receive should not be called")  # pragma: no cover

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-length", b"6")],
    }
    middleware = RequestBodyLimitMiddleware(app, max_body_size=5)

    await middleware(scope, receive, send)
    assert sent[0]["status"] == 413


@pytest.mark.anyio
async def test_received_bytes_are_counted_without_content_length() -> None:
    messages = iter(
        [
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"456", "more_body": False},
        ]
    )

    async def receive() -> Message:
        return next(messages)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        await receive()

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    scope: Scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    middleware = RequestBodyLimitMiddleware(app, max_body_size=5)

    await middleware(scope, receive, send)
    assert sent[0]["status"] == 413


def test_received_bytes_are_counted_with_unreliable_content_length(test_client_factory: TestClientFactory) -> None:
    app = RequestBodyLimitMiddleware(
        Starlette(routes=[Route("/", echo, methods=["POST"])]),
        max_body_size=5,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"123456", headers={"Content-Length": "1"})
    assert response.status_code == 413
    assert response.text == "Content Too Large"
    response = client.post("/", content=b"12345", headers={"Content-Length": "invalid"})

    assert response.status_code == 200
    assert response.content == b"12345"


@pytest.mark.anyio
async def test_limit_exceeded_after_response_started_is_raised() -> None:
    messages = iter(
        [
            {"type": "http.request", "body": b"12345", "more_body": True},
            {"type": "http.request", "body": b"6", "more_body": False},
        ]
    )

    async def receive() -> Message:
        return next(messages)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await receive()
        await receive()

    async def send(message: Message) -> None:
        pass

    scope: Scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    middleware = RequestBodyLimitMiddleware(app, max_body_size=5)

    with pytest.raises(HTTPException) as exc_info:
        await middleware(scope, receive, send)

    assert exc_info.value.status_code == 413


@pytest.mark.anyio
async def test_non_http_scope_is_unchanged() -> None:
    received_scope: Scope | None = None

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal received_scope
        received_scope = scope

    async def receive() -> Message:
        return {"type": "lifespan.startup"}  # pragma: no cover

    async def send(message: Message) -> None:
        pass  # pragma: no cover

    scope: Scope = {"type": "lifespan"}
    middleware = RequestBodyLimitMiddleware(app, max_body_size=5)

    await middleware(scope, receive, send)

    assert received_scope is scope
    assert MAX_BODY_SIZE_SCOPE_KEY not in scope


@pytest.mark.anyio
async def test_non_request_message_passes_through() -> None:
    message: Message = {"type": "http.disconnect"}
    received: Message | None = None

    async def receive() -> Message:
        return message

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal received
        received = await receive()

    async def send(message: Message) -> None:
        pass  # pragma: no cover

    scope: Scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    middleware = RequestBodyLimitMiddleware(app, max_body_size=5)

    await middleware(scope, receive, send)

    assert received is message


@pytest.mark.anyio
async def test_existing_scope_limit_is_restored() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        assert scope[MAX_BODY_SIZE_SCOPE_KEY] == 5

    async def receive() -> Message:
        return {"type": "http.request", "body": b""}  # pragma: no cover

    async def send(message: Message) -> None:
        pass  # pragma: no cover

    scope: Scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [],
        MAX_BODY_SIZE_SCOPE_KEY: 10,
    }
    middleware = RequestBodyLimitMiddleware(app, max_body_size=5)

    await middleware(scope, receive, send)

    assert scope[MAX_BODY_SIZE_SCOPE_KEY] == 10


def test_starlette_limit_applies_before_user_middleware(
    test_client_factory: TestClientFactory,
) -> None:
    class ReadBodyMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await receive()
            await self.app(scope, receive, send)  # pragma: no cover

    app = Starlette(
        routes=[Route("/", echo, methods=["POST"])],
        middleware=[Middleware(ReadBodyMiddleware)],
        max_body_size=5,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"123456")
    assert response.status_code == 413


def test_route_can_raise_application_limit(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/default", echo, methods=["POST"]),
            Route("/upload", echo, methods=["POST"], max_body_size=10),
        ],
        max_body_size=5,
    )
    client = test_client_factory(app)

    default_response = client.post("/default", content=b"12345678")
    upload_response = client.post("/upload", content=b"12345678")

    assert default_response.status_code == 413
    assert upload_response.status_code == 200
    assert upload_response.content == b"12345678"


def test_route_can_lower_application_limit(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[Route("/", echo, methods=["POST"], max_body_size=5)],
        max_body_size=10,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"123456")
    assert response.status_code == 413


def test_mount_can_override_application_limit(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Mount(
                "/upload",
                routes=[Route("/", echo, methods=["POST"])],
                max_body_size=10,
            )
        ],
        max_body_size=5,
    )
    client = test_client_factory(app)

    response = client.post("/upload/", content=b"12345678")
    assert response.status_code == 200
    assert response.content == b"12345678"


def test_router_limit(test_client_factory: TestClientFactory) -> None:
    app = Router(routes=[Route("/", echo, methods=["POST"])], max_body_size=5)
    client = test_client_factory(app)

    response = client.post("/", content=b"123456")
    assert response.status_code == 413


def test_route_override_survives_shallow_scope_copy(test_client_factory: TestClientFactory) -> None:
    class CopyScopeMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await self.app(dict(scope), receive, send)

    app = Starlette(
        routes=[Route("/", echo, methods=["POST"], max_body_size=10)],
        middleware=[Middleware(CopyScopeMiddleware)],
        max_body_size=5,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"12345678")
    assert response.status_code == 200
    assert response.content == b"12345678"


def test_stricter_route_rejects_body_read_by_middleware(test_client_factory: TestClientFactory) -> None:
    async def read_body(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        await request.body()
        return await call_next(request)

    app = Starlette(
        routes=[Route("/", echo, methods=["POST"], max_body_size=5)],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=read_body)],
        max_body_size=10,
    )
    client = test_client_factory(app)

    response = client.post("/", content=b"123456")
    assert response.status_code == 413


def test_multipart_file_counts_towards_limit(test_client_factory: TestClientFactory) -> None:
    async def upload(request: Request) -> PlainTextResponse:
        async with request.form():
            return PlainTextResponse("uploaded")  # pragma: no cover

    app = Starlette(
        routes=[Route("/", upload, methods=["POST"])],
        max_body_size=512,
    )
    client = test_client_factory(app)
    response = client.post("/", files={"file": ("example.txt", b"x" * 1024)})
    assert response.status_code == 413
