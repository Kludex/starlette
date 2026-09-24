from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import anyio
import pytest

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware import Middleware
from starlette.middleware.background import BackgroundTaskMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send


@pytest.mark.anyio
@pytest.mark.parametrize(
    "response_type,stack",
    [
        ("plain", "installed"),
        ("stream", "installed"),
        ("file", "installed"),
        ("pathsend", "installed"),
        ("plain", "mounted"),
        ("plain", "external"),
        ("plain", "gzip"),
        ("plain", "rebuild"),
    ],
)
async def test_background_runs_after_response_and_middleware(tmp_path: Path, response_type: str, stack: str) -> None:
    events: list[str] = []
    path = tmp_path / "response.txt"
    path.write_bytes(b"hello")

    async def record(label: str) -> None:
        events.append(label)

    async def content() -> AsyncIterator[bytes]:
        yield b"hello"

    async def endpoint(request: Request) -> Response:
        await request.body()
        task = BackgroundTask(record, "endpoint task")
        if response_type == "plain":
            return PlainTextResponse("hello", background=task)
        if response_type == "stream":
            return StreamingResponse(content(), background=task)
        return FileResponse(path, background=task)

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.background = BackgroundTask(record, "middleware task")
        return response

    async def rebuild(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        chunks: list[bytes] = []

        async def collect(message: Message) -> None:
            if message["type"] == "http.response.body":
                chunks.append(message["body"])

        await response(request.scope, request.receive, collect)
        return Response(b"".join(chunks))

    class CleanupMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            await self.app(scope, receive, send)
            events.append("cleanup")

    middleware = [Middleware(BaseHTTPMiddleware, dispatch=dispatch)]
    middleware.append(Middleware(BaseHTTPMiddleware, dispatch=rebuild if stack == "rebuild" else dispatch))
    if stack == "gzip":
        middleware.append(Middleware(GZipMiddleware, minimum_size=0))
    if stack != "external":
        middleware.insert(0, Middleware(CleanupMiddleware))
    routes = [Route("/", endpoint)]
    if stack == "mounted":
        app: ASGIApp = Starlette(routes=[Mount("/", app=Starlette(routes=routes))], middleware=middleware)
    elif stack == "external":
        app = BaseHTTPMiddleware(Starlette(routes=routes, middleware=middleware), dispatch=dispatch)
        app = BackgroundTaskMiddleware(CleanupMiddleware(app))
    else:
        app = Starlette(routes=routes, middleware=middleware)

    scope: Scope = {
        "type": "http",
        "asgi": {"spec_version": "2.4"},
        "method": "GET",
        "path": "/",
        "headers": [(b"accept-encoding", b"gzip")],
        "extensions": {"http.response.pathsend": {}} if response_type == "pathsend" else {},
    }

    async def receive() -> Message:
        return {"type": "http.request", "body": b""}

    async def send(message: Message) -> None:
        await anyio.sleep(0.01)
        events.append(message["type"])

    with anyio.fail_after(5):
        await app(scope, receive, send)

    expected_tasks = 3 if stack == "external" else 1 if stack == "rebuild" else 2
    assert events[-expected_tasks - 2] == "cleanup"
    assert sorted(events[-expected_tasks - 1 :]) == ["endpoint task"] + ["middleware task"] * expected_tasks
    assert events[-expected_tasks - 3] == (
        "http.response.pathsend" if response_type == "pathsend" else "http.response.body"
    )


@pytest.mark.anyio
@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("scope_type", ["http", "websocket"])
async def test_reuse_response(wrapped: bool, scope_type: str) -> None:
    events: list[str] = []
    response = Response(background=BackgroundTask(events.append, "task"))
    app: ASGIApp = BackgroundTaskMiddleware(response) if wrapped else response
    scope: Scope = {"type": scope_type}

    async def receive() -> Message:
        raise AssertionError(
            "Response does not read requests"
        )  # pragma: no cover - these responses only send messages.

    async def send(message: Message) -> None:
        events.append(message["type"])

    for _ in range(2):
        await app(scope, receive, send)

    prefix = "websocket." if scope_type == "websocket" else ""
    assert events == [prefix + "http.response.start", prefix + "http.response.body", "task"] * 2


@pytest.mark.anyio
async def test_lifespan_passes_through() -> None:
    events: list[Message] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        assert scope == {"type": "lifespan"}
        assert await receive() == {"type": "lifespan.startup"}
        await send({"type": "lifespan.startup.complete"})

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(message: Message) -> None:
        events.append(message)

    await BackgroundTaskMiddleware(app)({"type": "lifespan"}, receive, send)
    assert events == [{"type": "lifespan.startup.complete"}]
