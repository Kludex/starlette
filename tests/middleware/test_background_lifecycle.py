from __future__ import annotations

import anyio
import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.applications import Starlette
from starlette.background import BackgroundTask, BackgroundTasks
from starlette.middleware import Middleware
from starlette.middleware.background import BackgroundTaskMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send


@pytest.mark.anyio
@pytest.mark.parametrize("raise_app_exceptions", [False, True])
async def test_background_failure_stops_remaining_tasks(raise_app_exceptions: bool) -> None:
    events: list[str] = []

    async def fail() -> None:
        events.append("task")
        raise ValueError("task failed")

    async def endpoint(request: Request) -> Response:
        tasks = BackgroundTasks()
        tasks.add_task(fail)
        tasks.add_task(events.append, "second task")
        return Response("hello", background=tasks)

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        return await call_next(request)

    app = Starlette(routes=[Route("/", endpoint)], middleware=[Middleware(BaseHTTPMiddleware, dispatch=dispatch)])
    transport = ASGITransport(app, raise_app_exceptions=raise_app_exceptions)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        if raise_app_exceptions:
            with pytest.raises(ValueError, match="task failed"):
                await client.get("/")
        else:
            response = await client.get("/")
            assert response.status_code == 200
            assert response.text == "hello"
    assert events == ["task"]


@pytest.mark.anyio
@pytest.mark.parametrize("failure", ["send", "app"])
async def test_failed_request_discards_tasks(failure: str) -> None:
    events: list[str] = []
    should_fail = True

    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        assert (await receive())["type"] == "http.request"
        await Response("hello", background=BackgroundTask(events.append, "task"))(scope, receive, send)
        if should_fail and failure == "app":
            raise ValueError("app failed")

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        return await call_next(request)

    app = BackgroundTaskMiddleware(BaseHTTPMiddleware(endpoint, dispatch=dispatch))
    scope: Scope = {"type": "http", "method": "GET", "path": "/", "headers": []}

    async def receive() -> Message:
        return {"type": "http.request", "body": b""}

    async def send(message: Message) -> None:
        await anyio.sleep(0.01)
        if should_fail and failure == "send" and message["type"] == "http.response.body":
            raise OSError("send failed")

    with pytest.raises(OSError if failure == "send" else ValueError, match=f"{failure} failed"):
        await app(scope, receive, send)
    assert events == []

    should_fail = False
    await app(scope, receive, send)
    assert events == ["task"]


@pytest.mark.anyio
async def test_concurrent_requests_with_reused_response() -> None:
    started = anyio.Event()
    release = anyio.Event()
    task_count = 0

    async def task() -> None:
        nonlocal task_count
        task_count += 1
        if task_count == 1:
            started.set()
            await release.wait()

    response = Response("hello", background=BackgroundTask(task))
    app = BackgroundTaskMiddleware(response)
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:

        async def request() -> None:
            response = await client.get("/")
            assert response.text == "hello"

        async with anyio.create_task_group() as task_group:
            task_group.cancel_scope.deadline = anyio.current_time() + 5
            task_group.start_soon(request)
            await started.wait()
            await request()
            release.set()

    assert not task_group.cancel_scope.cancel_called
    assert task_count == 2
