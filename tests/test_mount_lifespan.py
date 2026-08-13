from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import pytest

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Host, Mount, Route, Router
from starlette.types import ASGIApp, Lifespan, Receive, Scope, Send
from tests.types import TestClientFactory


def _lifespan_app(events: list[str], name: str) -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "lifespan":
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})
            return
        await receive()
        events.append(f"{name}:startup")
        await send({"type": "lifespan.startup.complete"})
        await receive()
        events.append(f"{name}:shutdown")
        await send({"type": "lifespan.shutdown.complete"})

    return app


def _starlette_lifespan(events: list[str], name: str) -> Lifespan[Starlette]:
    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        events.append(f"{name}:startup")
        yield
        events.append(f"{name}:shutdown")

    return lifespan


def _text(body: str) -> Callable[[Request], PlainTextResponse]:
    def endpoint(request: Request) -> PlainTextResponse:
        return PlainTextResponse(body)

    return endpoint


def test_mounted_asgi_app_receives_lifespan(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []
    app = Router(routes=[Mount("/mcp", _lifespan_app(events, "mcp"))])

    with test_client_factory(app) as client:
        assert events == ["mcp:startup"]
        response = client.get("/mcp")
        assert response.status_code == 200

    assert events == ["mcp:startup", "mcp:shutdown"]


def test_parent_and_mounted_lifespan_order(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []

    @asynccontextmanager
    async def parent_lifespan(app: Starlette) -> AsyncIterator[None]:
        events.append("parent:startup")
        yield
        events.append("parent:shutdown")

    @asynccontextmanager
    async def child_lifespan(app: Starlette) -> AsyncIterator[None]:
        events.append("child:startup")
        yield
        events.append("child:shutdown")

    child = Starlette(
        routes=[Route("/", _text("child"))],
        lifespan=child_lifespan,
    )
    app = Starlette(
        routes=[
            Route("/", _text("parent")),
            Mount("/child", child),
        ],
        lifespan=parent_lifespan,
    )

    with test_client_factory(app) as client:
        assert events == ["parent:startup", "child:startup"]
        assert client.get("/").text == "parent"
        assert client.get("/child").text == "child"

    assert events == ["parent:startup", "child:startup", "child:shutdown", "parent:shutdown"]


def test_multiple_mounts_start_in_order_and_shutdown_lifo(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []
    app = Router(
        routes=[
            Mount("/a", _lifespan_app(events, "a")),
            Mount("/b", _lifespan_app(events, "b")),
        ]
    )

    with test_client_factory(app):
        assert events == ["a:startup", "b:startup"]

    assert events == ["a:startup", "b:startup", "b:shutdown", "a:shutdown"]


def test_nested_mounts(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []
    grandchild = Starlette(
        routes=[Route("/", _text("gc"))],
        lifespan=_starlette_lifespan(events, "grandchild"),
    )
    child = Starlette(
        routes=[Mount("/gc", grandchild)],
        lifespan=_starlette_lifespan(events, "child"),
    )
    app = Starlette(
        routes=[Mount("/child", child)],
        lifespan=_starlette_lifespan(events, "parent"),
    )

    with test_client_factory(app) as client:
        assert events == ["parent:startup", "child:startup", "grandchild:startup"]
        assert client.get("/child/gc").text == "gc"

    assert events == [
        "parent:startup",
        "child:startup",
        "grandchild:startup",
        "grandchild:shutdown",
        "child:shutdown",
        "parent:shutdown",
    ]


def test_host_receives_lifespan(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []
    app = Router(routes=[Host("api.example.org", _lifespan_app(events, "host"))])

    with test_client_factory(app):
        assert events == ["host:startup"]

    assert events == ["host:startup", "host:shutdown"]


def test_http_only_mount_is_ignored(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []

    @asynccontextmanager
    async def parent_lifespan(app: Starlette) -> AsyncIterator[None]:
        events.append("parent:startup")
        yield
        events.append("parent:shutdown")

    app = Starlette(
        routes=[Mount("/static", PlainTextResponse("asset"))],
        lifespan=parent_lifespan,
    )

    with test_client_factory(app) as client:
        assert events == ["parent:startup"]
        assert client.get("/static").text == "asset"

    assert events == ["parent:startup", "parent:shutdown"]


def test_mounted_lifespan_state_is_merged(test_client_factory: TestClientFactory) -> None:
    @asynccontextmanager
    async def parent_lifespan(app: Starlette) -> AsyncIterator[dict[str, str]]:
        yield {"from_parent": "yes"}

    @asynccontextmanager
    async def child_lifespan(app: Starlette) -> AsyncIterator[dict[str, str]]:
        yield {"from_child": "yes"}

    async def homepage(request: Request) -> JSONResponse:
        return JSONResponse({"from_parent": request.state["from_parent"], "from_child": request.state["from_child"]})

    child = Starlette(lifespan=child_lifespan)
    app = Starlette(routes=[Route("/", homepage), Mount("/child", child)], lifespan=parent_lifespan)

    with test_client_factory(app) as client:
        assert client.get("/").json() == {"from_parent": "yes", "from_child": "yes"}


def test_mounted_lifespan_without_server_state(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []
    child = _lifespan_app(events, "child")
    router = Router(routes=[Mount("/child", child)])

    async def no_state_wrapper(scope: Scope, receive: Receive, send: Send) -> None:
        scope.pop("state", None)
        await router(scope, receive, send)

    with test_client_factory(no_state_wrapper):
        assert events == ["child:startup"]

    assert events == ["child:startup", "child:shutdown"]


def test_mounted_startup_failure(test_client_factory: TestClientFactory) -> None:
    async def failing(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        raise RuntimeError("child boom")

    app = Router(routes=[Mount("/sub", failing)])

    with pytest.raises(RuntimeError, match="child boom"):
        with test_client_factory(app):
            raise AssertionError("Should not be called")  # pragma: no cover


def test_mounted_startup_failed_message_without_raise(test_client_factory: TestClientFactory) -> None:
    async def failing(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        await send({"type": "lifespan.startup.failed", "message": "nope"})

    app = Router(routes=[Mount("/sub", failing)])

    with pytest.raises(RuntimeError, match="failed during lifespan startup"):
        with test_client_factory(app):
            raise AssertionError("Should not be called")  # pragma: no cover


def test_mounted_shutdown_failed_message_without_raise(test_client_factory: TestClientFactory) -> None:
    async def failing(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await send({"type": "lifespan.shutdown.failed", "message": "nope"})

    app = Router(routes=[Mount("/sub", failing)])

    with pytest.raises(RuntimeError, match="failed during lifespan shutdown"):
        with test_client_factory(app):
            pass


def test_mounted_lifespan_exits_before_shutdown(test_client_factory: TestClientFactory) -> None:
    async def broken(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        await send({"type": "lifespan.startup.complete"})

    app = Router(routes=[Mount("/sub", broken)])

    with pytest.raises(RuntimeError, match="exited before shutdown"):
        with test_client_factory(app):
            raise AssertionError("Should not be called")  # pragma: no cover


def test_mounted_app_that_never_receives_is_skipped(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []

    async def silent(scope: Scope, receive: Receive, send: Send) -> None:
        return

    app = Router(routes=[Mount("/silent", silent), Mount("/ok", _lifespan_app(events, "ok"))])

    with test_client_factory(app):
        assert events == ["ok:startup"]

    assert events == ["ok:startup", "ok:shutdown"]


def test_mounted_app_raising_before_receive_is_skipped(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []

    async def exploding(scope: Scope, receive: Receive, send: Send) -> None:
        raise AssertionError("http only")

    app = Router(routes=[Mount("/boom", exploding), Mount("/ok", _lifespan_app(events, "ok"))])

    with test_client_factory(app):
        assert events == ["ok:startup"]

    assert events == ["ok:startup", "ok:shutdown"]


def test_mounted_non_lifespan_messages_are_ignored(test_client_factory: TestClientFactory) -> None:
    events: list[str] = []

    async def messy(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"foo": "bar"})
        await send({"type": 1})
        await send({"type": "http.response.start", "status": 200, "headers": []})

    app = Router(routes=[Mount("/messy", messy), Mount("/ok", _lifespan_app(events, "ok"))])

    with test_client_factory(app):
        assert events == ["ok:startup"]

    assert events == ["ok:startup", "ok:shutdown"]


def test_mounted_app_extra_receive_raises(test_client_factory: TestClientFactory) -> None:
    async def greedy(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        await send({"type": "lifespan.startup.complete"})
        await receive()
        await send({"type": "lifespan.shutdown.complete"})
        await receive()

    app = Router(routes=[Mount("/sub", greedy)])

    with pytest.raises(RuntimeError, match="too many times"):
        with test_client_factory(app):
            pass
