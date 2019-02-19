import pytest

from starlette.applications import Starlette
from starlette.middleware.lifespan import LifespanMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Lifespan, Route, Router
from starlette.testclient import TestClient


class App:
    raise_on_startup = False
    raise_on_shutdown = False

    def __init__(self, scope):
        pass

    async def __call__(self, receive, send):
        message = await receive()
        assert message["type"] == "lifespan.startup"
        if self.raise_on_startup:
            raise RuntimeError()
        await send({"type": "lifespan.startup.complete"})

        message = await receive()
        assert message["type"]
        if self.raise_on_shutdown:
            raise RuntimeError()
        await send({"type": "lifespan.shutdown.complete"})


class RaiseOnStartup(App):
    raise_on_startup = True


class RaiseOnShutdown(App):
    raise_on_shutdown = True


def test_lifespan_handler():
    startup_complete = False
    cleanup_complete = False
    handler = LifespanMiddleware(App)

    @handler.on_event("startup")
    def run_startup():
        nonlocal startup_complete
        startup_complete = True

    @handler.on_event("shutdown")
    def run_cleanup():
        nonlocal cleanup_complete
        cleanup_complete = True

    assert not startup_complete
    assert not cleanup_complete
    with TestClient(handler):
        assert startup_complete
        assert not cleanup_complete
    assert startup_complete
    assert cleanup_complete


def test_async_lifespan_handler():
    startup_complete = False
    cleanup_complete = False
    handler = LifespanMiddleware(App)

    @handler.on_event("startup")
    async def run_startup():
        nonlocal startup_complete
        startup_complete = True

    @handler.on_event("shutdown")
    async def run_cleanup():
        nonlocal cleanup_complete
        cleanup_complete = True

    assert not startup_complete
    assert not cleanup_complete
    with TestClient(handler):
        assert startup_complete
        assert not cleanup_complete
    assert startup_complete
    assert cleanup_complete


def test_raise_on_startup():
    handler = LifespanMiddleware(RaiseOnStartup)

    with pytest.raises(RuntimeError):
        with TestClient(handler):
            pass  # pragma: nocover


def test_raise_on_shutdown():
    handler = LifespanMiddleware(RaiseOnShutdown)

    with pytest.raises(RuntimeError):
        with TestClient(handler):
            pass


def test_routed_lifespan():
    startup_complete = False
    shutdown_complete = False

    def hello_world(request):
        return PlainTextResponse("hello, world")

    def run_startup():
        nonlocal startup_complete
        startup_complete = True

    def run_shutdown():
        nonlocal shutdown_complete
        shutdown_complete = True

    app = Router(
        routes=[
            Lifespan(on_startup=run_startup, on_shutdown=run_shutdown),
            Route("/", hello_world),
        ]
    )

    assert not startup_complete
    assert not shutdown_complete
    with TestClient(app) as client:
        assert startup_complete
        assert not shutdown_complete
        client.get("/")
    assert startup_complete
    assert shutdown_complete


def test_app_lifespan():
    startup_complete = False
    cleanup_complete = False
    app = Starlette()

    @app.on_event("startup")
    def run_startup():
        nonlocal startup_complete
        startup_complete = True

    @app.on_event("shutdown")
    def run_cleanup():
        nonlocal cleanup_complete
        cleanup_complete = True

    assert not startup_complete
    assert not cleanup_complete
    with TestClient(app):
        assert startup_complete
        assert not cleanup_complete
    assert startup_complete
    assert cleanup_complete


def test_app_async_lifespan():
    startup_complete = False
    cleanup_complete = False
    app = Starlette()

    @app.on_event("startup")
    async def run_startup():
        nonlocal startup_complete
        startup_complete = True

    @app.on_event("shutdown")
    async def run_cleanup():
        nonlocal cleanup_complete
        cleanup_complete = True

    assert not startup_complete
    assert not cleanup_complete
    with TestClient(app):
        assert startup_complete
        assert not cleanup_complete
    assert startup_complete
    assert cleanup_complete
