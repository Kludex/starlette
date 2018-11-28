import pytest

from starlette.applications import Starlette
from starlette.middleware.lifespan import LifespanMiddleware
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
