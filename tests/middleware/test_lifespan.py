import pytest

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route, Router
from starlette.testclient import TestClient


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
        on_startup=[run_startup],
        on_shutdown=[run_shutdown],
        routes=[Route("/", hello_world)],
    )

    assert not startup_complete
    assert not shutdown_complete
    with TestClient(app) as client:
        assert startup_complete
        assert not shutdown_complete
        client.get("/")
    assert startup_complete
    assert shutdown_complete


def test_raise_on_startup():
    def run_startup():
        raise RuntimeError()

    router = Router(on_startup=[run_startup])

    async def app(scope, receive, send):
        async def _send(message):
            nonlocal startup_failed
            if message["type"] == "lifespan.startup.failed":
                startup_failed = True
            return await send(message)

        await router(scope, receive, _send)

    startup_failed = False
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass  # pragma: nocover
    assert startup_failed


def test_raise_on_shutdown():
    def run_shutdown():
        raise RuntimeError()

    app = Router(on_shutdown=[run_shutdown])

    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass  # pragma: nocover


def test_app_lifespan():
    startup_complete = False
    shutdown_complete = False
    app = Starlette()

    @app.on_event("startup")
    def run_startup():
        nonlocal startup_complete
        startup_complete = True

    @app.on_event("shutdown")
    def run_shutdown():
        nonlocal shutdown_complete
        shutdown_complete = True

    assert not startup_complete
    assert not shutdown_complete
    with TestClient(app):
        assert startup_complete
        assert not shutdown_complete
    assert startup_complete
    assert shutdown_complete


def test_app_async_lifespan():
    startup_complete = False
    shutdown_complete = False
    app = Starlette()

    @app.on_event("startup")
    async def run_startup():
        nonlocal startup_complete
        startup_complete = True

    @app.on_event("shutdown")
    async def run_shutdown():
        nonlocal shutdown_complete
        shutdown_complete = True

    assert not startup_complete
    assert not shutdown_complete
    with TestClient(app):
        assert startup_complete
        assert not shutdown_complete
    assert startup_complete
    assert shutdown_complete
