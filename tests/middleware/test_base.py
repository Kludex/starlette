import contextvars

import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse, StreamingResponse
from starlette.routing import Route, WebSocketRoute
from starlette.types import ASGIApp, Receive, Scope, Send


class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Custom-Header"] = "Example"
        return response


def homepage(request):
    return PlainTextResponse("Homepage")


def exc(request):
    raise Exception("Exc")


def exc_stream(request):
    return StreamingResponse(_generate_faulty_stream())


def _generate_faulty_stream():
    yield b"Ok"
    raise Exception("Faulty Stream")


class NoResponse:
    def __init__(self, scope, receive, send):
        pass

    def __await__(self):
        return self.dispatch().__await__()

    async def dispatch(self):
        pass


async def websocket_endpoint(session):
    await session.accept()
    await session.send_text("Hello, world!")
    await session.close()


app = Starlette(
    routes=[
        Route("/", endpoint=homepage),
        Route("/exc", endpoint=exc),
        Route("/exc-stream", endpoint=exc_stream),
        Route("/no-response", endpoint=NoResponse),
        WebSocketRoute("/ws", endpoint=websocket_endpoint),
    ],
    middleware=[Middleware(CustomMiddleware)],
)


def test_custom_middleware(test_client_factory):
    client = test_client_factory(app)
    response = client.get("/")
    assert response.headers["Custom-Header"] == "Example"

    with pytest.raises(Exception) as ctx:
        response = client.get("/exc")
    assert str(ctx.value) == "Exc"

    with pytest.raises(Exception) as ctx:
        response = client.get("/exc-stream")
    assert str(ctx.value) == "Faulty Stream"

    with pytest.raises(RuntimeError):
        response = client.get("/no-response")

    with client.websocket_connect("/ws") as session:
        text = session.receive_text()
        assert text == "Hello, world!"


def test_state_data_across_multiple_middlewares(test_client_factory):
    expected_value1 = "foo"
    expected_value2 = "bar"

    class aMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.foo = expected_value1
            response = await call_next(request)
            return response

    class bMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.bar = expected_value2
            response = await call_next(request)
            response.headers["X-State-Foo"] = request.state.foo
            return response

    class cMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            response = await call_next(request)
            response.headers["X-State-Bar"] = request.state.bar
            return response

    def homepage(request):
        return PlainTextResponse("OK")

    app = Starlette(
        routes=[Route("/", homepage)],
        middleware=[
            Middleware(aMiddleware),
            Middleware(bMiddleware),
            Middleware(cMiddleware),
        ],
    )

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "OK"
    assert response.headers["X-State-Foo"] == expected_value1
    assert response.headers["X-State-Bar"] == expected_value2


def test_app_middleware_argument(test_client_factory):
    def homepage(request):
        return PlainTextResponse("Homepage")

    app = Starlette(
        routes=[Route("/", homepage)], middleware=[Middleware(CustomMiddleware)]
    )

    client = test_client_factory(app)
    response = client.get("/")
    assert response.headers["Custom-Header"] == "Example"


def test_fully_evaluated_response(test_client_factory):
    # Test for https://github.com/encode/starlette/issues/1022
    class CustomMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            await call_next(request)
            return PlainTextResponse("Custom")

    app = Starlette(middleware=[Middleware(CustomMiddleware)])

    client = test_client_factory(app)
    response = client.get("/does_not_exist")
    assert response.text == "Custom"


ctxvar: contextvars.ContextVar[str] = contextvars.ContextVar("ctxvar")


class CustomMiddlewareWithoutBaseHTTPMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        ctxvar.set("set by middleware")
        await self.app(scope, receive, send)
        assert ctxvar.get() == "set by endpoint"


class CustomMiddlewareUsingBaseHTTPMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        ctxvar.set("set by middleware")
        resp = await call_next(request)
        assert ctxvar.get() == "set by endpoint"
        return resp  # pragma: no cover


@pytest.mark.parametrize(
    "middleware_cls",
    [
        CustomMiddlewareWithoutBaseHTTPMiddleware,
        pytest.param(
            CustomMiddlewareUsingBaseHTTPMiddleware,
            marks=pytest.mark.xfail(
                reason=(
                    "BaseHTTPMiddleware creates a TaskGroup which copies the context"
                    "and erases any changes to it made within the TaskGroup"
                ),
                raises=AssertionError,
            ),
        ),
    ],
)
def test_contextvars(test_client_factory, middleware_cls: type):
    # this has to be an async endpoint because Starlette calls run_in_threadpool
    # on sync endpoints which has it's own set of peculiarities w.r.t propagating
    # contextvars (it propagates them forwards but not backwards)
    async def homepage(request):
        assert ctxvar.get() == "set by middleware"
        ctxvar.set("set by endpoint")
        return PlainTextResponse("Homepage")

    app = Starlette(
        middleware=[Middleware(middleware_cls)], routes=[Route("/", homepage)]
    )

    client = test_client_factory(app)
    response = client.get("/")
    assert response.status_code == 200, response.content
