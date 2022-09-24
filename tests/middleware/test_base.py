import contextvars
from contextlib import AsyncExitStack

import anyio
import pytest

from starlette.applications import Starlette
from starlette.background import BackgroundTask
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


@pytest.mark.anyio
async def test_run_background_tasks_even_if_client_disconnects():
    # test for https://github.com/encode/starlette/issues/1438
    request_body_sent = False
    response_complete = anyio.Event()
    background_task_run = anyio.Event()

    async def sleep_and_set():
        # small delay to give BaseHTTPMiddleware a chance to cancel us
        # this is required to make the test fail prior to fixing the issue
        # so do not be surprised if you remove it and the test still passes
        await anyio.sleep(0.1)
        background_task_run.set()

    async def endpoint_with_background_task(_):
        return PlainTextResponse(background=BackgroundTask(sleep_and_set))

    async def passthrough(request, call_next):
        return await call_next(request)

    app = Starlette(
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=passthrough)],
        routes=[Route("/", endpoint_with_background_task)],
    )

    scope = {
        "type": "http",
        "version": "3",
        "method": "GET",
        "path": "/",
    }

    async def receive():
        nonlocal request_body_sent
        if not request_body_sent:
            request_body_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        # We simulate a client that disconnects immediately after receiving the response
        await response_complete.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == "http.response.body":
            if not message.get("more_body", False):
                response_complete.set()

    await app(scope, receive, send)

    assert background_task_run.is_set()


@pytest.mark.anyio
async def test_run_context_manager_exit_even_if_client_disconnects():
    # test for https://github.com/encode/starlette/issues/1678#issuecomment-1172916042
    request_body_sent = False
    response_complete = anyio.Event()
    context_manager_exited = anyio.Event()

    async def sleep_and_set():
        # small delay to give BaseHTTPMiddleware a chance to cancel us
        # this is required to make the test fail prior to fixing the issue
        # so do not be surprised if you remove it and the test still passes
        await anyio.sleep(0.1)
        context_manager_exited.set()

    class ContextManagerMiddleware:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send):
            async with AsyncExitStack() as stack:
                stack.push_async_callback(sleep_and_set)
                await self.app(scope, receive, send)

    async def simple_endpoint(_):
        return PlainTextResponse(background=BackgroundTask(sleep_and_set))

    async def passthrough(request, call_next):
        return await call_next(request)

    app = Starlette(
        middleware=[
            Middleware(BaseHTTPMiddleware, dispatch=passthrough),
            Middleware(ContextManagerMiddleware),
        ],
        routes=[Route("/", simple_endpoint)],
    )

    scope = {
        "type": "http",
        "version": "3",
        "method": "GET",
        "path": "/",
    }

    async def receive():
        nonlocal request_body_sent
        if not request_body_sent:
            request_body_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        # We simulate a client that disconnects immediately after receiving the response
        await response_complete.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == "http.response.body":
            if not message.get("more_body", False):
                response_complete.set()

    await app(scope, receive, send)

    assert context_manager_exited.is_set()


def test_app_receives_http_disconnect_while_sending_if_discarded(test_client_factory):
    class DiscardingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            await call_next(request)
            return PlainTextResponse("Custom")

    async def downstream_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                ],
            }
        )
        async with anyio.create_task_group() as task_group:

            async def cancel_on_disconnect():
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        task_group.cancel_scope.cancel()
                        break

            task_group.start_soon(cancel_on_disconnect)

            # A timeout is set for 0.1 second in order to ensure that
            # cancel_on_disconnect is scheduled by the event loop
            with anyio.move_on_after(0.1):
                while True:
                    await send(
                        {
                            "type": "http.response.body",
                            "body": b"chunk ",
                            "more_body": True,
                        }
                    )

            pytest.fail(
                "http.disconnect should have been received and canceled the scope"
            )  # pragma: no cover

    app = DiscardingMiddleware(downstream_app)

    client = test_client_factory(app)
    response = client.get("/does_not_exist")
    assert response.text == "Custom"


def test_app_receives_http_disconnect_after_sending_if_discarded(test_client_factory):
    class DiscardingMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            await call_next(request)
            return PlainTextResponse("Custom")

    async def downstream_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"text/plain"),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"first chunk, ",
                "more_body": True,
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"second chunk",
                "more_body": True,
            }
        )
        message = await receive()
        assert message["type"] == "http.disconnect"

    app = DiscardingMiddleware(downstream_app)

    client = test_client_factory(app)
    response = client.get("/does_not_exist")
    assert response.text == "Custom"
