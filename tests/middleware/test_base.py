from __future__ import annotations

import contextvars
from contextlib import AsyncExitStack
from typing import Any, AsyncGenerator, AsyncIterator, Generator

import anyio
import pytest
from anyio.abc import TaskStatus

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware import Middleware, _MiddlewareFactory
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import ClientDisconnect, Request
from starlette.responses import PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocket
from tests.types import TestClientFactory


class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        response = await call_next(request)
        response.headers["Custom-Header"] = "Example"
        return response


def homepage(request: Request) -> PlainTextResponse:
    return PlainTextResponse("Homepage")


def exc(request: Request) -> None:
    raise Exception("Exc")


def exc_stream(request: Request) -> StreamingResponse:
    return StreamingResponse(_generate_faulty_stream())


def _generate_faulty_stream() -> Generator[bytes, None, None]:
    yield b"Ok"
    raise Exception("Faulty Stream")


class NoResponse:
    def __init__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ):
        pass

    def __await__(self) -> Generator[Any, None, None]:
        return self.dispatch().__await__()

    async def dispatch(self) -> None:
        pass


async def websocket_endpoint(session: WebSocket) -> None:
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


def test_custom_middleware(test_client_factory: TestClientFactory) -> None:
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


def test_state_data_across_multiple_middlewares(
    test_client_factory: TestClientFactory,
) -> None:
    expected_value1 = "foo"
    expected_value2 = "bar"

    class aMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            request.state.foo = expected_value1
            response = await call_next(request)
            return response

    class bMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            request.state.bar = expected_value2
            response = await call_next(request)
            response.headers["X-State-Foo"] = request.state.foo
            return response

    class cMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            response = await call_next(request)
            response.headers["X-State-Bar"] = request.state.bar
            return response

    def homepage(request: Request) -> PlainTextResponse:
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


def test_app_middleware_argument(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage")

    app = Starlette(routes=[Route("/", homepage)], middleware=[Middleware(CustomMiddleware)])

    client = test_client_factory(app)
    response = client.get("/")
    assert response.headers["Custom-Header"] == "Example"


def test_fully_evaluated_response(test_client_factory: TestClientFactory) -> None:
    # Test for https://github.com/encode/starlette/issues/1022
    class CustomMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> PlainTextResponse:
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
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
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
def test_contextvars(
    test_client_factory: TestClientFactory,
    middleware_cls: _MiddlewareFactory[Any],
) -> None:
    # this has to be an async endpoint because Starlette calls run_in_threadpool
    # on sync endpoints which has it's own set of peculiarities w.r.t propagating
    # contextvars (it propagates them forwards but not backwards)
    async def homepage(request: Request) -> PlainTextResponse:
        assert ctxvar.get() == "set by middleware"
        ctxvar.set("set by endpoint")
        return PlainTextResponse("Homepage")

    app = Starlette(middleware=[Middleware(middleware_cls)], routes=[Route("/", homepage)])

    client = test_client_factory(app)
    response = client.get("/")
    assert response.status_code == 200, response.content


@pytest.mark.anyio
async def test_run_background_tasks_even_if_client_disconnects() -> None:
    # test for https://github.com/encode/starlette/issues/1438
    response_complete = anyio.Event()
    background_task_run = anyio.Event()

    async def sleep_and_set() -> None:
        # small delay to give BaseHTTPMiddleware a chance to cancel us
        # this is required to make the test fail prior to fixing the issue
        # so do not be surprised if you remove it and the test still passes
        await anyio.sleep(0.1)
        background_task_run.set()

    async def endpoint_with_background_task(_: Request) -> PlainTextResponse:
        return PlainTextResponse(background=BackgroundTask(sleep_and_set))

    async def passthrough(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
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

    async def receive() -> Message:
        raise NotImplementedError("Should not be called!")

    async def send(message: Message) -> None:
        if message["type"] == "http.response.body":
            if not message.get("more_body", False):  # pragma: no branch
                response_complete.set()

    await app(scope, receive, send)

    assert background_task_run.is_set()


@pytest.mark.anyio
async def test_do_not_block_on_background_tasks() -> None:
    response_complete = anyio.Event()
    events: list[str | Message] = []

    async def sleep_and_set() -> None:
        events.append("Background task started")
        await anyio.sleep(0.1)
        events.append("Background task finished")

    async def endpoint_with_background_task(_: Request) -> PlainTextResponse:
        return PlainTextResponse(content="Hello", background=BackgroundTask(sleep_and_set))

    async def passthrough(request: Request, call_next: RequestResponseEndpoint) -> Response:
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

    async def receive() -> Message:
        raise NotImplementedError("Should not be called!")

    async def send(message: Message) -> None:
        if message["type"] == "http.response.body":
            events.append(message)
            if not message.get("more_body", False):
                response_complete.set()

    async with anyio.create_task_group() as tg:
        tg.start_soon(app, scope, receive, send)
        tg.start_soon(app, scope, receive, send)

    # Without the fix, the background tasks would start and finish before the
    # last http.response.body is sent.
    assert events == [
        {"body": b"Hello", "more_body": True, "type": "http.response.body"},
        {"body": b"", "more_body": False, "type": "http.response.body"},
        {"body": b"Hello", "more_body": True, "type": "http.response.body"},
        {"body": b"", "more_body": False, "type": "http.response.body"},
        "Background task started",
        "Background task started",
        "Background task finished",
        "Background task finished",
    ]


@pytest.mark.anyio
async def test_run_context_manager_exit_even_if_client_disconnects() -> None:
    # test for https://github.com/encode/starlette/issues/1678#issuecomment-1172916042
    response_complete = anyio.Event()
    context_manager_exited = anyio.Event()

    async def sleep_and_set() -> None:
        # small delay to give BaseHTTPMiddleware a chance to cancel us
        # this is required to make the test fail prior to fixing the issue
        # so do not be surprised if you remove it and the test still passes
        await anyio.sleep(0.1)
        context_manager_exited.set()

    class ContextManagerMiddleware:
        def __init__(self, app: ASGIApp):
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            async with AsyncExitStack() as stack:
                stack.push_async_callback(sleep_and_set)
                await self.app(scope, receive, send)

    async def simple_endpoint(_: Request) -> PlainTextResponse:
        return PlainTextResponse(background=BackgroundTask(sleep_and_set))

    async def passthrough(
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
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

    async def receive() -> Message:
        raise NotImplementedError("Should not be called!")

    async def send(message: Message) -> None:
        if message["type"] == "http.response.body":
            if not message.get("more_body", False):  # pragma: no branch
                response_complete.set()

    await app(scope, receive, send)

    assert context_manager_exited.is_set()


def test_app_receives_http_disconnect_while_sending_if_discarded(
    test_client_factory: TestClientFactory,
) -> None:
    class DiscardingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: Any,
        ) -> PlainTextResponse:
            # As a matter of ordering, this test targets the case where the downstream
            # app response is discarded while it is sending a response body.
            # We need to wait for the downstream app to begin sending a response body
            # before sending the middleware response that will overwrite the downstream
            # response.
            downstream_app_response = await call_next(request)
            body_generator = downstream_app_response.body_iterator
            try:
                await body_generator.__anext__()
            finally:
                await body_generator.aclose()

            return PlainTextResponse("Custom")

    async def downstream_app(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
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

            async def cancel_on_disconnect(
                *,
                task_status: TaskStatus[None] = anyio.TASK_STATUS_IGNORED,
            ) -> None:
                task_status.started()
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":  # pragma: no branch
                        task_group.cancel_scope.cancel()
                        break

            # Using start instead of start_soon to ensure that
            # cancel_on_disconnect is scheduled by the event loop
            # before we start returning the body
            await task_group.start(cancel_on_disconnect)

            # A timeout is set for 0.1 second in order to ensure that
            # we never deadlock the test run in an infinite loop
            with anyio.move_on_after(0.1):
                while True:
                    await send(
                        {
                            "type": "http.response.body",
                            "body": b"chunk ",
                            "more_body": True,
                        }
                    )

            pytest.fail("http.disconnect should have been received and canceled the scope")  # pragma: no cover

    app = DiscardingMiddleware(downstream_app)

    client = test_client_factory(app)
    response = client.get("/does_not_exist")
    assert response.text == "Custom"


def test_app_receives_http_disconnect_after_sending_if_discarded(
    test_client_factory: TestClientFactory,
) -> None:
    class DiscardingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> PlainTextResponse:
            await call_next(request)
            return PlainTextResponse("Custom")

    async def downstream_app(
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
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


def test_read_request_stream_in_app_after_middleware_calls_stream(
    test_client_factory: TestClientFactory,
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        expected = [b""]
        async for chunk in request.stream():
            assert chunk == expected.pop(0)
        assert expected == []
        return PlainTextResponse("Homepage")

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            expected = [b"a", b""]
            async for chunk in request.stream():
                assert chunk == expected.pop(0)
            assert expected == []
            return await call_next(request)

    app = Starlette(
        routes=[Route("/", homepage, methods=["POST"])],
        middleware=[Middleware(ConsumingMiddleware)],
    )

    client: TestClient = test_client_factory(app)
    response = client.post("/", content=b"a")
    assert response.status_code == 200


def test_read_request_stream_in_app_after_middleware_calls_body(
    test_client_factory: TestClientFactory,
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        expected = [b"a", b""]
        async for chunk in request.stream():
            assert chunk == expected.pop(0)
        assert expected == []
        return PlainTextResponse("Homepage")

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            assert await request.body() == b"a"
            return await call_next(request)

    app = Starlette(
        routes=[Route("/", homepage, methods=["POST"])],
        middleware=[Middleware(ConsumingMiddleware)],
    )

    client: TestClient = test_client_factory(app)
    response = client.post("/", content=b"a")
    assert response.status_code == 200


def test_read_request_body_in_app_after_middleware_calls_stream(
    test_client_factory: TestClientFactory,
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        assert await request.body() == b""
        return PlainTextResponse("Homepage")

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            expected = [b"a", b""]
            async for chunk in request.stream():
                assert chunk == expected.pop(0)
            assert expected == []
            return await call_next(request)

    app = Starlette(
        routes=[Route("/", homepage, methods=["POST"])],
        middleware=[Middleware(ConsumingMiddleware)],
    )

    client: TestClient = test_client_factory(app)
    response = client.post("/", content=b"a")
    assert response.status_code == 200


def test_read_request_body_in_app_after_middleware_calls_body(
    test_client_factory: TestClientFactory,
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        assert await request.body() == b"a"
        return PlainTextResponse("Homepage")

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            assert await request.body() == b"a"
            return await call_next(request)

    app = Starlette(
        routes=[Route("/", homepage, methods=["POST"])],
        middleware=[Middleware(ConsumingMiddleware)],
    )

    client: TestClient = test_client_factory(app)
    response = client.post("/", content=b"a")
    assert response.status_code == 200


def test_read_request_stream_in_dispatch_after_app_calls_stream(
    test_client_factory: TestClientFactory,
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        expected = [b"a", b""]
        async for chunk in request.stream():
            assert chunk == expected.pop(0)
        assert expected == []
        return PlainTextResponse("Homepage")

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            resp = await call_next(request)
            with pytest.raises(RuntimeError, match="Stream consumed"):
                async for _ in request.stream():
                    raise AssertionError("should not be called")  # pragma: no cover
            return resp

    app = Starlette(
        routes=[Route("/", homepage, methods=["POST"])],
        middleware=[Middleware(ConsumingMiddleware)],
    )

    client: TestClient = test_client_factory(app)
    response = client.post("/", content=b"a")
    assert response.status_code == 200


def test_read_request_stream_in_dispatch_after_app_calls_body(
    test_client_factory: TestClientFactory,
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        assert await request.body() == b"a"
        return PlainTextResponse("Homepage")

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            resp = await call_next(request)
            with pytest.raises(RuntimeError, match="Stream consumed"):
                async for _ in request.stream():
                    raise AssertionError("should not be called")  # pragma: no cover
            return resp

    app = Starlette(
        routes=[Route("/", homepage, methods=["POST"])],
        middleware=[Middleware(ConsumingMiddleware)],
    )

    client: TestClient = test_client_factory(app)
    response = client.post("/", content=b"a")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_read_request_stream_in_dispatch_wrapping_app_calls_body() -> None:
    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        async for chunk in request.stream():  # pragma: no branch
            assert chunk == b"2"
            break
        await Response()(scope, receive, send)

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            expected = b"1"
            response: Response | None = None
            async for chunk in request.stream():  # pragma: no branch
                assert chunk == expected
                if expected == b"1":
                    response = await call_next(request)
                    expected = b"3"
                else:
                    break
            assert response is not None
            return response

    async def rcv() -> AsyncGenerator[Message, None]:
        yield {"type": "http.request", "body": b"1", "more_body": True}
        yield {"type": "http.request", "body": b"2", "more_body": True}
        yield {"type": "http.request", "body": b"3"}
        raise AssertionError(  # pragma: no cover
            "Should not be called, no need to poll for disconnect"
        )

    sent: list[Message] = []

    async def send(msg: Message) -> None:
        sent.append(msg)

    app: ASGIApp = endpoint
    app = ConsumingMiddleware(app)

    rcv_stream = rcv()

    await app({"type": "http"}, rcv_stream.__anext__, send)

    assert sent == [
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", b"0")],
        },
        {"type": "http.response.body", "body": b"", "more_body": False},
    ]

    await rcv_stream.aclose()


def test_read_request_stream_in_dispatch_after_app_calls_body_with_middleware_calling_body_before_call_next(
    test_client_factory: TestClientFactory,
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        assert await request.body() == b"a"
        return PlainTextResponse("Homepage")

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            assert await request.body() == b"a"  # this buffers the request body in memory
            resp = await call_next(request)
            async for chunk in request.stream():
                if chunk:
                    assert chunk == b"a"
            return resp

    app = Starlette(
        routes=[Route("/", homepage, methods=["POST"])],
        middleware=[Middleware(ConsumingMiddleware)],
    )

    client: TestClient = test_client_factory(app)
    response = client.post("/", content=b"a")
    assert response.status_code == 200


def test_read_request_body_in_dispatch_after_app_calls_body_with_middleware_calling_body_before_call_next(
    test_client_factory: TestClientFactory,
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        assert await request.body() == b"a"
        return PlainTextResponse("Homepage")

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            assert await request.body() == b"a"  # this buffers the request body in memory
            resp = await call_next(request)
            assert await request.body() == b"a"  # no problem here
            return resp

    app = Starlette(
        routes=[Route("/", homepage, methods=["POST"])],
        middleware=[Middleware(ConsumingMiddleware)],
    )

    client: TestClient = test_client_factory(app)
    response = client.post("/", content=b"a")
    assert response.status_code == 200


@pytest.mark.anyio
async def test_read_request_disconnected_client() -> None:
    """If we receive a disconnect message when the downstream ASGI
    app calls receive() the Request instance passed into the dispatch function
    should get marked as disconnected.
    The downstream ASGI app should not get a ClientDisconnect raised,
    instead if should just receive the disconnect message.
    """

    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        msg = await receive()
        assert msg["type"] == "http.disconnect"
        await Response()(scope, receive, send)

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            response = await call_next(request)
            disconnected = await request.is_disconnected()
            assert disconnected is True
            return response

    scope = {"type": "http", "method": "POST", "path": "/"}

    async def receive() -> AsyncGenerator[Message, None]:
        yield {"type": "http.disconnect"}
        raise AssertionError("Should not be called, would hang")  # pragma: no cover

    async def send(msg: Message) -> None:
        if msg["type"] == "http.response.start":
            assert msg["status"] == 200

    app: ASGIApp = ConsumingMiddleware(endpoint)

    rcv = receive()

    await app(scope, rcv.__anext__, send)

    await rcv.aclose()


@pytest.mark.anyio
async def test_read_request_disconnected_after_consuming_steam() -> None:
    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        msg = await receive()
        assert msg.pop("more_body", False) is False
        assert msg == {"type": "http.request", "body": b"hi"}
        msg = await receive()
        assert msg == {"type": "http.disconnect"}
        await Response()(scope, receive, send)

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            await request.body()
            disconnected = await request.is_disconnected()
            assert disconnected is True
            response = await call_next(request)
            return response

    scope = {"type": "http", "method": "POST", "path": "/"}

    async def receive() -> AsyncGenerator[Message, None]:
        yield {"type": "http.request", "body": b"hi"}
        yield {"type": "http.disconnect"}
        raise AssertionError("Should not be called, would hang")  # pragma: no cover

    async def send(msg: Message) -> None:
        if msg["type"] == "http.response.start":
            assert msg["status"] == 200

    app: ASGIApp = ConsumingMiddleware(endpoint)

    rcv = receive()

    await app(scope, rcv.__anext__, send)

    await rcv.aclose()


def test_downstream_middleware_modifies_receive(
    test_client_factory: TestClientFactory,
) -> None:
    """If a downstream middleware modifies receive() the final ASGI app
    should see the modified version.
    """

    async def endpoint(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        body = await request.body()
        assert body == b"foo foo "
        await Response()(scope, receive, send)

    class ConsumingMiddleware(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            body = await request.body()
            assert body == b"foo "
            return await call_next(request)

    def modifying_middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped_app(scope: Scope, receive: Receive, send: Send) -> None:
            async def wrapped_receive() -> Message:
                msg = await receive()
                if msg["type"] == "http.request":  # pragma: no branch
                    msg["body"] = msg["body"] * 2
                return msg

            await app(scope, wrapped_receive, send)

        return wrapped_app

    client = test_client_factory(ConsumingMiddleware(modifying_middleware(endpoint)))

    resp = client.post("/", content=b"foo ")
    assert resp.status_code == 200


def test_pr_1519_comment_1236166180_example() -> None:
    """
    https://github.com/encode/starlette/pull/1519#issuecomment-1236166180
    """
    bodies: list[bytes] = []

    class LogRequestBodySize(BaseHTTPMiddleware):
        async def dispatch(
            self,
            request: Request,
            call_next: RequestResponseEndpoint,
        ) -> Response:
            print(len(await request.body()))
            return await call_next(request)

    def replace_body_middleware(app: ASGIApp) -> ASGIApp:
        async def wrapped_app(scope: Scope, receive: Receive, send: Send) -> None:
            async def wrapped_rcv() -> Message:
                msg = await receive()
                msg["body"] += b"-foo"
                return msg

            await app(scope, wrapped_rcv, send)

        return wrapped_app

    async def endpoint(request: Request) -> Response:
        body = await request.body()
        bodies.append(body)
        return Response()

    app: ASGIApp = Starlette(routes=[Route("/", endpoint, methods=["POST"])])
    app = replace_body_middleware(app)
    app = LogRequestBodySize(app)

    client = TestClient(app)
    resp = client.post("/", content=b"Hello, World!")
    resp.raise_for_status()

    assert bodies == [b"Hello, World!-foo"]


@pytest.mark.anyio
async def test_multiple_middlewares_stacked_client_disconnected() -> None:
    """
    Tests for:
    - https://github.com/encode/starlette/issues/2516
    - https://github.com/encode/starlette/pull/2687
    """
    ordered_events: list[str] = []
    unordered_events: list[str] = []

    class MyMiddleware(BaseHTTPMiddleware):
        def __init__(self, app: ASGIApp, version: int) -> None:
            self.version = version
            super().__init__(app)

        async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
            ordered_events.append(f"{self.version}:STARTED")
            res = await call_next(request)
            ordered_events.append(f"{self.version}:COMPLETED")

            def background() -> None:
                unordered_events.append(f"{self.version}:BACKGROUND")

            assert res.background is None
            res.background = BackgroundTask(background)
            return res

    async def sleepy(request: Request) -> Response:
        try:
            await request.body()
        except ClientDisconnect:
            pass
        else:  # pragma: no cover
            raise AssertionError("Should have raised ClientDisconnect")
        return Response(b"")

    app = Starlette(
        routes=[Route("/", sleepy)],
        middleware=[Middleware(MyMiddleware, version=_ + 1) for _ in range(10)],
    )

    scope = {
        "type": "http",
        "version": "3",
        "method": "GET",
        "path": "/",
    }

    async def receive() -> AsyncIterator[Message]:
        yield {"type": "http.disconnect"}

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive().__anext__, send)

    assert ordered_events == [
        "1:STARTED",
        "2:STARTED",
        "3:STARTED",
        "4:STARTED",
        "5:STARTED",
        "6:STARTED",
        "7:STARTED",
        "8:STARTED",
        "9:STARTED",
        "10:STARTED",
        "10:COMPLETED",
        "9:COMPLETED",
        "8:COMPLETED",
        "7:COMPLETED",
        "6:COMPLETED",
        "5:COMPLETED",
        "4:COMPLETED",
        "3:COMPLETED",
        "2:COMPLETED",
        "1:COMPLETED",
    ]

    assert sorted(unordered_events) == sorted(
        [
            "1:BACKGROUND",
            "2:BACKGROUND",
            "3:BACKGROUND",
            "4:BACKGROUND",
            "5:BACKGROUND",
            "6:BACKGROUND",
            "7:BACKGROUND",
            "8:BACKGROUND",
            "9:BACKGROUND",
            "10:BACKGROUND",
        ]
    )

    assert sent == [
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", b"0")],
        },
        {"type": "http.response.body", "body": b"", "more_body": False},
    ]


@pytest.mark.anyio
@pytest.mark.parametrize("send_body", [True, False])
async def test_poll_for_disconnect_repeated(send_body: bool) -> None:
    async def app_poll_disconnect(scope: Scope, receive: Receive, send: Send) -> None:
        for _ in range(2):
            msg = await receive()
            while msg["type"] == "http.request":
                msg = await receive()
            assert msg["type"] == "http.disconnect"
        await Response(b"good!")(scope, receive, send)

    class MyMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
            return await call_next(request)

    app = MyMiddleware(app_poll_disconnect)

    scope = {
        "type": "http",
        "version": "3",
        "method": "GET",
        "path": "/",
    }

    async def receive() -> AsyncIterator[Message]:
        # the key here is that we only ever send 1 htt.disconnect message
        if send_body:
            yield {"type": "http.request", "body": b"hello", "more_body": True}
            yield {"type": "http.request", "body": b"", "more_body": False}
        yield {"type": "http.disconnect"}
        raise AssertionError("Should not be called, would hang")  # pragma: no cover

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive().__anext__, send)

    assert sent == [
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-length", b"5")],
        },
        {"type": "http.response.body", "body": b"good!", "more_body": True},
        {"type": "http.response.body", "body": b"", "more_body": False},
    ]
