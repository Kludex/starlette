from __future__ import annotations

import inspect
import itertools
import threading
from asyncio import CancelledError as AsyncioCancelledError, Task, current_task as asyncio_current_task
from collections.abc import AsyncGenerator, Callable, Generator
from concurrent.futures import CancelledError, Future
from contextlib import asynccontextmanager, nullcontext
from typing import Any

import anyio
import anyio.lowlevel
import pytest
import sniffio
import trio.lowlevel
from anyio.from_thread import BlockingPortal
from anyio.streams.memory import MemoryObjectSendStream

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.exceptions import StarletteDeprecationWarning
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.testclient import ASGIInstance, TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect
from tests.types import TestClientFactory


def mock_service_endpoint(request: Request) -> JSONResponse:
    return JSONResponse({"mock": "example"})


mock_service = Starlette(routes=[Route("/", endpoint=mock_service_endpoint)])


def current_task() -> Task[Any] | trio.lowlevel.Task:
    # anyio's TaskInfo comparisons are invalid after their associated native
    # task object is GC'd https://github.com/agronholm/anyio/issues/324
    asynclib_name = sniffio.current_async_library()
    if asynclib_name == "trio":
        return trio.lowlevel.current_task()

    if asynclib_name == "asyncio":
        task = asyncio_current_task()
        if task is None:
            raise RuntimeError("must be called from a running task")  # pragma: no cover
        return task
    raise RuntimeError(f"unsupported asynclib={asynclib_name}")  # pragma: no cover


def test_use_testclient_in_endpoint(test_client_factory: TestClientFactory) -> None:
    """
    We should be able to use the test client within applications.

    This is useful if we need to mock out other services,
    during tests or in development.
    """

    def homepage(request: Request) -> JSONResponse:
        client = test_client_factory(mock_service)
        response = client.get("/")
        return JSONResponse(response.json())

    app = Starlette(routes=[Route("/", endpoint=homepage)])

    client = test_client_factory(app)
    response = client.get("/")
    assert response.json() == {"mock": "example"}


def test_testclient_headers_behavior() -> None:
    """
    We should be able to use the test client with user defined headers.

    This is useful if we need to set custom headers for authentication
    during tests or in development.
    """

    client = TestClient(mock_service)
    assert client.headers.get("user-agent") == "testclient"

    client = TestClient(mock_service, headers={"user-agent": "non-default-agent"})
    assert client.headers.get("user-agent") == "non-default-agent"

    client = TestClient(mock_service, headers={"Authentication": "Bearer 123"})
    assert client.headers.get("user-agent") == "testclient"
    assert client.headers.get("Authentication") == "Bearer 123"


def test_use_testclient_as_contextmanager(test_client_factory: TestClientFactory, anyio_backend_name: str) -> None:
    """
    This test asserts a number of properties that are important for an
    app level task_group
    """
    counter = itertools.count()
    identity_runvar = anyio.lowlevel.RunVar[int]("identity_runvar")

    def get_identity() -> int:
        try:
            return identity_runvar.get()
        except LookupError:
            token = next(counter)
            identity_runvar.set(token)
            return token

    startup_task = object()
    startup_loop = None
    shutdown_task = object()
    shutdown_loop = None

    @asynccontextmanager
    async def lifespan_context(app: Starlette) -> AsyncGenerator[None, None]:
        nonlocal startup_task, startup_loop, shutdown_task, shutdown_loop

        startup_task = current_task()
        startup_loop = get_identity()
        async with anyio.create_task_group():
            yield
        shutdown_task = current_task()
        shutdown_loop = get_identity()

    async def loop_id(request: Request) -> JSONResponse:
        return JSONResponse(get_identity())

    app = Starlette(
        lifespan=lifespan_context,
        routes=[Route("/loop_id", endpoint=loop_id)],
    )

    client = test_client_factory(app)

    with client:
        # within a TestClient context every async request runs in the same thread
        assert client.get("/loop_id").json() == 0
        assert client.get("/loop_id").json() == 0

    # that thread is also the same as the lifespan thread
    assert startup_loop == 0
    assert shutdown_loop == 0

    # lifespan events run in the same task, this is important because a task
    # group must be entered and exited in the same task.
    assert startup_task is shutdown_task

    # outside the TestClient context, new requests continue to spawn in new
    # event loops in new threads
    assert client.get("/loop_id").json() == 1
    assert client.get("/loop_id").json() == 2

    first_task = startup_task

    with client:
        # the TestClient context can be re-used, starting a new lifespan task
        # in a new thread
        assert client.get("/loop_id").json() == 3
        assert client.get("/loop_id").json() == 3

    assert startup_loop == 3
    assert shutdown_loop == 3

    # lifespan events still run in the same task, with the context but...
    assert startup_task is shutdown_task

    # ... the second TestClient context creates a new lifespan task.
    assert first_task is not startup_task


def test_error_on_startup(test_client_factory: TestClientFactory) -> None:
    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncGenerator[None, None]:
        raise RuntimeError("Startup error")
        yield

    startup_error_app = Starlette(lifespan=lifespan)

    with pytest.raises(RuntimeError, match="Startup error"):
        with test_client_factory(startup_error_app):
            pass  # pragma: no cover


def test_exception_in_middleware(test_client_factory: TestClientFactory) -> None:
    class MiddlewareException(Exception):
        pass

    class BrokenMiddleware:
        def __init__(self, app: ASGIApp):
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            raise MiddlewareException()

    broken_middleware = Starlette(middleware=[Middleware(BrokenMiddleware)])

    with pytest.raises(MiddlewareException):
        with test_client_factory(broken_middleware):
            pass  # pragma: no cover


def test_testclient_asgi2(test_client_factory: TestClientFactory) -> None:
    def app(scope: Scope) -> ASGIInstance:
        async def inner(receive: Receive, send: Send) -> None:
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [[b"content-type", b"text/plain"]],
                }
            )
            await send({"type": "http.response.body", "body": b"Hello, world!"})

        return inner

    client = test_client_factory(app)  # type: ignore
    response = client.get("/")
    assert response.text == "Hello, world!"


def test_testclient_asgi3(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.body", "body": b"Hello, world!"})

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "Hello, world!"


def test_testclient_requires_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        pass

    client = test_client_factory(app)
    with pytest.raises(AssertionError, match="TestClient did not receive any response"):
        client.get("/")


def test_streaming_response_is_available_before_first_chunk(test_client_factory: TestClientFactory) -> None:
    release_response = threading.Event()

    async def stream() -> AsyncGenerator[bytes, None]:
        assert await anyio.to_thread.run_sync(release_response.wait, 10)
        yield b"hello"

    async def homepage(request: Request) -> StreamingResponse:
        return StreamingResponse(stream())

    client = test_client_factory(Starlette(routes=[Route("/", homepage)]))
    with client.stream("GET", "/") as response:
        release_response.set()
        assert response.read() == b"hello"


def test_streaming_response_applies_backpressure(test_client_factory: TestClientFactory) -> None:
    second_chunk_started = threading.Event()

    async def stream() -> AsyncGenerator[bytes, None]:
        yield b"one"
        second_chunk_started.set()
        yield b"two"

    async def homepage(request: Request) -> StreamingResponse:
        return StreamingResponse(stream())

    client = test_client_factory(Starlette(routes=[Route("/", homepage)]))
    with client.stream("GET", "/") as response:
        chunks = response.iter_raw()
        assert not second_chunk_started.is_set()
        assert next(chunks) == b"one"
        assert second_chunk_started.wait(timeout=10)
        assert list(chunks) == [b"two"]


@pytest.mark.parametrize(("method", "body"), [("GET", b""), ("HEAD", b"chunk")])
def test_streaming_response_applies_backpressure_to_ignored_body(
    test_client_factory: TestClientFactory,
    method: str,
    body: bytes,
) -> None:
    response_opened = threading.Event()
    stop_streaming = threading.Event()

    async def http_app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        while not stop_streaming.is_set():
            await send({"type": "http.response.body", "body": body, "more_body": True})
        await send({"type": "http.response.body", "body": b""})

    client = test_client_factory(http_app)
    response_body: list[bytes] = []

    def open_response() -> None:
        with client.stream(method, "/") as response:
            response_opened.set()
            response_body.append(response.read())

    thread = threading.Thread(target=open_response, daemon=True)
    thread.start()
    try:
        assert response_opened.wait(timeout=10)
    finally:
        stop_streaming.set()
        thread.join(timeout=10)
    assert not thread.is_alive()
    assert response_body == [b""]


def test_closing_streaming_response_stops_application(test_client_factory: TestClientFactory) -> None:
    app_finished = threading.Event()

    async def http_app(scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            while True:
                await send({"type": "http.response.body", "body": b"chunk", "more_body": True})
        finally:
            app_finished.set()

    client = test_client_factory(Starlette(routes=[Mount("/", app=http_app)]))
    with client:
        with client.stream("GET", "/") as response:
            assert next(response.iter_raw()) == b"chunk"
        assert app_finished.is_set()


@pytest.mark.parametrize("lifespan", [True, False])
@pytest.mark.parametrize("close_iterator", [True, False])
@pytest.mark.parametrize(("fail", "raise_server_exceptions"), [(False, True), (True, True), (True, False)])
def test_closing_completed_response_waits_for_background_task(
    test_client_factory: TestClientFactory,
    lifespan: bool,
    close_iterator: bool,
    fail: bool,
    raise_server_exceptions: bool,
) -> None:
    started = threading.Event()
    completed = threading.Event()

    async def background() -> None:
        started.set()
        await anyio.sleep(0.1)
        completed.set()
        if fail:
            raise RuntimeError("background failure")

    async def homepage(request: Request) -> Response:
        return Response(b"hello", background=BackgroundTask(background))

    client = test_client_factory(
        Starlette(routes=[Route("/", homepage)]), raise_server_exceptions=raise_server_exceptions
    )
    expected = (
        pytest.raises(RuntimeError, match="background failure") if fail and raise_server_exceptions else nullcontext()
    )
    with client if lifespan else nullcontext():
        with expected:
            with client.stream("GET", "/") as response:
                chunks = response.iter_raw()
                assert next(chunks) == b"hello"
                assert started.wait(timeout=10)
                if close_iterator:
                    assert isinstance(chunks, Generator)
                    chunks.close()
        assert completed.is_set()


@pytest.mark.parametrize("lifespan", [True, False])
@pytest.mark.parametrize("fail", [True, False])
def test_interrupted_completed_response_cancels_background_task(
    test_client_factory: TestClientFactory, monkeypatch: pytest.MonkeyPatch, lifespan: bool, fail: bool
) -> None:
    started = threading.Event()
    finished = threading.Event()
    background_timeout: anyio.CancelScope
    original_call = BlockingPortal.call

    async def background() -> None:
        nonlocal background_timeout
        with anyio.move_on_after(10) as background_timeout:
            try:
                started.set()
                await anyio.sleep_forever()
            except anyio.get_cancelled_exc_class():
                if fail:
                    raise RuntimeError("cleanup failure")
                raise
            finally:
                finished.set()

    async def homepage(request: Request) -> Response:
        return Response(b"hello", background=BackgroundTask(background))

    def call(portal: BlockingPortal, func: Callable[..., Any], *args: Any) -> Any:
        result = original_call(portal, func, *args)
        if result == b"hello":
            patch.undo()
            assert started.wait(timeout=10)
            raise KeyboardInterrupt
        return result

    client = test_client_factory(Starlette(routes=[Route("/", homepage), Route("/ready", mock_service_endpoint)]))
    with client if lifespan else nullcontext():
        with monkeypatch.context() as patch:
            patch.setattr(BlockingPortal, "call", call)
            with pytest.raises(KeyboardInterrupt):
                client.get("/")
        assert finished.is_set()
        assert not background_timeout.cancel_called
        assert client.get("/ready").json() == {"mock": "example"}


def test_closing_response_after_final_chunk_handoff(
    test_client_factory: TestClientFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    completed = threading.Event()
    original_send = MemoryObjectSendStream.send

    async def delayed_send(stream: MemoryObjectSendStream[Any], item: Any) -> None:
        await original_send(stream, item)
        await anyio.sleep(0.1)

    async def background() -> None:
        completed.set()

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await Response(b"hello", background=BackgroundTask(background))(scope, receive, send)

    monkeypatch.setattr(MemoryObjectSendStream, "send", delayed_send)
    client = test_client_factory(app)
    with client.stream("GET", "/") as response:
        chunks = response.iter_raw()
        assert next(chunks) == b"hello"
    assert completed.is_set()


@pytest.mark.parametrize("trailers", [True, False])
def test_closing_response_cancels_pending_body_or_trailers(
    test_client_factory: TestClientFactory, trailers: bool
) -> None:
    finished = threading.Event()
    app_timeout: anyio.CancelScope

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal app_timeout
        with anyio.move_on_after(10) as app_timeout:
            try:
                await send({"type": "http.response.start", "status": 200, "trailers": trailers})
                await send({"type": "http.response.body", "body": b"hello"})
                await anyio.sleep_forever()
            finally:
                finished.set()

    client = test_client_factory(app)
    with client.stream("GET", "/") as response:
        if trailers:
            chunks = response.iter_raw()
            assert next(chunks) == b"hello"
    assert finished.is_set()
    assert not app_timeout.cancel_called


@pytest.mark.parametrize("raise_server_exceptions", [True, False])
def test_streaming_response_late_server_exception(
    test_client_factory: TestClientFactory, raise_server_exceptions: bool
) -> None:
    async def http_app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"body"})
        await anyio.sleep(0)
        raise RuntimeError("late failure")

    client = test_client_factory(
        Starlette(routes=[Mount("/", app=http_app)]),
        raise_server_exceptions=raise_server_exceptions,
    )
    expected = pytest.raises(RuntimeError, match="late failure") if raise_server_exceptions else nullcontext()
    with client, expected:
        with client.stream("GET", "/") as response:
            assert response.read() == b"body"


@pytest.mark.parametrize("anyio_backend", ["asyncio"])
@pytest.mark.parametrize("response_started", [True, False])
@pytest.mark.parametrize("raise_server_exceptions", [True, False])
def test_cancelled_application_respects_raise_server_exceptions(
    test_client_factory: TestClientFactory, response_started: bool, raise_server_exceptions: bool
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if response_started:
            await Response(b"hello")(scope, receive, send)
        raise AsyncioCancelledError

    client = test_client_factory(app, raise_server_exceptions=raise_server_exceptions)
    if raise_server_exceptions:
        with pytest.raises(CancelledError):
            client.get("/")
    else:
        response = client.get("/")
        assert response.status_code == (200 if response_started else 500)
        assert response.content == (b"hello" if response_started else b"")


def test_streaming_response_copies_mutable_chunks(test_client_factory: TestClientFactory) -> None:
    async def chunks() -> AsyncGenerator[memoryview, None]:
        buffer = bytearray(b"one")
        yield memoryview(buffer)
        buffer[:] = b"two"
        yield memoryview(buffer)

    async def homepage(request: Request) -> StreamingResponse:
        return StreamingResponse(chunks())

    client = test_client_factory(Starlette(routes=[Route("/", homepage)]))
    with client.stream("GET", "/") as response:
        assert list(response.iter_raw()) == [b"one", b"two"]


def test_buffered_response_copies_mutable_chunks(test_client_factory: TestClientFactory) -> None:
    async def chunks() -> AsyncGenerator[memoryview, None]:
        buffer = bytearray(b"one")
        yield memoryview(buffer)
        buffer[:] = b"two"
        yield memoryview(buffer)

    async def homepage(request: Request) -> StreamingResponse:
        return StreamingResponse(chunks())

    client = test_client_factory(Starlette(routes=[Route("/", homepage)]))
    assert client.get("/").content == b"onetwo"


@pytest.mark.parametrize("lifespan", [True, False])
def test_interrupted_submission_keeps_client_usable(
    test_client_factory: TestClientFactory, monkeypatch: pytest.MonkeyPatch, lifespan: bool
) -> None:
    original_start_task_soon = BlockingPortal.start_task_soon

    def start_task_soon(
        portal: BlockingPortal, func: Callable[..., Any], *args: Any, name: object = None
    ) -> Future[Any]:
        if inspect.iscoroutinefunction(func):
            patch.undo()
            raise KeyboardInterrupt
        return original_start_task_soon(portal, func, *args, name=name)

    client = test_client_factory(mock_service)
    with client if lifespan else nullcontext():
        with monkeypatch.context() as patch:
            patch.setattr(BlockingPortal, "start_task_soon", start_task_soon)
            with pytest.raises(KeyboardInterrupt):
                client.get("/")
        assert client.get("/").json() == {"mock": "example"}


@pytest.mark.parametrize("lifespan", [True, False])
def test_interrupted_submission_stops_started_application(
    test_client_factory: TestClientFactory, monkeypatch: pytest.MonkeyPatch, lifespan: bool
) -> None:
    started = threading.Event()
    finished = threading.Event()
    app_timeout: anyio.CancelScope
    original_start_task_soon = BlockingPortal.start_task_soon

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal app_timeout
        with anyio.move_on_after(10) as app_timeout:
            try:
                started.set()
                await anyio.sleep_forever()
            finally:
                finished.set()

    def start_task_soon(
        portal: BlockingPortal, func: Callable[..., Any], *args: Any, name: object = None
    ) -> Future[Any]:
        future = original_start_task_soon(portal, func, *args, name=name)
        if inspect.iscoroutinefunction(func):
            patch.undo()
            assert started.wait(timeout=10)
            raise KeyboardInterrupt
        return future

    client = test_client_factory(Starlette(routes=[Route("/ready", mock_service_endpoint), Mount("/", app=app)]))
    with client if lifespan else nullcontext():
        with monkeypatch.context() as patch:
            patch.setattr(BlockingPortal, "start_task_soon", start_task_soon)
            with pytest.raises(KeyboardInterrupt):
                client.get("/")
        assert finished.is_set()
        assert not app_timeout.cancel_called
        assert client.get("/ready").json() == {"mock": "example"}


@pytest.mark.parametrize("lifespan", [True, False])
def test_interrupted_request_preserves_interrupt_on_cleanup_error(
    test_client_factory: TestClientFactory, monkeypatch: pytest.MonkeyPatch, lifespan: bool
) -> None:
    started = threading.Event()
    finished = threading.Event()
    app_timeout: anyio.CancelScope
    original_call = BlockingPortal.call

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal app_timeout
        if scope["type"] == "lifespan":
            await mock_service(scope, receive, send)
            return
        with anyio.move_on_after(10) as app_timeout:
            try:
                started.set()
                await anyio.sleep_forever()
            finally:
                finished.set()
                raise RuntimeError("cleanup failure")

    def call(portal: BlockingPortal, func: Callable[..., Any], *args: Any) -> Any:
        if inspect.ismethod(func) and isinstance(func.__self__, anyio.Event):
            patch.undo()
            assert started.wait(timeout=10)
            raise KeyboardInterrupt
        return original_call(portal, func, *args)

    client = test_client_factory(app)
    with client if lifespan else nullcontext():
        with monkeypatch.context() as patch:
            patch.setattr(BlockingPortal, "call", call)
            with pytest.raises(KeyboardInterrupt):
                client.get("/")
        assert finished.is_set()
        assert not app_timeout.cancel_called


def test_debug_info_in_response_extensions(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.debug", "info": {"fragment": "header", "blocks": ["nav", "title"]}})
        await send({"type": "http.response.body", "body": b"Hello, world!"})

    client = test_client_factory(app)
    response = client.get("/")
    assert response.extensions["http.response.debug"] == {"fragment": "header", "blocks": ["nav", "title"]}
    assert not hasattr(response, "template")


def test_debug_info_in_response_extensions_with_template(test_client_factory: TestClientFactory) -> None:
    info = {"template": "index.html", "context": {"name": "world"}, "blocks": ["nav"]}

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"text/plain"]],
            }
        )
        await send({"type": "http.response.debug", "info": info})
        await send({"type": "http.response.body", "body": b"Hello, world!"})

    client = test_client_factory(app)
    response = client.get("/")
    assert response.extensions["http.response.debug"] == info
    assert response.template == "index.html"  # type: ignore[attr-defined]
    assert response.context == {"name": "world"}  # type: ignore[attr-defined]


def test_websocket_blocking_receive(test_client_factory: TestClientFactory) -> None:
    def app(scope: Scope) -> ASGIInstance:
        async def respond(websocket: WebSocket) -> None:
            await websocket.send_json({"message": "test"})

        async def asgi(receive: Receive, send: Send) -> None:
            websocket = WebSocket(scope, receive=receive, send=send)
            await websocket.accept()
            async with anyio.create_task_group() as task_group:
                task_group.start_soon(respond, websocket)
                try:
                    # this will block as the client does not send us data
                    # it should not prevent `respond` from executing though
                    await websocket.receive_json()
                except WebSocketDisconnect:
                    pass

        return asgi

    client = test_client_factory(app)  # type: ignore
    with client.websocket_connect("/") as websocket:
        data = websocket.receive_json()
        assert data == {"message": "test"}


def test_websocket_not_block_on_close(test_client_factory: TestClientFactory) -> None:
    cancelled = False

    def app(scope: Scope) -> ASGIInstance:
        async def asgi(receive: Receive, send: Send) -> None:
            nonlocal cancelled
            try:
                websocket = WebSocket(scope, receive=receive, send=send)
                await websocket.accept()
                await anyio.sleep_forever()
            except anyio.get_cancelled_exc_class():
                cancelled = True
                raise

        return asgi

    client = test_client_factory(app)  # type: ignore
    with client.websocket_connect("/"):
        ...
    assert cancelled


def test_client(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        client = scope.get("client")
        assert client is not None
        host, port = client
        response = JSONResponse({"host": host, "port": port})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.json() == {"host": "testclient", "port": 50000}


def test_client_custom_client(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        client = scope.get("client")
        assert client is not None
        host, port = client
        response = JSONResponse({"host": host, "port": port})
        await response(scope, receive, send)

    client = test_client_factory(app, client=("192.168.0.1", 3000))
    response = client.get("/")
    assert response.json() == {"host": "192.168.0.1", "port": 3000}


@pytest.mark.parametrize("param", ("2020-07-14T00:00:00+00:00", "España", "voilà"))
def test_query_params(test_client_factory: TestClientFactory, param: str) -> None:
    def homepage(request: Request) -> Response:
        return Response(request.query_params["param"])

    app = Starlette(routes=[Route("/", endpoint=homepage)])
    client = test_client_factory(app)
    response = client.get("/", params={"param": param})
    assert response.text == param


@pytest.mark.parametrize(
    "domain, ok",
    [
        ("testserver", True),
        ("testserver.local", True),
        ("localhost", False),
        ("example.com", False),
    ],
)
def test_domain_restricted_cookies(test_client_factory: TestClientFactory, domain: str, ok: bool) -> None:
    """
    Test that test client discards domain restricted cookies which do not match the
    base_url of the testclient (`http://testserver` by default).

    The domain `testserver.local` works because the Python http.cookiejar module derives
    the "effective domain" by appending `.local` to non-dotted request domains
    in accordance with RFC 2965.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("Hello, world!", media_type="text/plain")
        response.set_cookie(
            "mycookie",
            "myvalue",
            path="/",
            domain=domain,
        )
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    cookie_set = len(response.cookies) == 1
    assert cookie_set == ok


def test_forward_follow_redirects(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if "/ok" in scope["path"]:
            response = Response("ok")
        else:
            response = RedirectResponse("/ok")
        await response(scope, receive, send)

    client = test_client_factory(app, follow_redirects=True)
    response = client.get("/")
    assert response.status_code == 200


def test_forward_nofollow_redirects(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = RedirectResponse("/ok")
        await response(scope, receive, send)

    client = test_client_factory(app, follow_redirects=False)
    response = client.get("/")
    assert response.status_code == 307


def test_with_duplicate_headers(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> JSONResponse:
        return JSONResponse({"x-token": request.headers.getlist("x-token")})

    app = Starlette(routes=[Route("/", endpoint=homepage)])
    client = test_client_factory(app)
    response = client.get("/", headers=[("x-token", "foo"), ("x-token", "bar")])
    assert response.json() == {"x-token": ["foo", "bar"]}


def test_merge_url(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> Response:
        return Response(request.url.path)

    app = Starlette(routes=[Route("/api/v1/bar", endpoint=homepage)])
    client = test_client_factory(app, base_url="http://testserver/api/v1/")
    response = client.get("/bar")
    assert response.text == "/api/v1/bar"


def test_raw_path_with_querystring(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response(scope.get("raw_path"))
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/hello-world", params={"foo": "bar"})
    assert response.content == b"/hello-world"


@pytest.mark.parametrize(
    ("base_url", "server", "host"),
    [
        ("http://[::1]", ["::1", 80], "[::1]"),
        ("http://[::1]:8000", ["::1", 8000], "[::1]:8000"),
        ("http://[::1]:0", ["::1", 0], "[::1]:0"),
    ],
)
def test_ipv6_base_url(
    test_client_factory: TestClientFactory, base_url: str, server: list[str | int], host: str
) -> None:
    def homepage(request: Request) -> JSONResponse:
        return JSONResponse({"server": request.scope["server"], "host": request.headers["host"]})

    app = Starlette(routes=[Route("/", endpoint=homepage)])
    client = test_client_factory(app, base_url=base_url)
    response = client.get("/")
    assert response.json() == {"server": server, "host": host}


def test_websocket_raw_path_without_params(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        raw_path = scope.get("raw_path")
        assert raw_path is not None
        await websocket.send_bytes(raw_path)

    client = test_client_factory(app)
    with client.websocket_connect("/hello-world", params={"foo": "bar"}) as websocket:
        data = websocket.receive_bytes()
        assert data == b"/hello-world"


def test_timeout_deprecation() -> None:
    with pytest.warns(
        StarletteDeprecationWarning, match="You should not use the 'timeout' argument with the TestClient."
    ):
        client = TestClient(mock_service)
        client.get("/", timeout=1)


@pytest.mark.parametrize(
    "messages, error",
    [
        ([], "TestClient did not receive any response"),
        ([{"type": "http.response.trailers"}], "without declaring trailers"),
        (
            [{"type": "http.response.start", "status": 200, "trailers": True}, {"type": "http.response.trailers"}],
            "before body completed",
        ),
        (
            [
                {"type": "http.response.start", "status": 200, "trailers": True},
                {"type": "http.response.body"},
                {"type": "http.response.body"},
            ],
            "after body completed",
        ),
        (
            [
                {"type": "http.response.start", "status": 200, "trailers": True},
                {"type": "http.response.body"},
                {"type": "http.response.trailers"},
                {"type": "http.response.trailers"},
            ],
            "after response completed",
        ),
    ],
)
def test_invalid_trailer_sequence(test_client_factory: TestClientFactory, messages: list[Message], error: str) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        for message in messages:
            await send(message)

    with pytest.raises(AssertionError, match=error):
        test_client_factory(app).get("/")


@pytest.mark.parametrize("trailers", [[], [(b"x-item", b"one"), (b"x-item", b"two")]])
def test_capture_trailers(test_client_factory: TestClientFactory, trailers: list[tuple[bytes, bytes]]) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        assert "http.response.trailers" in scope["extensions"]
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        await anyio.lowlevel.checkpoint()
        await send({"type": "http.response.trailers", "headers": trailers[:1], "more_trailers": True})
        await send({"type": "http.response.trailers", "headers": trailers[1:]})

    client = test_client_factory(app)
    response = client.get("/", headers={"te": "trailers"})
    assert response.content == b"hello"
    assert response.extensions["http.response.trailers"] == trailers
    assert "x-item" not in response.headers


@pytest.mark.parametrize("trailers", [[], [(b"x-item", b"one"), (b"x-item", b"two")]])
def test_streaming_response_captures_trailers(
    test_client_factory: TestClientFactory, trailers: list[tuple[bytes, bytes]]
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        assert "http.response.trailers" in scope["extensions"]
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        await anyio.lowlevel.checkpoint()
        await send({"type": "http.response.trailers", "headers": trailers[:1], "more_trailers": True})
        await send({"type": "http.response.trailers", "headers": trailers[1:]})

    client = test_client_factory(app)
    with client.stream("GET", "/", headers={"te": "trailers"}) as response:
        assert response.extensions["http.response.trailers"] == []
        assert response.read() == b"hello"
    assert response.content == b"hello"
    assert response.extensions["http.response.trailers"] == trailers
    assert "x-item" not in response.headers


def test_closing_completed_trailers_waits_for_application(test_client_factory: TestClientFactory) -> None:
    trailers_sent = threading.Event()
    completed = threading.Event()

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        await send({"type": "http.response.trailers", "headers": [(b"x-item", b"one")]})
        trailers_sent.set()
        await anyio.sleep(0.1)
        completed.set()

    client = test_client_factory(app)
    with client.stream("GET", "/") as response:
        chunks = response.iter_raw()
        assert next(chunks) == b"hello"
        assert trailers_sent.wait(timeout=10)
        assert response.extensions["http.response.trailers"] == [(b"x-item", b"one")]
    assert completed.is_set()


@pytest.mark.parametrize("partial", [True, False])
def test_incomplete_trailers(test_client_factory: TestClientFactory, partial: bool) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        if partial:
            await send({"type": "http.response.trailers", "headers": [(b"x-item", b"partial")], "more_trailers": True})

    response = test_client_factory(app).get("/")
    assert response.content == b"hello"
    assert response.extensions["http.response.trailers"] == ([(b"x-item", b"partial")] if partial else [])


@pytest.mark.parametrize("raise_server_exceptions", [True, False])
def test_trailer_error_respects_raise_server_exceptions(
    test_client_factory: TestClientFactory, raise_server_exceptions: bool
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        await send({"type": "http.response.trailers", "headers": [(b"x-item", b"partial")], "more_trailers": True})
        raise ValueError("trailer production failed")

    client = test_client_factory(app, raise_server_exceptions=raise_server_exceptions)
    if raise_server_exceptions:
        with pytest.raises(ValueError, match="trailer production failed"):
            client.get("/")
    else:
        response = client.get("/")
        assert response.content == b"hello"
        assert response.extensions["http.response.trailers"] == [(b"x-item", b"partial")]
