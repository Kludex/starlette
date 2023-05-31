import itertools
import sys
from asyncio import current_task as asyncio_current_task
from contextlib import asynccontextmanager

import anyio
import pytest
import sniffio
import trio.lowlevel

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect


def mock_service_endpoint(request):
    return JSONResponse({"mock": "example"})


mock_service = Starlette(
    routes=[
        Route("/", endpoint=mock_service_endpoint),
    ]
)


def current_task():
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


def startup():
    raise RuntimeError()


def test_use_testclient_in_endpoint(test_client_factory):
    """
    We should be able to use the test client within applications.

    This is useful if we need to mock out other services,
    during tests or in development.
    """

    def homepage(request):
        client = test_client_factory(mock_service)
        response = client.get("/")
        return JSONResponse(response.json())

    app = Starlette(routes=[Route("/", endpoint=homepage)])

    client = test_client_factory(app)
    response = client.get("/")
    assert response.json() == {"mock": "example"}


def test_testclient_headers_behavior():
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


def test_use_testclient_as_contextmanager(test_client_factory, anyio_backend_name):
    """
    This test asserts a number of properties that are important for an
    app level task_group
    """
    counter = itertools.count()
    identity_runvar = anyio.lowlevel.RunVar[int]("identity_runvar")

    def get_identity():
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
    async def lifespan_context(app):
        nonlocal startup_task, startup_loop, shutdown_task, shutdown_loop

        startup_task = current_task()
        startup_loop = get_identity()
        async with anyio.create_task_group() as app.task_group:
            yield
        shutdown_task = current_task()
        shutdown_loop = get_identity()

    async def loop_id(request):
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
    # eventloops in new threads
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


def test_error_on_startup(test_client_factory):
    with pytest.deprecated_call(
        match="The on_startup and on_shutdown parameters are deprecated"
    ):
        startup_error_app = Starlette(on_startup=[startup])

    with pytest.raises(RuntimeError):
        with test_client_factory(startup_error_app):
            pass  # pragma: no cover


def test_exception_in_middleware(test_client_factory):
    class MiddlewareException(Exception):
        pass

    class BrokenMiddleware:
        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            raise MiddlewareException()

    broken_middleware = Starlette(middleware=[Middleware(BrokenMiddleware)])

    with pytest.raises(MiddlewareException):
        with test_client_factory(broken_middleware):
            pass  # pragma: no cover


def test_testclient_asgi2(test_client_factory):
    def app(scope):
        async def inner(receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [[b"content-type", b"text/plain"]],
                }
            )
            await send({"type": "http.response.body", "body": b"Hello, world!"})

        return inner

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "Hello, world!"


def test_testclient_asgi3(test_client_factory):
    async def app(scope, receive, send):
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


def test_websocket_blocking_receive(test_client_factory):
    def app(scope):
        async def respond(websocket):
            await websocket.send_json({"message": "test"})

        async def asgi(receive, send):
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

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        data = websocket.receive_json()
        assert data == {"message": "test"}


def test_client(test_client_factory):
    async def app(scope, receive, send):
        client = scope.get("client")
        assert client is not None
        host, port = client
        response = JSONResponse({"host": host, "port": port})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.json() == {"host": "testclient", "port": 50000}


@pytest.mark.parametrize("param", ("2020-07-14T00:00:00+00:00", "España", "voilà"))
def test_query_params(test_client_factory, param: str):
    def homepage(request):
        return Response(request.query_params["param"])

    app = Starlette(routes=[Route("/", endpoint=homepage)])
    client = test_client_factory(app)
    response = client.get("/", params={"param": param})
    assert response.text == param


@pytest.mark.parametrize(
    "domain, ok",
    [
        pytest.param(
            "testserver",
            True,
            marks=[
                pytest.mark.xfail(
                    sys.version_info < (3, 11),
                    reason="Fails due to domain handling in http.cookiejar module (see "
                    "#2152)",
                ),
            ],
        ),
        ("testserver.local", True),
        ("localhost", False),
        ("example.com", False),
    ],
)
def test_domain_restricted_cookies(test_client_factory, domain, ok):
    """
    Test that test client discards domain restricted cookies which do not match the
    base_url of the testclient (`http://testserver` by default).

    The domain `testserver.local` works because the Python http.cookiejar module derives
    the "effective domain" by appending `.local` to non-dotted request domains
    in accordance with RFC 2965.
    """

    async def app(scope, receive, send):
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
