from __future__ import annotations

import contextlib
import functools
import json
import typing
import uuid

import pytest

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Host, Mount, NoMatchFound, Route, Router, WebSocketRoute
from starlette.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect
from tests.types import TestClientFactory


def homepage(request: Request) -> Response:
    return Response("Hello, world", media_type="text/plain")


def users(request: Request) -> Response:
    return Response("All users", media_type="text/plain")


def user(request: Request) -> Response:
    content = "User " + request.path_params["username"]
    return Response(content, media_type="text/plain")


def user_me(request: Request) -> Response:
    content = "User fixed me"
    return Response(content, media_type="text/plain")


def disable_user(request: Request) -> Response:
    content = "User " + request.path_params["username"] + " disabled"
    return Response(content, media_type="text/plain")


def user_no_match(request: Request) -> Response:  # pragma: no cover
    content = "User fixed no match"
    return Response(content, media_type="text/plain")


async def partial_endpoint(arg: str, request: Request) -> JSONResponse:
    return JSONResponse({"arg": arg})


async def partial_ws_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    await websocket.send_json({"url": str(websocket.url)})
    await websocket.close()


class PartialRoutes:
    @classmethod
    async def async_endpoint(cls, arg: str, request: Request) -> JSONResponse:
        return JSONResponse({"arg": arg})

    @classmethod
    async def async_ws_endpoint(cls, websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_json({"url": str(websocket.url)})
        await websocket.close()


def func_homepage(request: Request) -> Response:
    return Response("Hello, world!", media_type="text/plain")


def contact(request: Request) -> Response:
    return Response("Hello, POST!", media_type="text/plain")


def int_convertor(request: Request) -> JSONResponse:
    number = request.path_params["param"]
    return JSONResponse({"int": number})


def float_convertor(request: Request) -> JSONResponse:
    num = request.path_params["param"]
    return JSONResponse({"float": num})


def path_convertor(request: Request) -> JSONResponse:
    path = request.path_params["param"]
    return JSONResponse({"path": path})


def uuid_converter(request: Request) -> JSONResponse:
    uuid_param = request.path_params["param"]
    return JSONResponse({"uuid": str(uuid_param)})


def path_with_parentheses(request: Request) -> JSONResponse:
    number = request.path_params["param"]
    return JSONResponse({"int": number})


async def websocket_endpoint(session: WebSocket) -> None:
    await session.accept()
    await session.send_text("Hello, world!")
    await session.close()


async def websocket_params(session: WebSocket) -> None:
    await session.accept()
    await session.send_text(f"Hello, {session.path_params['room']}!")
    await session.close()


app = Router(
    [
        Route("/", endpoint=homepage, methods=["GET"]),
        Mount(
            "/users",
            routes=[
                Route("/", endpoint=users),
                Route("/me", endpoint=user_me),
                Route("/{username}", endpoint=user),
                Route("/{username}:disable", endpoint=disable_user, methods=["PUT"]),
                Route("/nomatch", endpoint=user_no_match),
            ],
        ),
        Mount(
            "/partial",
            routes=[
                Route("/", endpoint=functools.partial(partial_endpoint, "foo")),
                Route(
                    "/cls",
                    endpoint=functools.partial(PartialRoutes.async_endpoint, "foo"),
                ),
                WebSocketRoute("/ws", endpoint=functools.partial(partial_ws_endpoint)),
                WebSocketRoute(
                    "/ws/cls",
                    endpoint=functools.partial(PartialRoutes.async_ws_endpoint),
                ),
            ],
        ),
        Mount("/static", app=Response("xxxxx", media_type="image/png")),
        Route("/func", endpoint=func_homepage, methods=["GET"]),
        Route("/func", endpoint=contact, methods=["POST"]),
        Route("/int/{param:int}", endpoint=int_convertor, name="int-convertor"),
        Route("/float/{param:float}", endpoint=float_convertor, name="float-convertor"),
        Route("/path/{param:path}", endpoint=path_convertor, name="path-convertor"),
        Route("/uuid/{param:uuid}", endpoint=uuid_converter, name="uuid-convertor"),
        # Route with chars that conflict with regex meta chars
        Route(
            "/path-with-parentheses({param:int})",
            endpoint=path_with_parentheses,
            name="path-with-parentheses",
        ),
        WebSocketRoute("/ws", endpoint=websocket_endpoint),
        WebSocketRoute("/ws/{room}", endpoint=websocket_params),
    ]
)


@pytest.fixture
def client(
    test_client_factory: TestClientFactory,
) -> typing.Generator[TestClient, None, None]:
    with test_client_factory(app) as client:
        yield client


@pytest.mark.filterwarnings(
    r"ignore"
    r":Trying to detect encoding from a tiny portion of \(5\) byte\(s\)\."
    r":UserWarning"
    r":charset_normalizer.api"
)
def test_router(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, world"

    response = client.post("/")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"
    assert set(response.headers["allow"].split(", ")) == {"HEAD", "GET"}

    response = client.get("/foo")
    assert response.status_code == 404
    assert response.text == "Not Found"

    response = client.get("/users")
    assert response.status_code == 200
    assert response.text == "All users"

    response = client.get("/users/tomchristie")
    assert response.status_code == 200
    assert response.text == "User tomchristie"

    response = client.get("/users/me")
    assert response.status_code == 200
    assert response.text == "User fixed me"

    response = client.get("/users/tomchristie/")
    assert response.status_code == 200
    assert response.url == "http://testserver/users/tomchristie"
    assert response.text == "User tomchristie"

    response = client.put("/users/tomchristie:disable")
    assert response.status_code == 200
    assert response.url == "http://testserver/users/tomchristie:disable"
    assert response.text == "User tomchristie disabled"

    response = client.get("/users/nomatch")
    assert response.status_code == 200
    assert response.text == "User nomatch"

    response = client.get("/static/123")
    assert response.status_code == 200
    assert response.text == "xxxxx"


def test_route_converters(client: TestClient) -> None:
    # Test integer conversion
    response = client.get("/int/5")
    assert response.status_code == 200
    assert response.json() == {"int": 5}
    assert app.url_path_for("int-convertor", param=5) == "/int/5"

    # Test path with parentheses
    response = client.get("/path-with-parentheses(7)")
    assert response.status_code == 200
    assert response.json() == {"int": 7}
    assert app.url_path_for("path-with-parentheses", param=7) == "/path-with-parentheses(7)"

    # Test float conversion
    response = client.get("/float/25.5")
    assert response.status_code == 200
    assert response.json() == {"float": 25.5}
    assert app.url_path_for("float-convertor", param=25.5) == "/float/25.5"

    # Test path conversion
    response = client.get("/path/some/example")
    assert response.status_code == 200
    assert response.json() == {"path": "some/example"}
    assert app.url_path_for("path-convertor", param="some/example") == "/path/some/example"

    # Test UUID conversion
    response = client.get("/uuid/ec38df32-ceda-4cfa-9b4a-1aeb94ad551a")
    assert response.status_code == 200
    assert response.json() == {"uuid": "ec38df32-ceda-4cfa-9b4a-1aeb94ad551a"}
    assert (
        app.url_path_for("uuid-convertor", param=uuid.UUID("ec38df32-ceda-4cfa-9b4a-1aeb94ad551a"))
        == "/uuid/ec38df32-ceda-4cfa-9b4a-1aeb94ad551a"
    )


def test_url_path_for() -> None:
    assert app.url_path_for("homepage") == "/"
    assert app.url_path_for("user", username="tomchristie") == "/users/tomchristie"
    assert app.url_path_for("websocket_endpoint") == "/ws"
    with pytest.raises(NoMatchFound, match='No route exists for name "broken" and params "".'):
        assert app.url_path_for("broken")
    with pytest.raises(NoMatchFound, match='No route exists for name "broken" and params "key, key2".'):
        assert app.url_path_for("broken", key="value", key2="value2")
    with pytest.raises(AssertionError):
        app.url_path_for("user", username="tom/christie")
    with pytest.raises(AssertionError):
        app.url_path_for("user", username="")


def test_url_for() -> None:
    assert app.url_path_for("homepage").make_absolute_url(base_url="https://example.org") == "https://example.org/"
    assert (
        app.url_path_for("homepage").make_absolute_url(base_url="https://example.org/root_path/")
        == "https://example.org/root_path/"
    )
    assert (
        app.url_path_for("user", username="tomchristie").make_absolute_url(base_url="https://example.org")
        == "https://example.org/users/tomchristie"
    )
    assert (
        app.url_path_for("user", username="tomchristie").make_absolute_url(base_url="https://example.org/root_path/")
        == "https://example.org/root_path/users/tomchristie"
    )
    assert (
        app.url_path_for("websocket_endpoint").make_absolute_url(base_url="https://example.org")
        == "wss://example.org/ws"
    )


def test_router_add_route(client: TestClient) -> None:
    response = client.get("/func")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_router_duplicate_path(client: TestClient) -> None:
    response = client.post("/func")
    assert response.status_code == 200
    assert response.text == "Hello, POST!"


def test_router_add_websocket_route(client: TestClient) -> None:
    with client.websocket_connect("/ws") as session:
        text = session.receive_text()
        assert text == "Hello, world!"

    with client.websocket_connect("/ws/test") as session:
        text = session.receive_text()
        assert text == "Hello, test!"


def test_router_middleware(test_client_factory: TestClientFactory) -> None:
    class CustomMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            response = PlainTextResponse("OK")
            await response(scope, receive, send)

    app = Router(
        routes=[Route("/", homepage)],
        middleware=[Middleware(CustomMiddleware)],
    )

    client = test_client_factory(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "OK"


def http_endpoint(request: Request) -> Response:
    url = request.url_for("http_endpoint")
    return Response(f"URL: {url}", media_type="text/plain")


class WebSocketEndpoint:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope=scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.send_json({"URL": str(websocket.url_for("websocket_endpoint"))})
        await websocket.close()


mixed_protocol_app = Router(
    routes=[
        Route("/", endpoint=http_endpoint),
        WebSocketRoute("/", endpoint=WebSocketEndpoint(), name="websocket_endpoint"),
    ]
)


def test_protocol_switch(test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(mixed_protocol_app)

    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "URL: http://testserver/"

    with client.websocket_connect("/") as session:
        assert session.receive_json() == {"URL": "ws://testserver/"}

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/404"):
            pass  # pragma: no cover


ok = PlainTextResponse("OK")


def test_mount_urls(test_client_factory: TestClientFactory) -> None:
    mounted = Router([Mount("/users", ok, name="users")])
    client = test_client_factory(mounted)
    assert client.get("/users").status_code == 200
    assert client.get("/users").url == "http://testserver/users/"
    assert client.get("/users/").status_code == 200
    assert client.get("/users/a").status_code == 200
    assert client.get("/usersa").status_code == 404


def test_reverse_mount_urls() -> None:
    mounted = Router([Mount("/users", ok, name="users")])
    assert mounted.url_path_for("users", path="/a") == "/users/a"

    users = Router([Route("/{username}", ok, name="user")])
    mounted = Router([Mount("/{subpath}/users", users, name="users")])
    assert mounted.url_path_for("users:user", subpath="test", username="tom") == "/test/users/tom"
    assert mounted.url_path_for("users", subpath="test", path="/tom") == "/test/users/tom"

    mounted = Router([Mount("/users", ok, name="users")])
    with pytest.raises(NoMatchFound):
        mounted.url_path_for("users", path="/a", foo="bar")

    mounted = Router([Mount("/users", ok, name="users")])
    with pytest.raises(NoMatchFound):
        mounted.url_path_for("users")


def test_mount_at_root(test_client_factory: TestClientFactory) -> None:
    mounted = Router([Mount("/", ok, name="users")])
    client = test_client_factory(mounted)
    assert client.get("/").status_code == 200


def users_api(request: Request) -> JSONResponse:
    return JSONResponse({"users": [{"username": "tom"}]})


mixed_hosts_app = Router(
    routes=[
        Host(
            "www.example.org",
            app=Router(
                [
                    Route("/", homepage, name="homepage"),
                    Route("/users", users, name="users"),
                ]
            ),
        ),
        Host(
            "api.example.org",
            name="api",
            app=Router([Route("/users", users_api, name="users")]),
        ),
        Host(
            "port.example.org:3600",
            name="port",
            app=Router([Route("/", homepage, name="homepage")]),
        ),
    ]
)


def test_host_routing(test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(mixed_hosts_app, base_url="https://api.example.org/")

    response = client.get("/users")
    assert response.status_code == 200
    assert response.json() == {"users": [{"username": "tom"}]}

    response = client.get("/")
    assert response.status_code == 404

    client = test_client_factory(mixed_hosts_app, base_url="https://www.example.org/")

    response = client.get("/users")
    assert response.status_code == 200
    assert response.text == "All users"

    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(mixed_hosts_app, base_url="https://port.example.org:3600/")

    response = client.get("/users")
    assert response.status_code == 404

    response = client.get("/")
    assert response.status_code == 200

    # Port in requested Host is irrelevant.

    client = test_client_factory(mixed_hosts_app, base_url="https://port.example.org/")

    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(mixed_hosts_app, base_url="https://port.example.org:5600/")

    response = client.get("/")
    assert response.status_code == 200


def test_host_reverse_urls() -> None:
    assert mixed_hosts_app.url_path_for("homepage").make_absolute_url("https://whatever") == "https://www.example.org/"
    assert (
        mixed_hosts_app.url_path_for("users").make_absolute_url("https://whatever") == "https://www.example.org/users"
    )
    assert (
        mixed_hosts_app.url_path_for("api:users").make_absolute_url("https://whatever")
        == "https://api.example.org/users"
    )
    assert (
        mixed_hosts_app.url_path_for("port:homepage").make_absolute_url("https://whatever")
        == "https://port.example.org:3600/"
    )
    with pytest.raises(NoMatchFound):
        mixed_hosts_app.url_path_for("api", path="whatever", foo="bar")


async def subdomain_app(scope: Scope, receive: Receive, send: Send) -> None:
    response = JSONResponse({"subdomain": scope["path_params"]["subdomain"]})
    await response(scope, receive, send)


subdomain_router = Router(routes=[Host("{subdomain}.example.org", app=subdomain_app, name="subdomains")])


def test_subdomain_routing(test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(subdomain_router, base_url="https://foo.example.org/")

    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"subdomain": "foo"}


def test_subdomain_reverse_urls() -> None:
    assert (
        subdomain_router.url_path_for("subdomains", subdomain="foo", path="/homepage").make_absolute_url(
            "https://whatever"
        )
        == "https://foo.example.org/homepage"
    )


async def echo_urls(request: Request) -> JSONResponse:
    return JSONResponse(
        {
            "index": str(request.url_for("index")),
            "submount": str(request.url_for("mount:submount")),
        }
    )


echo_url_routes = [
    Route("/", echo_urls, name="index", methods=["GET"]),
    Mount(
        "/submount",
        name="mount",
        routes=[Route("/", echo_urls, name="submount", methods=["GET"])],
    ),
]


def test_url_for_with_root_path(test_client_factory: TestClientFactory) -> None:
    app = Starlette(routes=echo_url_routes)
    client = test_client_factory(app, base_url="https://www.example.org/", root_path="/sub_path")
    response = client.get("/sub_path/")
    assert response.json() == {
        "index": "https://www.example.org/sub_path/",
        "submount": "https://www.example.org/sub_path/submount/",
    }
    response = client.get("/sub_path/submount/")
    assert response.json() == {
        "index": "https://www.example.org/sub_path/",
        "submount": "https://www.example.org/sub_path/submount/",
    }


async def stub_app(scope: Scope, receive: Receive, send: Send) -> None:
    pass  # pragma: no cover


double_mount_routes = [
    Mount("/mount", name="mount", routes=[Mount("/static", stub_app, name="static")]),
]


def test_url_for_with_double_mount() -> None:
    app = Starlette(routes=double_mount_routes)
    url = app.url_path_for("mount:static", path="123")
    assert url == "/mount/static/123"


def test_url_for_with_root_path_ending_with_slash(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> JSONResponse:
        return JSONResponse({"index": str(request.url_for("homepage"))})

    app = Starlette(routes=[Route("/", homepage, name="homepage")])
    client = test_client_factory(app, base_url="https://www.example.org/", root_path="/sub_path/")
    response = client.get("/sub_path/")
    assert response.json() == {"index": "https://www.example.org/sub_path/"}


def test_standalone_route_matches(
    test_client_factory: TestClientFactory,
) -> None:
    app = Route("/", PlainTextResponse("Hello, World!"))
    client = test_client_factory(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, World!"


def test_standalone_route_does_not_match(
    test_client_factory: typing.Callable[..., TestClient],
) -> None:
    app = Route("/", PlainTextResponse("Hello, World!"))
    client = test_client_factory(app)
    response = client.get("/invalid")
    assert response.status_code == 404
    assert response.text == "Not Found"


async def ws_helloworld(websocket: WebSocket) -> None:
    await websocket.accept()
    await websocket.send_text("Hello, world!")
    await websocket.close()


def test_standalone_ws_route_matches(
    test_client_factory: TestClientFactory,
) -> None:
    app = WebSocketRoute("/", ws_helloworld)
    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        text = websocket.receive_text()
        assert text == "Hello, world!"


def test_standalone_ws_route_does_not_match(
    test_client_factory: TestClientFactory,
) -> None:
    app = WebSocketRoute("/", ws_helloworld)
    client = test_client_factory(app)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/invalid"):
            pass  # pragma: no cover


def test_lifespan_async(test_client_factory: TestClientFactory) -> None:
    startup_complete = False
    shutdown_complete = False

    async def hello_world(request: Request) -> PlainTextResponse:
        return PlainTextResponse("hello, world")

    async def run_startup() -> None:
        nonlocal startup_complete
        startup_complete = True

    async def run_shutdown() -> None:
        nonlocal shutdown_complete
        shutdown_complete = True

    with pytest.deprecated_call(match="The on_startup and on_shutdown parameters are deprecated"):
        app = Router(
            on_startup=[run_startup],
            on_shutdown=[run_shutdown],
            routes=[Route("/", hello_world)],
        )

    assert not startup_complete
    assert not shutdown_complete
    with test_client_factory(app) as client:
        assert startup_complete
        assert not shutdown_complete
        client.get("/")
    assert startup_complete
    assert shutdown_complete


def test_lifespan_with_on_events(test_client_factory: TestClientFactory) -> None:
    lifespan_called = False
    startup_called = False
    shutdown_called = False

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> typing.AsyncGenerator[None, None]:
        nonlocal lifespan_called
        lifespan_called = True
        yield

    # We do not expected, neither of run_startup nor run_shutdown to be called
    # we thus mark them as #pragma: no cover, to fulfill test coverage
    def run_startup() -> None:  # pragma: no cover
        nonlocal startup_called
        startup_called = True

    def run_shutdown() -> None:  # pragma: no cover
        nonlocal shutdown_called
        shutdown_called = True

    with pytest.deprecated_call(match="The on_startup and on_shutdown parameters are deprecated"):
        with pytest.warns(
            UserWarning, match="The `lifespan` parameter cannot be used with `on_startup` or `on_shutdown`."
        ):
            app = Router(on_startup=[run_startup], on_shutdown=[run_shutdown], lifespan=lifespan)

            assert not lifespan_called
            assert not startup_called
            assert not shutdown_called

            # Triggers the lifespan events
            with test_client_factory(app):
                ...

            assert lifespan_called
            assert not startup_called
            assert not shutdown_called


def test_lifespan_sync(test_client_factory: TestClientFactory) -> None:
    startup_complete = False
    shutdown_complete = False

    def hello_world(request: Request) -> PlainTextResponse:
        return PlainTextResponse("hello, world")

    def run_startup() -> None:
        nonlocal startup_complete
        startup_complete = True

    def run_shutdown() -> None:
        nonlocal shutdown_complete
        shutdown_complete = True

    with pytest.deprecated_call(match="The on_startup and on_shutdown parameters are deprecated"):
        app = Router(
            on_startup=[run_startup],
            on_shutdown=[run_shutdown],
            routes=[Route("/", hello_world)],
        )

    assert not startup_complete
    assert not shutdown_complete
    with test_client_factory(app) as client:
        assert startup_complete
        assert not shutdown_complete
        client.get("/")
    assert startup_complete
    assert shutdown_complete


def test_lifespan_state_unsupported(
    test_client_factory: TestClientFactory,
) -> None:
    @contextlib.asynccontextmanager
    async def lifespan(
        app: ASGIApp,
    ) -> typing.AsyncGenerator[dict[str, str], None]:
        yield {"foo": "bar"}

    app = Router(
        lifespan=lifespan,
        routes=[Mount("/", PlainTextResponse("hello, world"))],
    )

    async def no_state_wrapper(scope: Scope, receive: Receive, send: Send) -> None:
        del scope["state"]
        await app(scope, receive, send)

    with pytest.raises(RuntimeError, match='The server does not support "state" in the lifespan scope'):
        with test_client_factory(no_state_wrapper):
            raise AssertionError("Should not be called")  # pragma: no cover


def test_lifespan_state_async_cm(test_client_factory: TestClientFactory) -> None:
    startup_complete = False
    shutdown_complete = False

    class State(typing.TypedDict):
        count: int
        items: list[int]

    async def hello_world(request: Request) -> Response:
        # modifications to the state should not leak across requests
        assert request.state.count == 0
        # modify the state, this should not leak to the lifespan or other requests
        request.state.count += 1
        # since state.items is a mutable object this modification _will_ leak across
        # requests and to the lifespan
        request.state.items.append(1)
        return PlainTextResponse("hello, world")

    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> typing.AsyncIterator[State]:
        nonlocal startup_complete, shutdown_complete
        startup_complete = True
        state = State(count=0, items=[])
        yield state
        shutdown_complete = True
        # modifications made to the state from a request do not leak to the lifespan
        assert state["count"] == 0
        # unless of course the request mutates a mutable object that is referenced
        # via state
        assert state["items"] == [1, 1]

    app = Router(
        lifespan=lifespan,
        routes=[Route("/", hello_world)],
    )

    assert not startup_complete
    assert not shutdown_complete
    with test_client_factory(app) as client:
        assert startup_complete
        assert not shutdown_complete
        client.get("/")
        # Calling it a second time to ensure that the state is preserved.
        client.get("/")
    assert startup_complete
    assert shutdown_complete


def test_raise_on_startup(test_client_factory: TestClientFactory) -> None:
    def run_startup() -> None:
        raise RuntimeError()

    with pytest.deprecated_call(match="The on_startup and on_shutdown parameters are deprecated"):
        router = Router(on_startup=[run_startup])
    startup_failed = False

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        async def _send(message: Message) -> None:
            nonlocal startup_failed
            if message["type"] == "lifespan.startup.failed":  # pragma: no branch
                startup_failed = True
            return await send(message)

        await router(scope, receive, _send)

    with pytest.raises(RuntimeError):
        with test_client_factory(app):
            pass  # pragma: no cover
    assert startup_failed


def test_raise_on_shutdown(test_client_factory: TestClientFactory) -> None:
    def run_shutdown() -> None:
        raise RuntimeError()

    with pytest.deprecated_call(match="The on_startup and on_shutdown parameters are deprecated"):
        app = Router(on_shutdown=[run_shutdown])

    with pytest.raises(RuntimeError):
        with test_client_factory(app):
            pass  # pragma: no cover


def test_partial_async_endpoint(test_client_factory: TestClientFactory) -> None:
    test_client = test_client_factory(app)
    response = test_client.get("/partial")
    assert response.status_code == 200
    assert response.json() == {"arg": "foo"}

    cls_method_response = test_client.get("/partial/cls")
    assert cls_method_response.status_code == 200
    assert cls_method_response.json() == {"arg": "foo"}


def test_partial_async_ws_endpoint(
    test_client_factory: TestClientFactory,
) -> None:
    test_client = test_client_factory(app)
    with test_client.websocket_connect("/partial/ws") as websocket:
        data = websocket.receive_json()
        assert data == {"url": "ws://testserver/partial/ws"}

    with test_client.websocket_connect("/partial/ws/cls") as websocket:
        data = websocket.receive_json()
        assert data == {"url": "ws://testserver/partial/ws/cls"}


def test_duplicated_param_names() -> None:
    with pytest.raises(
        ValueError,
        match="Duplicated param name id at path /{id}/{id}",
    ):
        Route("/{id}/{id}", user)

    with pytest.raises(
        ValueError,
        match="Duplicated param names id, name at path /{id}/{name}/{id}/{name}",
    ):
        Route("/{id}/{name}/{id}/{name}", user)


class Endpoint:
    async def my_method(self, request: Request) -> None: ...  # pragma: no cover

    @classmethod
    async def my_classmethod(cls, request: Request) -> None: ...  # pragma: no cover

    @staticmethod
    async def my_staticmethod(request: Request) -> None: ...  # pragma: no cover

    def __call__(self, request: Request) -> None: ...  # pragma: no cover


@pytest.mark.parametrize(
    "endpoint, expected_name",
    [
        pytest.param(func_homepage, "func_homepage", id="function"),
        pytest.param(Endpoint().my_method, "my_method", id="method"),
        pytest.param(Endpoint.my_classmethod, "my_classmethod", id="classmethod"),
        pytest.param(
            Endpoint.my_staticmethod,
            "my_staticmethod",
            id="staticmethod",
        ),
        pytest.param(Endpoint(), "Endpoint", id="object"),
        pytest.param(lambda request: ..., "<lambda>", id="lambda"),  # pragma: no branch
    ],
)
def test_route_name(endpoint: typing.Callable[..., Response], expected_name: str) -> None:
    assert Route(path="/", endpoint=endpoint).name == expected_name


class AddHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope["add_headers_middleware"] = True

        async def modified_send(msg: Message) -> None:
            if msg["type"] == "http.response.start":
                msg["headers"].append((b"X-Test", b"Set by middleware"))
            await send(msg)

        await self.app(scope, receive, modified_send)


def assert_middleware_header_route(request: Request) -> Response:
    assert request.scope["add_headers_middleware"] is True
    return Response()


route_with_middleware = Starlette(
    routes=[
        Route(
            "/http",
            endpoint=assert_middleware_header_route,
            methods=["GET"],
            middleware=[Middleware(AddHeadersMiddleware)],
        ),
        Route("/home", homepage),
    ]
)

mounted_routes_with_middleware = Starlette(
    routes=[
        Mount(
            "/http",
            routes=[
                Route(
                    "/",
                    endpoint=assert_middleware_header_route,
                    methods=["GET"],
                    name="route",
                ),
            ],
            middleware=[Middleware(AddHeadersMiddleware)],
        ),
        Route("/home", homepage),
    ]
)


mounted_app_with_middleware = Starlette(
    routes=[
        Mount(
            "/http",
            app=Route(
                "/",
                endpoint=assert_middleware_header_route,
                methods=["GET"],
                name="route",
            ),
            middleware=[Middleware(AddHeadersMiddleware)],
        ),
        Route("/home", homepage),
    ]
)


@pytest.mark.parametrize(
    "app",
    [
        mounted_routes_with_middleware,
        mounted_app_with_middleware,
        route_with_middleware,
    ],
)
def test_base_route_middleware(
    test_client_factory: TestClientFactory,
    app: Starlette,
) -> None:
    test_client = test_client_factory(app)

    response = test_client.get("/home")
    assert response.status_code == 200
    assert "X-Test" not in response.headers

    response = test_client.get("/http")
    assert response.status_code == 200
    assert response.headers["X-Test"] == "Set by middleware"


def test_mount_routes_with_middleware_url_path_for() -> None:
    """Checks that url_path_for still works with mounted routes with Middleware"""
    assert mounted_routes_with_middleware.url_path_for("route") == "/http/"


def test_mount_asgi_app_with_middleware_url_path_for() -> None:
    """Mounted ASGI apps do not work with url path for,
    middleware does not change this
    """
    with pytest.raises(NoMatchFound):
        mounted_app_with_middleware.url_path_for("route")


def test_add_route_to_app_after_mount(
    test_client_factory: typing.Callable[..., TestClient],
) -> None:
    """Checks that Mount will pick up routes
    added to the underlying app after it is mounted
    """
    inner_app = Router()
    app = Mount("/http", app=inner_app)
    inner_app.add_route(
        "/inner",
        endpoint=homepage,
        methods=["GET"],
    )
    client = test_client_factory(app)
    response = client.get("/http/inner")
    assert response.status_code == 200


def test_exception_on_mounted_apps(
    test_client_factory: TestClientFactory,
) -> None:
    def exc(request: Request) -> None:
        raise Exception("Exc")

    sub_app = Starlette(routes=[Route("/", exc)])
    app = Starlette(routes=[Mount("/sub", app=sub_app)])

    client = test_client_factory(app)
    with pytest.raises(Exception) as ctx:
        client.get("/sub/")
    assert str(ctx.value) == "Exc"


def test_mounted_middleware_does_not_catch_exception(
    test_client_factory: typing.Callable[..., TestClient],
) -> None:
    # https://github.com/encode/starlette/pull/1649#discussion_r960236107
    def exc(request: Request) -> Response:
        raise HTTPException(status_code=403, detail="auth")

    class NamedMiddleware:
        def __init__(self, app: ASGIApp, name: str) -> None:
            self.app = app
            self.name = name

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            async def modified_send(msg: Message) -> None:
                if msg["type"] == "http.response.start":
                    msg["headers"].append((f"X-{self.name}".encode(), b"true"))
                await send(msg)

            await self.app(scope, receive, modified_send)

    app = Starlette(
        routes=[
            Mount(
                "/mount",
                routes=[
                    Route("/err", exc),
                    Route("/home", homepage),
                ],
                middleware=[Middleware(NamedMiddleware, name="Mounted")],
            ),
            Route("/err", exc),
            Route("/home", homepage),
        ],
        middleware=[Middleware(NamedMiddleware, name="Outer")],
    )

    client = test_client_factory(app)

    resp = client.get("/home")
    assert resp.status_code == 200, resp.content
    assert "X-Outer" in resp.headers

    resp = client.get("/err")
    assert resp.status_code == 403, resp.content
    assert "X-Outer" in resp.headers

    resp = client.get("/mount/home")
    assert resp.status_code == 200, resp.content
    assert "X-Mounted" in resp.headers

    resp = client.get("/mount/err")
    assert resp.status_code == 403, resp.content
    assert "X-Mounted" in resp.headers


def test_websocket_route_middleware(
    test_client_factory: TestClientFactory,
) -> None:
    async def websocket_endpoint(session: WebSocket) -> None:
        await session.accept()
        await session.send_text("Hello, world!")
        await session.close()

    class WebsocketMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            async def modified_send(msg: Message) -> None:
                if msg["type"] == "websocket.accept":
                    msg["headers"].append((b"X-Test", b"Set by middleware"))
                await send(msg)

            await self.app(scope, receive, modified_send)

    app = Starlette(
        routes=[
            WebSocketRoute(
                "/ws",
                endpoint=websocket_endpoint,
                middleware=[Middleware(WebsocketMiddleware)],
            )
        ]
    )

    client = test_client_factory(app)

    with client.websocket_connect("/ws") as websocket:
        text = websocket.receive_text()
        assert text == "Hello, world!"
        assert websocket.extra_headers == [(b"X-Test", b"Set by middleware")]


def test_route_repr() -> None:
    route = Route("/welcome", endpoint=homepage)
    assert repr(route) == "Route(path='/welcome', name='homepage', methods=['GET', 'HEAD'])"


def test_route_repr_without_methods() -> None:
    route = Route("/welcome", endpoint=Endpoint, methods=None)
    assert repr(route) == "Route(path='/welcome', name='Endpoint', methods=[])"


def test_websocket_route_repr() -> None:
    route = WebSocketRoute("/ws", endpoint=websocket_endpoint)
    assert repr(route) == "WebSocketRoute(path='/ws', name='websocket_endpoint')"


def test_mount_repr() -> None:
    route = Mount(
        "/app",
        routes=[
            Route("/", endpoint=homepage),
        ],
    )
    # test for substring because repr(Router) returns unique object ID
    assert repr(route).startswith("Mount(path='/app', name='', app=")


def test_mount_named_repr() -> None:
    route = Mount(
        "/app",
        name="app",
        routes=[
            Route("/", endpoint=homepage),
        ],
    )
    # test for substring because repr(Router) returns unique object ID
    assert repr(route).startswith("Mount(path='/app', name='app', app=")


def test_host_repr() -> None:
    route = Host(
        "example.com",
        app=Router(
            [
                Route("/", endpoint=homepage),
            ]
        ),
    )
    # test for substring because repr(Router) returns unique object ID
    assert repr(route).startswith("Host(host='example.com', name='', app=")


def test_host_named_repr() -> None:
    route = Host(
        "example.com",
        name="app",
        app=Router(
            [
                Route("/", endpoint=homepage),
            ]
        ),
    )
    # test for substring because repr(Router) returns unique object ID
    assert repr(route).startswith("Host(host='example.com', name='app', app=")


def test_decorator_deprecations() -> None:
    router = Router()

    with pytest.deprecated_call():
        router.route("/")(homepage)

    with pytest.deprecated_call():
        router.websocket_route("/ws")(websocket_endpoint)

    with pytest.deprecated_call():

        async def startup() -> None: ...  # pragma: no cover

        router.on_event("startup")(startup)


async def echo_paths(request: Request, name: str) -> JSONResponse:
    return JSONResponse(
        {
            "name": name,
            "path": request.scope["path"],
            "root_path": request.scope["root_path"],
        }
    )


async def pure_asgi_echo_paths(scope: Scope, receive: Receive, send: Send, name: str) -> None:
    data = {"name": name, "path": scope["path"], "root_path": scope["root_path"]}
    content = json.dumps(data).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": content})


echo_paths_routes = [
    Route(
        "/path",
        functools.partial(echo_paths, name="path"),
        name="path",
        methods=["GET"],
    ),
    Route(
        "/root-queue/path",
        functools.partial(echo_paths, name="queue_path"),
        name="queue_path",
        methods=["POST"],
    ),
    Mount("/asgipath", app=functools.partial(pure_asgi_echo_paths, name="asgipath")),
    Mount(
        "/sub",
        name="mount",
        routes=[
            Route(
                "/path",
                functools.partial(echo_paths, name="subpath"),
                name="subpath",
                methods=["GET"],
            ),
        ],
    ),
]


def test_paths_with_root_path(test_client_factory: TestClientFactory) -> None:
    app = Starlette(routes=echo_paths_routes)
    client = test_client_factory(app, base_url="https://www.example.org/", root_path="/root")
    response = client.get("/root/path")
    assert response.status_code == 200
    assert response.json() == {
        "name": "path",
        "path": "/root/path",
        "root_path": "/root",
    }
    response = client.get("/root/asgipath/")
    assert response.status_code == 200
    assert response.json() == {
        "name": "asgipath",
        "path": "/root/asgipath/",
        # Things that mount other ASGI apps, like WSGIMiddleware, would not be aware
        # of the prefixed path, and would have their own notion of their own paths,
        # so they need to be able to rely on the root_path to know the location they
        # are mounted on
        "root_path": "/root/asgipath",
    }

    response = client.get("/root/sub/path")
    assert response.status_code == 200
    assert response.json() == {
        "name": "subpath",
        "path": "/root/sub/path",
        "root_path": "/root/sub",
    }

    response = client.post("/root/root-queue/path")
    assert response.status_code == 200
    assert response.json() == {
        "name": "queue_path",
        "path": "/root/root-queue/path",
        "root_path": "/root",
    }
