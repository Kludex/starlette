import functools
import uuid

import pytest

from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Host, Mount, NoMatchFound, Route, Router, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect


def homepage(request):
    return Response("Hello, world", media_type="text/plain")


def users(request):
    return Response("All users", media_type="text/plain")


def user(request):
    content = "User " + request.path_params["username"]
    return Response(content, media_type="text/plain")


def user_me(request):
    content = "User fixed me"
    return Response(content, media_type="text/plain")


def user_no_match(request):  # pragma: no cover
    content = "User fixed no match"
    return Response(content, media_type="text/plain")


async def partial_endpoint(arg, request):
    return JSONResponse({"arg": arg})


async def partial_ws_endpoint(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_json({"url": str(websocket.url)})
    await websocket.close()


class PartialRoutes:
    @classmethod
    async def async_endpoint(cls, arg, request):
        return JSONResponse({"arg": arg})

    @classmethod
    async def async_ws_endpoint(cls, websocket: WebSocket):
        await websocket.accept()
        await websocket.send_json({"url": str(websocket.url)})
        await websocket.close()


app = Router(
    [
        Route("/", endpoint=homepage, methods=["GET"]),
        Mount(
            "/users",
            routes=[
                Route("/", endpoint=users),
                Route("/me", endpoint=user_me),
                Route("/{username}", endpoint=user),
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
    ]
)


@app.route("/func")
def func_homepage(request):
    return Response("Hello, world!", media_type="text/plain")


@app.route("/func", methods=["POST"])
def contact(request):
    return Response("Hello, POST!", media_type="text/plain")


@app.route("/int/{param:int}", name="int-convertor")
def int_convertor(request):
    number = request.path_params["param"]
    return JSONResponse({"int": number})


@app.route("/float/{param:float}", name="float-convertor")
def float_convertor(request):
    num = request.path_params["param"]
    return JSONResponse({"float": num})


@app.route("/path/{param:path}", name="path-convertor")
def path_convertor(request):
    path = request.path_params["param"]
    return JSONResponse({"path": path})


@app.route("/uuid/{param:uuid}", name="uuid-convertor")
def uuid_converter(request):
    uuid_param = request.path_params["param"]
    return JSONResponse({"uuid": str(uuid_param)})


# Route with chars that conflict with regex meta chars
@app.route("/path-with-parentheses({param:int})", name="path-with-parentheses")
def path_with_parentheses(request):
    number = request.path_params["param"]
    return JSONResponse({"int": number})


@app.websocket_route("/ws")
async def websocket_endpoint(session: WebSocket):
    await session.accept()
    await session.send_text("Hello, world!")
    await session.close()


@app.websocket_route("/ws/{room}")
async def websocket_params(session: WebSocket):
    await session.accept()
    await session.send_text(f"Hello, {session.path_params['room']}!")
    await session.close()


@pytest.fixture
def client(test_client_factory):
    with test_client_factory(app) as client:
        yield client


@pytest.mark.filterwarnings(
    r"ignore"
    r":Trying to detect encoding from a tiny portion of \(5\) byte\(s\)\."
    r":UserWarning"
    r":charset_normalizer.api"
)
def test_router(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, world"

    response = client.post("/")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"

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

    response = client.get("/users/nomatch")
    assert response.status_code == 200
    assert response.text == "User nomatch"

    response = client.get("/static/123")
    assert response.status_code == 200
    assert response.text == "xxxxx"


def test_route_converters(client):
    # Test integer conversion
    response = client.get("/int/5")
    assert response.status_code == 200
    assert response.json() == {"int": 5}
    assert app.url_path_for("int-convertor", param=5) == "/int/5"

    # Test path with parentheses
    response = client.get("/path-with-parentheses(7)")
    assert response.status_code == 200
    assert response.json() == {"int": 7}
    assert (
        app.url_path_for("path-with-parentheses", param=7)
        == "/path-with-parentheses(7)"
    )

    # Test float conversion
    response = client.get("/float/25.5")
    assert response.status_code == 200
    assert response.json() == {"float": 25.5}
    assert app.url_path_for("float-convertor", param=25.5) == "/float/25.5"

    # Test path conversion
    response = client.get("/path/some/example")
    assert response.status_code == 200
    assert response.json() == {"path": "some/example"}
    assert (
        app.url_path_for("path-convertor", param="some/example") == "/path/some/example"
    )

    # Test UUID conversion
    response = client.get("/uuid/ec38df32-ceda-4cfa-9b4a-1aeb94ad551a")
    assert response.status_code == 200
    assert response.json() == {"uuid": "ec38df32-ceda-4cfa-9b4a-1aeb94ad551a"}
    assert (
        app.url_path_for(
            "uuid-convertor", param=uuid.UUID("ec38df32-ceda-4cfa-9b4a-1aeb94ad551a")
        )
        == "/uuid/ec38df32-ceda-4cfa-9b4a-1aeb94ad551a"
    )


def test_url_path_for():
    assert app.url_path_for("homepage") == "/"
    assert app.url_path_for("user", username="tomchristie") == "/users/tomchristie"
    assert app.url_path_for("websocket_endpoint") == "/ws"
    with pytest.raises(NoMatchFound):
        assert app.url_path_for("broken")
    with pytest.raises(AssertionError):
        app.url_path_for("user", username="tom/christie")
    with pytest.raises(AssertionError):
        app.url_path_for("user", username="")


def test_url_for():
    assert (
        app.url_path_for("homepage").make_absolute_url(base_url="https://example.org")
        == "https://example.org/"
    )
    assert (
        app.url_path_for("homepage").make_absolute_url(
            base_url="https://example.org/root_path/"
        )
        == "https://example.org/root_path/"
    )
    assert (
        app.url_path_for("user", username="tomchristie").make_absolute_url(
            base_url="https://example.org"
        )
        == "https://example.org/users/tomchristie"
    )
    assert (
        app.url_path_for("user", username="tomchristie").make_absolute_url(
            base_url="https://example.org/root_path/"
        )
        == "https://example.org/root_path/users/tomchristie"
    )
    assert (
        app.url_path_for("websocket_endpoint").make_absolute_url(
            base_url="https://example.org"
        )
        == "wss://example.org/ws"
    )


def test_router_add_route(client):
    response = client.get("/func")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_router_duplicate_path(client):
    response = client.post("/func")
    assert response.status_code == 200
    assert response.text == "Hello, POST!"


def test_router_add_websocket_route(client):
    with client.websocket_connect("/ws") as session:
        text = session.receive_text()
        assert text == "Hello, world!"

    with client.websocket_connect("/ws/test") as session:
        text = session.receive_text()
        assert text == "Hello, test!"


def http_endpoint(request):
    url = request.url_for("http_endpoint")
    return Response(f"URL: {url}", media_type="text/plain")


class WebSocketEndpoint:
    async def __call__(self, scope, receive, send):
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


def test_protocol_switch(test_client_factory):
    client = test_client_factory(mixed_protocol_app)

    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "URL: http://testserver/"

    with client.websocket_connect("/") as session:
        assert session.receive_json() == {"URL": "ws://testserver/"}

    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/404"):
            pass  # pragma: nocover


ok = PlainTextResponse("OK")


def test_mount_urls(test_client_factory):
    mounted = Router([Mount("/users", ok, name="users")])
    client = test_client_factory(mounted)
    assert client.get("/users").status_code == 200
    assert client.get("/users").url == "http://testserver/users/"
    assert client.get("/users/").status_code == 200
    assert client.get("/users/a").status_code == 200
    assert client.get("/usersa").status_code == 404


def test_reverse_mount_urls():
    mounted = Router([Mount("/users", ok, name="users")])
    assert mounted.url_path_for("users", path="/a") == "/users/a"

    users = Router([Route("/{username}", ok, name="user")])
    mounted = Router([Mount("/{subpath}/users", users, name="users")])
    assert (
        mounted.url_path_for("users:user", subpath="test", username="tom")
        == "/test/users/tom"
    )
    assert (
        mounted.url_path_for("users", subpath="test", path="/tom") == "/test/users/tom"
    )


def test_mount_at_root(test_client_factory):
    mounted = Router([Mount("/", ok, name="users")])
    client = test_client_factory(mounted)
    assert client.get("/").status_code == 200


def users_api(request):
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


def test_host_routing(test_client_factory):
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

    client = test_client_factory(mixed_hosts_app, base_url="https://port.example.org/")

    response = client.get("/users")
    assert response.status_code == 404

    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(
        mixed_hosts_app, base_url="https://port.example.org:5600/"
    )

    response = client.get("/")
    assert response.status_code == 200


def test_host_reverse_urls():
    assert (
        mixed_hosts_app.url_path_for("homepage").make_absolute_url("https://whatever")
        == "https://www.example.org/"
    )
    assert (
        mixed_hosts_app.url_path_for("users").make_absolute_url("https://whatever")
        == "https://www.example.org/users"
    )
    assert (
        mixed_hosts_app.url_path_for("api:users").make_absolute_url("https://whatever")
        == "https://api.example.org/users"
    )
    assert (
        mixed_hosts_app.url_path_for("port:homepage").make_absolute_url(
            "https://whatever"
        )
        == "https://port.example.org:3600/"
    )


async def subdomain_app(scope, receive, send):
    response = JSONResponse({"subdomain": scope["path_params"]["subdomain"]})
    await response(scope, receive, send)


subdomain_router = Router(
    routes=[Host("{subdomain}.example.org", app=subdomain_app, name="subdomains")]
)


def test_subdomain_routing(test_client_factory):
    client = test_client_factory(subdomain_router, base_url="https://foo.example.org/")

    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"subdomain": "foo"}


def test_subdomain_reverse_urls():
    assert (
        subdomain_router.url_path_for(
            "subdomains", subdomain="foo", path="/homepage"
        ).make_absolute_url("https://whatever")
        == "https://foo.example.org/homepage"
    )


async def echo_urls(request):
    return JSONResponse(
        {
            "index": request.url_for("index"),
            "submount": request.url_for("mount:submount"),
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


def test_url_for_with_root_path(test_client_factory):
    app = Starlette(routes=echo_url_routes)
    client = test_client_factory(
        app, base_url="https://www.example.org/", root_path="/sub_path"
    )
    response = client.get("/")
    assert response.json() == {
        "index": "https://www.example.org/sub_path/",
        "submount": "https://www.example.org/sub_path/submount/",
    }
    response = client.get("/submount/")
    assert response.json() == {
        "index": "https://www.example.org/sub_path/",
        "submount": "https://www.example.org/sub_path/submount/",
    }


async def stub_app(scope, receive, send):
    pass  # pragma: no cover


double_mount_routes = [
    Mount("/mount", name="mount", routes=[Mount("/static", stub_app, name="static")]),
]


def test_url_for_with_double_mount():
    app = Starlette(routes=double_mount_routes)
    url = app.url_path_for("mount:static", path="123")
    assert url == "/mount/static/123"


def test_standalone_route_matches(test_client_factory):
    app = Route("/", PlainTextResponse("Hello, World!"))
    client = test_client_factory(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, World!"


def test_standalone_route_does_not_match(test_client_factory):
    app = Route("/", PlainTextResponse("Hello, World!"))
    client = test_client_factory(app)
    response = client.get("/invalid")
    assert response.status_code == 404
    assert response.text == "Not Found"


async def ws_helloworld(websocket):
    await websocket.accept()
    await websocket.send_text("Hello, world!")
    await websocket.close()


def test_standalone_ws_route_matches(test_client_factory):
    app = WebSocketRoute("/", ws_helloworld)
    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        text = websocket.receive_text()
        assert text == "Hello, world!"


def test_standalone_ws_route_does_not_match(test_client_factory):
    app = WebSocketRoute("/", ws_helloworld)
    client = test_client_factory(app)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/invalid"):
            pass  # pragma: nocover


def test_lifespan_async(test_client_factory):
    startup_complete = False
    shutdown_complete = False

    async def hello_world(request):
        return PlainTextResponse("hello, world")

    async def run_startup():
        nonlocal startup_complete
        startup_complete = True

    async def run_shutdown():
        nonlocal shutdown_complete
        shutdown_complete = True

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


def test_lifespan_sync(test_client_factory):
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
    with test_client_factory(app) as client:
        assert startup_complete
        assert not shutdown_complete
        client.get("/")
    assert startup_complete
    assert shutdown_complete


def test_raise_on_startup(test_client_factory):
    def run_startup():
        raise RuntimeError()

    router = Router(on_startup=[run_startup])
    startup_failed = False

    async def app(scope, receive, send):
        async def _send(message):
            nonlocal startup_failed
            if message["type"] == "lifespan.startup.failed":
                startup_failed = True
            return await send(message)

        await router(scope, receive, _send)

    with pytest.raises(RuntimeError):
        with test_client_factory(app):
            pass  # pragma: nocover
    assert startup_failed


def test_raise_on_shutdown(test_client_factory):
    def run_shutdown():
        raise RuntimeError()

    app = Router(on_shutdown=[run_shutdown])

    with pytest.raises(RuntimeError):
        with test_client_factory(app):
            pass  # pragma: nocover


def test_partial_async_endpoint(test_client_factory):
    test_client = test_client_factory(app)
    response = test_client.get("/partial")
    assert response.status_code == 200
    assert response.json() == {"arg": "foo"}

    cls_method_response = test_client.get("/partial/cls")
    assert cls_method_response.status_code == 200
    assert cls_method_response.json() == {"arg": "foo"}


def test_partial_async_ws_endpoint(test_client_factory):
    test_client = test_client_factory(app)
    with test_client.websocket_connect("/partial/ws") as websocket:
        data = websocket.receive_json()
        assert data == {"url": "ws://testserver/partial/ws"}

    with test_client.websocket_connect("/partial/ws/cls") as websocket:
        data = websocket.receive_json()
        assert data == {"url": "ws://testserver/partial/ws/cls"}


def test_duplicated_param_names():
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
