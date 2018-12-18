import pytest

from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, NoMatchFound, Route, Router, WebSocketRoute
from starlette.testclient import TestClient
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


def staticfiles(request):
    return Response("xxxxx", media_type="image/png")


app = Router(
    [
        Route("/", endpoint=homepage, methods=["GET"]),
        Mount(
            "/users",
            app=Router(
                [
                    Route("/", endpoint=users),
                    Route("/me", endpoint=user_me),
                    Route("/{username}", endpoint=user),
                    Route("/nomatch", endpoint=user_no_match),
                ]
            ),
        ),
        Mount("/static", app=staticfiles),
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


@app.websocket_route("/ws")
async def websocket_endpoint(session):
    await session.accept()
    await session.send_text("Hello, world!")
    await session.close()


@app.websocket_route("/ws/{room}")
async def websocket_params(session):
    await session.accept()
    await session.send_text("Hello, %s!" % session.path_params["room"])
    await session.close()


client = TestClient(app)


def test_router():
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

    response = client.get("/users/nomatch")
    assert response.status_code == 200
    assert response.text == "User nomatch"

    response = client.get("/static/123")
    assert response.status_code == 200
    assert response.text == "xxxxx"


def test_route_converters():
    # Test integer conversion
    response = client.get("/int/5")
    assert response.status_code == 200
    assert response.json() == {"int": 5}
    assert app.url_path_for("int-convertor", param=5) == "/int/5"

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
        app.url_path_for("user", username="tomchristie").make_absolute_url(
            base_url="https://example.org"
        )
        == "https://example.org/users/tomchristie"
    )
    assert (
        app.url_path_for("websocket_endpoint").make_absolute_url(
            base_url="https://example.org"
        )
        == "wss://example.org/ws"
    )


def test_router_add_route():
    response = client.get("/func")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_router_duplicate_path():
    response = client.post("/func")
    assert response.status_code == 200
    assert response.text == "Hello, POST!"


def test_router_add_websocket_route():
    with client.websocket_connect("/ws") as session:
        text = session.receive_text()
        assert text == "Hello, world!"

    with client.websocket_connect("/ws/test") as session:
        text = session.receive_text()
        assert text == "Hello, test!"


def http_endpoint(request):
    url = request.url_for("http_endpoint")
    return Response("URL: %s" % url, media_type="text/plain")


class WebsocketEndpoint:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        session = WebSocket(scope=self.scope, receive=receive, send=send)
        await session.accept()
        await session.send_json({"URL": str(session.url_for("WebsocketEndpoint"))})
        await session.close()


mixed_protocol_app = Router(
    routes=[
        Route("/", endpoint=http_endpoint),
        WebSocketRoute("/", endpoint=WebsocketEndpoint),
    ]
)


def test_protocol_switch():
    client = TestClient(mixed_protocol_app)

    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "URL: http://testserver/"

    with client.websocket_connect("/") as session:
        assert session.receive_json() == {"URL": "ws://testserver/"}

    with pytest.raises(WebSocketDisconnect):
        client.websocket_connect("/404")


def ok(request):
    return PlainTextResponse("OK")


def test_mount_urls():
    mounted = Router([Mount("/users", ok, name="users")])
    client = TestClient(mounted)
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
