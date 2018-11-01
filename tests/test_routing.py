import pytest

from starlette.exceptions import ExceptionMiddleware
from starlette.responses import Response
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


def staticfiles(request):
    return Response("xxxxx", media_type="image/png")


app = Router(
    [
        Route("/", endpoint=homepage, methods=["GET"]),
        Mount(
            "/users",
            app=Router(
                [Route("", endpoint=users), Route("/{username}", endpoint=user)]
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

    response = client.get("/static/123")
    assert response.status_code == 200
    assert response.text == "xxxxx"


def test_url_path_for():
    assert app.url_path_for("homepage") == "/"
    assert app.url_path_for("user", username="tomchristie") == "/users/tomchristie"
    assert app.url_path_for("websocket_endpoint") == "/ws"
    with pytest.raises(NoMatchFound):
        assert app.url_path_for("broken")


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
