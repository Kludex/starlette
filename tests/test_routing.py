from starlette import Response, TestClient
from starlette.exceptions import ExceptionMiddleware
from starlette.routing import Path, PathPrefix, Router, ProtocolRouter
from starlette.websockets import WebSocketSession, WebSocketDisconnect
import pytest


def homepage(scope):
    return Response("Hello, world", media_type="text/plain")


def users(scope):
    return Response("All users", media_type="text/plain")


def user(scope):
    content = "User " + scope["kwargs"]["username"]
    return Response(content, media_type="text/plain")


def staticfiles(scope):
    return Response("xxxxx", media_type="image/png")


app = Router(
    [
        Path("/", app=homepage, methods=["GET"]),
        PathPrefix(
            "/users", app=Router([Path("", app=users), Path("/{username}", app=user)])
        ),
        PathPrefix("/static", app=staticfiles, methods=["GET"]),
    ]
)


def test_router():
    client = TestClient(app)

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

    response = client.post("/static/123")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"


def http_endpoint(scope):
    return Response("Hello, world", media_type="text/plain")


def websocket_endpoint(scope):
    async def asgi(receive, send):
        session = WebSocketSession(scope, receive, send)
        await session.accept()
        await session.send_json({"hello": "world"})
        await session.close()

    return asgi


mixed_protocol_app = ProtocolRouter(
    {
        "http": Router([Path("/", app=http_endpoint)]),
        "websocket": Router([Path("/", app=websocket_endpoint)]),
    }
)


def test_protocol_switch():
    client = TestClient(mixed_protocol_app)

    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, world"

    with client.websocket_connect("/") as session:
        assert session.receive_json() == {"hello": "world"}

    with pytest.raises(WebSocketDisconnect):
        client.websocket_connect("/404")
