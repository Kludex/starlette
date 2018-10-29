import pytest
from starlette.responses import PlainTextResponse
from starlette.routing import Router, Route
from starlette.testclient import TestClient
from starlette.endpoints import HTTPEndpoint, WebSocketEndpoint


class Homepage(HTTPEndpoint):
    async def get(self, request):
        username = request.path_params.get("username")
        if username is None:
            return PlainTextResponse("Hello, world!")
        return PlainTextResponse(f"Hello, {username}!")


app = Router(
    routes=[Route("/", endpoint=Homepage), Route("/{username}", endpoint=Homepage)]
)

client = TestClient(app)


def test_http_endpoint_route():
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_http_endpoint_route_path_params():
    response = client.get("/tomchristie")
    assert response.status_code == 200
    assert response.text == "Hello, tomchristie!"


def test_http_endpoint_route_method():
    response = client.post("/")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"


def test_websocket_endpoint_on_connect():
    class WebSocketApp(WebSocketEndpoint):
        async def on_connect(self, websocket):
            assert websocket["subprotocols"] == ["soap", "wamp"]
            await websocket.accept(subprotocol="wamp")

    client = TestClient(WebSocketApp)
    with client.websocket_connect("/ws", subprotocols=["soap", "wamp"]) as websocket:
        assert websocket.accepted_subprotocol == "wamp"


def test_websocket_endpoint_on_receive_bytes():
    class WebSocketApp(WebSocketEndpoint):
        encoding = "bytes"

        async def on_receive(self, websocket, data):
            await websocket.send_bytes(b"Message bytes was: " + data)

    client = TestClient(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_bytes(b"Hello, world!")
        _bytes = websocket.receive_bytes()
        assert _bytes == b"Message bytes was: Hello, world!"

    with pytest.raises(RuntimeError):
        with client.websocket_connect("/ws") as websocket:
            websocket.send_text("Hello world")


def test_websocket_endpoint_on_receive_json():
    class WebSocketApp(WebSocketEndpoint):
        encoding = "json"

        async def on_receive(self, websocket, data):
            await websocket.send_json({"message": data})

    client = TestClient(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_json({"hello": "world"})
        data = websocket.receive_json()
        assert data == {"message": {"hello": "world"}}

    with pytest.raises(RuntimeError):
        with client.websocket_connect("/ws") as websocket:
            websocket.send_text("Hello world")


def test_websocket_endpoint_on_receive_text():
    class WebSocketApp(WebSocketEndpoint):
        encoding = "text"

        async def on_receive(self, websocket, data):
            await websocket.send_text(f"Message text was: {data}")

    client = TestClient(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text("Hello, world!")
        _text = websocket.receive_text()
        assert _text == "Message text was: Hello, world!"

    with pytest.raises(RuntimeError):
        with client.websocket_connect("/ws") as websocket:
            websocket.send_bytes(b"Hello world")


def test_websocket_endpoint_on_default():
    class WebSocketApp(WebSocketEndpoint):
        encoding = None

        async def on_receive(self, websocket, data):
            await websocket.send_text(f"Message text was: {data}")

    client = TestClient(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text("Hello, world!")
        _text = websocket.receive_text()
        assert _text == "Message text was: Hello, world!"


def test_websocket_endpoint_on_disconnect():
    class WebSocketApp(WebSocketEndpoint):
        async def on_disconnect(self, websocket, close_code):
            assert close_code == 1001
            await websocket.close(code=close_code)

    client = TestClient(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.close(code=1001)
