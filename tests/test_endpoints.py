from typing import Iterator

import pytest

from starlette.endpoints import HTTPEndpoint, WebSocketEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route, Router
from starlette.testclient import TestClient
from starlette.websockets import WebSocket
from tests.types import TestClientFactory


class Homepage(HTTPEndpoint):
    async def get(self, request: Request) -> PlainTextResponse:
        username = request.path_params.get("username")
        if username is None:
            return PlainTextResponse("Hello, world!")
        return PlainTextResponse(f"Hello, {username}!")


app = Router(routes=[Route("/", endpoint=Homepage), Route("/{username}", endpoint=Homepage)])


@pytest.fixture
def client(test_client_factory: TestClientFactory) -> Iterator[TestClient]:
    with test_client_factory(app) as client:
        yield client


def test_http_endpoint_route(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_http_endpoint_route_path_params(client: TestClient) -> None:
    response = client.get("/tomchristie")
    assert response.status_code == 200
    assert response.text == "Hello, tomchristie!"


def test_http_endpoint_route_method(client: TestClient) -> None:
    response = client.post("/")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"
    assert response.headers["allow"] == "GET"


def test_websocket_endpoint_on_connect(test_client_factory: TestClientFactory) -> None:
    class WebSocketApp(WebSocketEndpoint):
        async def on_connect(self, websocket: WebSocket) -> None:
            assert websocket["subprotocols"] == ["soap", "wamp"]
            await websocket.accept(subprotocol="wamp")

    client = test_client_factory(WebSocketApp)
    with client.websocket_connect("/ws", subprotocols=["soap", "wamp"]) as websocket:
        assert websocket.accepted_subprotocol == "wamp"


def test_websocket_endpoint_on_receive_bytes(
    test_client_factory: TestClientFactory,
) -> None:
    class WebSocketApp(WebSocketEndpoint):
        encoding = "bytes"

        async def on_receive(self, websocket: WebSocket, data: bytes) -> None:
            await websocket.send_bytes(b"Message bytes was: " + data)

    client = test_client_factory(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_bytes(b"Hello, world!")
        _bytes = websocket.receive_bytes()
        assert _bytes == b"Message bytes was: Hello, world!"

    with pytest.raises(RuntimeError):
        with client.websocket_connect("/ws") as websocket:
            websocket.send_text("Hello world")


def test_websocket_endpoint_on_receive_json(
    test_client_factory: TestClientFactory,
) -> None:
    class WebSocketApp(WebSocketEndpoint):
        encoding = "json"

        async def on_receive(self, websocket: WebSocket, data: str) -> None:
            await websocket.send_json({"message": data})

    client = test_client_factory(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_json({"hello": "world"})
        data = websocket.receive_json()
        assert data == {"message": {"hello": "world"}}

    with pytest.raises(RuntimeError):
        with client.websocket_connect("/ws") as websocket:
            websocket.send_text("Hello world")


def test_websocket_endpoint_on_receive_json_binary(
    test_client_factory: TestClientFactory,
) -> None:
    class WebSocketApp(WebSocketEndpoint):
        encoding = "json"

        async def on_receive(self, websocket: WebSocket, data: str) -> None:
            await websocket.send_json({"message": data}, mode="binary")

    client = test_client_factory(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_json({"hello": "world"}, mode="binary")
        data = websocket.receive_json(mode="binary")
        assert data == {"message": {"hello": "world"}}


def test_websocket_endpoint_on_receive_text(
    test_client_factory: TestClientFactory,
) -> None:
    class WebSocketApp(WebSocketEndpoint):
        encoding = "text"

        async def on_receive(self, websocket: WebSocket, data: str) -> None:
            await websocket.send_text(f"Message text was: {data}")

    client = test_client_factory(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text("Hello, world!")
        _text = websocket.receive_text()
        assert _text == "Message text was: Hello, world!"

    with pytest.raises(RuntimeError):
        with client.websocket_connect("/ws") as websocket:
            websocket.send_bytes(b"Hello world")


def test_websocket_endpoint_on_default(test_client_factory: TestClientFactory) -> None:
    class WebSocketApp(WebSocketEndpoint):
        encoding = None

        async def on_receive(self, websocket: WebSocket, data: str) -> None:
            await websocket.send_text(f"Message text was: {data}")

    client = test_client_factory(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.send_text("Hello, world!")
        _text = websocket.receive_text()
        assert _text == "Message text was: Hello, world!"


def test_websocket_endpoint_on_disconnect(
    test_client_factory: TestClientFactory,
) -> None:
    class WebSocketApp(WebSocketEndpoint):
        async def on_disconnect(self, websocket: WebSocket, close_code: int) -> None:
            assert close_code == 1001
            await websocket.close(code=close_code)

    client = test_client_factory(WebSocketApp)
    with client.websocket_connect("/ws") as websocket:
        websocket.close(code=1001)
