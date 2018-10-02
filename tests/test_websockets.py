import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect


def test_websocket_url():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.send_json({"url": websocket.url})
            await websocket.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/123?a=abc") as websocket:
        data = websocket.receive_json()
        assert data == {"url": "ws://testserver/123?a=abc"}


def test_websocket_query_params():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            query_params = dict(websocket.query_params)
            await websocket.accept()
            await websocket.send_json({"params": query_params})
            await websocket.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/?a=abc&b=456") as websocket:
        data = websocket.receive_json()
        assert data == {"params": {"a": "abc", "b": "456"}}


def test_websocket_headers():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            headers = dict(websocket.headers)
            await websocket.accept()
            await websocket.send_json({"headers": headers})
            await websocket.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as websocket:
        expected_headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate",
            "connection": "upgrade",
            "host": "testserver",
            "user-agent": "testclient",
            "sec-websocket-key": "testserver==",
            "sec-websocket-version": "13",
        }
        data = websocket.receive_json()
        assert data == {"headers": expected_headers}


def test_websocket_port():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.send_json({"port": websocket.url.port})
            await websocket.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("ws://example.com:123/123?a=abc") as websocket:
        data = websocket.receive_json()
        assert data == {"port": 123}


def test_websocket_send_and_receive_text():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            data = await websocket.receive_text()
            await websocket.send_text("Message was: " + data)
            await websocket.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_text("Hello, world!")
        data = websocket.receive_text()
        assert data == "Message was: Hello, world!"


def test_websocket_send_and_receive_bytes():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            data = await websocket.receive_bytes()
            await websocket.send_bytes(b"Message was: " + data)
            await websocket.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_bytes(b"Hello, world!")
        data = websocket.receive_bytes()
        assert data == b"Message was: Hello, world!"


def test_websocket_send_and_receive_json():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            data = await websocket.receive_json()
            await websocket.send_json({"message": data})
            await websocket.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_json({"hello": "world"})
        data = websocket.receive_json()
        assert data == {"message": {"hello": "world"}}


def test_client_close():
    close_code = None

    def app(scope):
        async def asgi(receive, send):
            nonlocal close_code
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            try:
                await websocket.receive_text()
            except WebSocketDisconnect as exc:
                close_code = exc.code

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as websocket:
        websocket.close(code=1001)
    assert close_code == 1001


def test_application_close():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.close(1001)

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as websocket:
        with pytest.raises(WebSocketDisconnect) as exc:
            websocket.receive_text()
        assert exc.value.code == 1001


def test_rejected_connection():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.close(1001)

        return asgi

    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as exc:
        client.websocket_connect("/")
    assert exc.value.code == 1001


def test_subprotocol():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            assert websocket["subprotocols"] == ["soap", "wamp"]
            await websocket.accept(subprotocol="wamp")
            await websocket.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/", subprotocols=["soap", "wamp"]) as websocket:
        assert websocket.accepted_subprotocol == "wamp"


def test_websocket_exception():
    def app(scope):
        async def asgi(receive, send):
            assert False

        return asgi

    client = TestClient(app)
    with pytest.raises(AssertionError):
        client.websocket_connect("/123?a=abc")


def test_duplicate_close():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            await websocket.close()
            await websocket.close()

        return asgi

    client = TestClient(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass


def test_duplicate_disconnect():
    def app(scope):
        async def asgi(receive, send):
            websocket = WebSocket(scope, receive, send)
            await websocket.accept()
            message = await websocket.receive()
            assert message["type"] == "websocket.disconnect"
            message = await websocket.receive()

        return asgi

    client = TestClient(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/") as websocket:
            websocket.close()


def test_websocket_scope_interface():
    """
    A WebSocket can be instantiated with a scope, and presents a `Mapping`
    interface.
    """

    websocket = WebSocket(
        {"type": "websocket", "path": "/abc/", "headers": []},
        send=lambda: True,
        receive=lambda: True,
    )
    assert websocket["type"] == "websocket"
    assert dict(websocket) == {"type": "websocket", "path": "/abc/", "headers": []}
    assert len(websocket) == 3
