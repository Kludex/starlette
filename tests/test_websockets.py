import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect


def test_session_url():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            await session.accept()
            await session.send_json({"url": session.url})
            await session.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/123?a=abc") as session:
        data = session.receive_json()
        assert data == {"url": "ws://testserver/123?a=abc"}


def test_session_query_params():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            query_params = dict(session.query_params)
            await session.accept()
            await session.send_json({"params": query_params})
            await session.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/?a=abc&b=456") as session:
        data = session.receive_json()
        assert data == {"params": {"a": "abc", "b": "456"}}


def test_session_headers():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            headers = dict(session.headers)
            await session.accept()
            await session.send_json({"headers": headers})
            await session.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as session:
        expected_headers = {
            "accept": "*/*",
            "accept-encoding": "gzip, deflate",
            "connection": "upgrade",
            "host": "testserver",
            "user-agent": "testclient",
            "sec-websocket-key": "testserver==",
            "sec-websocket-version": "13",
        }
        data = session.receive_json()
        assert data == {"headers": expected_headers}


def test_session_port():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            await session.accept()
            await session.send_json({"port": session.url.port})
            await session.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("ws://example.com:123/123?a=abc") as session:
        data = session.receive_json()
        assert data == {"port": 123}


def test_session_send_and_receive_text():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            await session.accept()
            data = await session.receive_text()
            await session.send_text("Message was: " + data)
            await session.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as session:
        session.send_text("Hello, world!")
        data = session.receive_text()
        assert data == "Message was: Hello, world!"


def test_session_send_and_receive_bytes():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            await session.accept()
            data = await session.receive_bytes()
            await session.send_bytes(b"Message was: " + data)
            await session.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as session:
        session.send_bytes(b"Hello, world!")
        data = session.receive_bytes()
        assert data == b"Message was: Hello, world!"


def test_session_send_and_receive_json():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            await session.accept()
            data = await session.receive_json()
            await session.send_json({"message": data})
            await session.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as session:
        session.send_json({"hello": "world"})
        data = session.receive_json()
        assert data == {"message": {"hello": "world"}}


def test_client_close():
    close_code = None

    def app(scope):
        async def asgi(receive, send):
            nonlocal close_code
            session = WebSocket(scope, receive, send)
            await session.accept()
            try:
                data = await session.receive_text()
            except WebSocketDisconnect as exc:
                close_code = exc.code

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as session:
        session.close(code=1001)
    assert close_code == 1001


def test_application_close():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            await session.accept()
            await session.close(1001)

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/") as session:
        with pytest.raises(WebSocketDisconnect) as exc:
            session.receive_text()
        assert exc.value.code == 1001


def test_rejected_connection():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            await session.close(1001)

        return asgi

    client = TestClient(app)
    with pytest.raises(WebSocketDisconnect) as exc:
        client.websocket_connect("/")
    assert exc.value.code == 1001


def test_subprotocol():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            assert session["subprotocols"] == ["soap", "wamp"]
            await session.accept(subprotocol="wamp")
            await session.close()

        return asgi

    client = TestClient(app)
    with client.websocket_connect("/", subprotocols=["soap", "wamp"]) as session:
        assert session.accepted_subprotocol == "wamp"


def test_session_exception():
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
            session = WebSocket(scope, receive, send)
            await session.accept()
            await session.close()
            await session.close()

        return asgi

    client = TestClient(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/") as session:
            pass


def test_duplicate_disconnect():
    def app(scope):
        async def asgi(receive, send):
            session = WebSocket(scope, receive, send)
            await session.accept()
            message = await session.receive()
            assert message["type"] == "websocket.disconnect"
            message = await session.receive()

        return asgi

    client = TestClient(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/") as session:
            session.close()


def test_session_scope_interface():
    """
    A WebSocket can be instantiated with a scope, and presents a `Mapping`
    interface.
    """
    session = WebSocket({"type": "websocket", "path": "/abc/", "headers": []})
    assert session["type"] == "websocket"
    assert dict(session) == {"type": "websocket", "path": "/abc/", "headers": []}
    assert len(session) == 3
