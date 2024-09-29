import sys
from typing import Any, MutableMapping

import anyio
import pytest
from anyio.abc import ObjectReceiveStream, ObjectSendStream

from starlette import status
from starlette.responses import Response
from starlette.testclient import WebSocketDenialResponse
from starlette.types import Message, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect, WebSocketState
from tests.types import TestClientFactory


def test_websocket_url(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.send_json({"url": str(websocket.url)})
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/123?a=abc") as websocket:
        data = websocket.receive_json()
        assert data == {"url": "ws://testserver/123?a=abc"}


def test_websocket_binary_json(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        message = await websocket.receive_json(mode="binary")
        await websocket.send_json(message, mode="binary")
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/123?a=abc") as websocket:
        websocket.send_json({"test": "data"}, mode="binary")
        data = websocket.receive_json(mode="binary")
        assert data == {"test": "data"}


def test_websocket_ensure_unicode_on_send_json(
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)

        await websocket.accept()
        message = await websocket.receive_json(mode="text")
        await websocket.send_json(message, mode="text")
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/123?a=abc") as websocket:
        websocket.send_json({"test": "数据"}, mode="text")
        data = websocket.receive_text()
        assert data == '{"test":"数据"}'


def test_websocket_query_params(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        query_params = dict(websocket.query_params)
        await websocket.accept()
        await websocket.send_json({"params": query_params})
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/?a=abc&b=456") as websocket:
        data = websocket.receive_json()
        assert data == {"params": {"a": "abc", "b": "456"}}


@pytest.mark.skipif(
    any(module in sys.modules for module in ("brotli", "brotlicffi")),
    reason='urllib3 includes "br" to the "accept-encoding" headers.',
)
def test_websocket_headers(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        headers = dict(websocket.headers)
        await websocket.accept()
        await websocket.send_json({"headers": headers})
        await websocket.close()

    client = test_client_factory(app)
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


def test_websocket_port(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.send_json({"port": websocket.url.port})
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("ws://example.com:123/123?a=abc") as websocket:
        data = websocket.receive_json()
        assert data == {"port": 123}


def test_websocket_send_and_receive_text(
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        data = await websocket.receive_text()
        await websocket.send_text("Message was: " + data)
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_text("Hello, world!")
        data = websocket.receive_text()
        assert data == "Message was: Hello, world!"


def test_websocket_send_and_receive_bytes(
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        data = await websocket.receive_bytes()
        await websocket.send_bytes(b"Message was: " + data)
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_bytes(b"Hello, world!")
        data = websocket.receive_bytes()
        assert data == b"Message was: Hello, world!"


def test_websocket_send_and_receive_json(
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        data = await websocket.receive_json()
        await websocket.send_json({"message": data})
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_json({"hello": "world"})
        data = websocket.receive_json()
        assert data == {"message": {"hello": "world"}}


def test_websocket_iter_text(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        async for data in websocket.iter_text():
            await websocket.send_text("Message was: " + data)

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_text("Hello, world!")
        data = websocket.receive_text()
        assert data == "Message was: Hello, world!"


def test_websocket_iter_bytes(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        async for data in websocket.iter_bytes():
            await websocket.send_bytes(b"Message was: " + data)

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_bytes(b"Hello, world!")
        data = websocket.receive_bytes()
        assert data == b"Message was: Hello, world!"


def test_websocket_iter_json(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        async for data in websocket.iter_json():
            await websocket.send_json({"message": data})

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_json({"hello": "world"})
        data = websocket.receive_json()
        assert data == {"message": {"hello": "world"}}


def test_websocket_concurrency_pattern(test_client_factory: TestClientFactory) -> None:
    stream_send: ObjectSendStream[MutableMapping[str, Any]]
    stream_receive: ObjectReceiveStream[MutableMapping[str, Any]]
    stream_send, stream_receive = anyio.create_memory_object_stream()

    async def reader(websocket: WebSocket) -> None:
        async with stream_send:
            async for data in websocket.iter_json():
                await stream_send.send(data)

    async def writer(websocket: WebSocket) -> None:
        async with stream_receive:
            async for message in stream_receive:
                await websocket.send_json(message)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(reader, websocket)
            await writer(websocket)
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        websocket.send_json({"hello": "world"})
        data = websocket.receive_json()
        assert data == {"hello": "world"}


def test_client_close(test_client_factory: TestClientFactory) -> None:
    close_code = None
    close_reason = None

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal close_code, close_reason
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        try:
            await websocket.receive_text()
        except WebSocketDisconnect as exc:
            close_code = exc.code
            close_reason = exc.reason

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        websocket.close(code=status.WS_1001_GOING_AWAY, reason="Going Away")
    assert close_code == status.WS_1001_GOING_AWAY
    assert close_reason == "Going Away"


@pytest.mark.anyio
async def test_client_disconnect_on_send() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.send_text("Hello, world!")

    async def receive() -> Message:
        return {"type": "websocket.connect"}

    async def send(message: Message) -> None:
        if message["type"] == "websocket.accept":
            return
        # Simulate the exception the server would send to the application when the client disconnects.
        raise OSError

    with pytest.raises(WebSocketDisconnect) as ctx:
        await app({"type": "websocket", "path": "/"}, receive, send)
    assert ctx.value.code == status.WS_1006_ABNORMAL_CLOSURE


def test_application_close(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.close(status.WS_1001_GOING_AWAY)

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        with pytest.raises(WebSocketDisconnect) as exc:
            websocket.receive_text()
        assert exc.value.code == status.WS_1001_GOING_AWAY


def test_rejected_connection(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        msg = await websocket.receive()
        assert msg == {"type": "websocket.connect"}
        await websocket.close(status.WS_1001_GOING_AWAY)

    client = test_client_factory(app)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/"):
            pass  # pragma: no cover
    assert exc.value.code == status.WS_1001_GOING_AWAY


def test_send_denial_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        msg = await websocket.receive()
        assert msg == {"type": "websocket.connect"}
        response = Response(status_code=404, content="foo")
        await websocket.send_denial_response(response)

    client = test_client_factory(app)
    with pytest.raises(WebSocketDenialResponse) as exc:
        with client.websocket_connect("/"):
            pass  # pragma: no cover
    assert exc.value.status_code == 404
    assert exc.value.content == b"foo"


def test_send_response_multi(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        msg = await websocket.receive()
        assert msg == {"type": "websocket.connect"}
        await websocket.send(
            {
                "type": "websocket.http.response.start",
                "status": 404,
                "headers": [(b"content-type", b"text/plain"), (b"foo", b"bar")],
            }
        )
        await websocket.send({"type": "websocket.http.response.body", "body": b"hard", "more_body": True})
        await websocket.send({"type": "websocket.http.response.body", "body": b"body"})

    client = test_client_factory(app)
    with pytest.raises(WebSocketDenialResponse) as exc:
        with client.websocket_connect("/"):
            pass  # pragma: no cover
    assert exc.value.status_code == 404
    assert exc.value.content == b"hardbody"
    assert exc.value.headers["foo"] == "bar"


def test_send_response_unsupported(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        del scope["extensions"]["websocket.http.response"]
        websocket = WebSocket(scope, receive=receive, send=send)
        msg = await websocket.receive()
        assert msg == {"type": "websocket.connect"}
        response = Response(status_code=404, content="foo")
        with pytest.raises(
            RuntimeError,
            match="The server doesn't support the Websocket Denial Response extension.",
        ):
            await websocket.send_denial_response(response)
        await websocket.close()

    client = test_client_factory(app)
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/"):
            pass  # pragma: no cover
    assert exc.value.code == status.WS_1000_NORMAL_CLOSURE


def test_send_response_duplicate_start(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        msg = await websocket.receive()
        assert msg == {"type": "websocket.connect"}
        response = Response(status_code=404, content="foo")
        await websocket.send(
            {
                "type": "websocket.http.response.start",
                "status": response.status_code,
                "headers": response.raw_headers,
            }
        )
        await websocket.send(
            {
                "type": "websocket.http.response.start",
                "status": response.status_code,
                "headers": response.raw_headers,
            }
        )

    client = test_client_factory(app)
    with pytest.raises(
        RuntimeError,
        match=("Expected ASGI message \"websocket.http.response.body\", but got 'websocket.http.response.start'"),
    ):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_subprotocol(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        assert websocket["subprotocols"] == ["soap", "wamp"]
        await websocket.accept(subprotocol="wamp")
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/", subprotocols=["soap", "wamp"]) as websocket:
        assert websocket.accepted_subprotocol == "wamp"


def test_additional_headers(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept(headers=[(b"additional", b"header")])
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        assert websocket.extra_headers == [(b"additional", b"header")]


def test_no_additional_headers(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.close()

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        assert websocket.extra_headers == []


def test_websocket_exception(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        assert False

    client = test_client_factory(app)
    with pytest.raises(AssertionError):
        with client.websocket_connect("/123?a=abc"):
            pass  # pragma: no cover


def test_duplicate_close(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.close()
        await websocket.close()

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_duplicate_disconnect(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        message = await websocket.receive()
        assert message["type"] == "websocket.disconnect"
        message = await websocket.receive()

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/") as websocket:
            websocket.close()


def test_websocket_scope_interface() -> None:
    """
    A WebSocket can be instantiated with a scope, and presents a `Mapping`
    interface.
    """

    async def mock_receive() -> Message:  # type: ignore
        ...  # pragma: no cover

    async def mock_send(message: Message) -> None: ...  # pragma: no cover

    websocket = WebSocket({"type": "websocket", "path": "/abc/", "headers": []}, receive=mock_receive, send=mock_send)
    assert websocket["type"] == "websocket"
    assert dict(websocket) == {"type": "websocket", "path": "/abc/", "headers": []}
    assert len(websocket) == 3

    # check __eq__ and __hash__
    assert websocket != WebSocket(
        {"type": "websocket", "path": "/abc/", "headers": []},
        receive=mock_receive,
        send=mock_send,
    )
    assert websocket == websocket
    assert websocket in {websocket}
    assert {websocket} == {websocket}


def test_websocket_close_reason(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.close(code=status.WS_1001_GOING_AWAY, reason="Going Away")

    client = test_client_factory(app)
    with client.websocket_connect("/") as websocket:
        with pytest.raises(WebSocketDisconnect) as exc:
            websocket.receive_text()
        assert exc.value.code == status.WS_1001_GOING_AWAY
        assert exc.value.reason == "Going Away"


def test_send_json_invalid_mode(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.send_json({}, mode="invalid")

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_receive_json_invalid_mode(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.receive_json(mode="invalid")

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_receive_text_before_accept(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.receive_text()

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_receive_bytes_before_accept(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.receive_bytes()

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_receive_json_before_accept(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.receive_json()

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_send_before_accept(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.send({"type": "websocket.send"})

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_send_wrong_message_type(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.send({"type": "websocket.accept"})
        await websocket.send({"type": "websocket.accept"})

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/"):
            pass  # pragma: no cover


def test_receive_before_accept(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        websocket.client_state = WebSocketState.CONNECTING
        await websocket.receive()

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/") as websocket:
            websocket.send({"type": "websocket.send"})


def test_receive_wrong_message_type(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.receive()

    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/") as websocket:
            websocket.send({"type": "websocket.connect"})
