from typing import Any

import pytest

from starlette.types import Receive, Scope, Send
from starlette.webtransport import WebTransport, WebTransportDisconnect


def test_webtransport_accept(test_client_factory: Any) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        transport = WebTransport(scope, receive=receive, send=send)
        await transport.accept()
        await transport.close()

    client = test_client_factory(app)
    with client.webtransport_connect("/"):
        pass


def test_webtransport_datagrams(test_client_factory: Any) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        transport = WebTransport(scope, receive=receive, send=send)
        await transport.accept()
        data = await transport.receive_datagram()
        await transport.send_datagram(b"echo: " + data)
        await transport.close()

    client = test_client_factory(app)
    with client.webtransport_connect("/") as session:
        session.send_datagram(b"hello")
        message = session.receive()
        assert message["type"] == "webtransport.datagram.send"
        assert message["data"] == b"echo: hello"


def test_webtransport_streams(test_client_factory: Any) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        transport = WebTransport(scope, receive=receive, send=send)
        await transport.accept()
        stream = await transport.accept_stream()
        data = await stream.receive_bytes()
        await stream.send_bytes(b"echo: " + data)
        await stream.close()
        await transport.close()

    client = test_client_factory(app)
    with client.webtransport_connect("/") as session:
        session.send_stream_data(stream_id=0, data=b"hello", end_stream=True)

        # We might receive multiple chunks if implementing flow control, but for test
        message = session.receive()
        assert message["type"] == "webtransport.stream.send"
        assert message["stream_id"] == 0
        assert message["data"] == b"echo: hello"

        # Expect FIN
        message = session.receive()
        assert message["type"] == "webtransport.stream.send"
        assert message["data"] == b""
        assert message["finish"] is True


def test_webtransport_disconnect(test_client_factory: Any) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        transport = WebTransport(scope, receive=receive, send=send)
        await transport.accept()
        try:
            await transport.receive_datagram()
        except WebTransportDisconnect:
            pass  # Expected

    client = test_client_factory(app)
    with client.webtransport_connect("/") as session:
        session.close()


def test_webtransport_reject(test_client_factory: Any) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        transport = WebTransport(scope, receive=receive, send=send)
        await transport.close(code=403)

    client = test_client_factory(app)
    with pytest.raises(WebTransportDisconnect) as exc:
        with client.webtransport_connect("/"):
            pass
    assert exc.value.code == 403
