
Starlette includes a `WebTransport` class that manages WebTransport sessions, allowing for bidirectional streams and unreliable datagrams over HTTP/3.

### WebTransport

Signature: `WebTransport(scope, receive, send)`

```python
from starlette.webtransport import WebTransport


async def app(scope, receive, send):
    transport = WebTransport(scope=scope, receive=receive, send=send)
    await transport.accept()
    async for data in transport.iter_datagrams():
        await transport.send_datagram(data)
    await transport.close()
```

WebTransport connections present a mapping interface, so you can use them in the same way as a `scope`.

#### URL

The connection URL is accessed as `transport.url`.

#### Headers

Headers are exposed as an immutable, case-insensitive, multi-dict.
For example: `transport.headers['user-agent']`

#### Query Parameters

Query parameters are exposed as an immutable multi-dict.
For example: `transport.query_params['search']`

#### Path Parameters

Router path parameters are exposed as a dictionary interface.
For example: `transport.path_params['username']`

### Accepting the connection

* `await transport.accept(headers=None)`

### Datagrams (Unreliable)

WebTransport supports sending and receiving unreliable datagrams (similar to UDP).

* `await transport.send_datagram(data: bytes)`
* `await transport.receive_datagram() -> bytes`
* `async for data in transport.iter_datagrams()`

### Streams (Reliable)

WebTransport supports multiple reliable streams over a single connection. Starlette provides a `WebTransportStream` object for each stream.

* `await transport.accept_stream() -> WebTransportStream`

#### WebTransportStream

Represents a single bidirectional or unidirectional stream.

* `stream.stream_id`: The ID of the stream.
* `await stream.receive_bytes() -> bytes`: Read data from the stream.
* `await stream.send_bytes(data: bytes)`: Write data to the stream.
* `await stream.close()`: Close the stream.

### Closing the connection

* `await transport.close(code=0, reason=None)`

### Endpoints

Starlette provides a `WebTransportEndpoint` base class for class-based views.

```python
from starlette.endpoints import WebTransportEndpoint
from starlette.webtransport import WebTransport

class EchoTransport(WebTransportEndpoint):
    async def on_connect(self, transport: WebTransport) -> None:
        await transport.accept()
    
    async def on_datagram_receive(self, transport: WebTransport, data: bytes) -> None:
        await transport.send_datagram(data)
        
    async def on_stream_receive(self, transport: WebTransport, stream_id: int, data: bytes, stream_ended: bool) -> None:
        # Echo data back on the same stream
        stream = transport._streams.get(stream_id)
        if stream:
            await stream.send_bytes(data)
```
