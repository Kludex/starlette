
Starlette includes a `WebSocket` class that fulfils a similar role
to the HTTP request, but that allows sending and receiving data on a websocket.

### WebSocket

Signature: `WebSocket(scope, receive=None, send=None)`

```python
from starlette.websockets import WebSocket


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        websocket = WebSocket(self.scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.send_text('Hello, world!')
        await websocket.close()
```

WebSockets present a mapping interface, so you can use them in the same
way as a `scope`.

For instance: `websocket['path']` will return the ASGI path.

#### URL

The websocket URL is accessed as `websocket.url`.

The property is actually a subclass of `str`, and also exposes all the
components that can be parsed out of the URL.

For example: `websocket.url.path`, `websocket.url.port`, `websocket.url.scheme`.

#### Headers

Headers are exposed as an immutable, case-insensitive, multi-dict.

For example: `websocket.headers['sec-websocket-version']`

#### Query Parameters

Headers are exposed as an immutable multi-dict.

For example: `websocket.query_params['abc']`

### Accepting the connection

* `await websocket.accept(subprotocol=None)`

### Sending data

* `await websocket.send_text(data)`
* `await websocket.send_bytes(data)`
* `await websocket.send_json(data)`

### Receiving data

* `await websocket.receive_text()`
* `await websocket.receive_bytes()`
* `await websocket.receive_json()`

May raise `starlette.websockets.Disconnect()`.

### Closing the connection

* `await websocket.close(code=1000)`

### Sending and receiving messages

If you need to send or receive raw ASGI messages then you should use
`websocket.send()` and `websocket.receive()` rather than using the raw `send` and
`receive` callables. This will ensure that the websocket's state is kept
correctly updated.

* `await websocket.send(message)`
* `await websocket.receive()`
