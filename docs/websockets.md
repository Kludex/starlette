
Starlette includes a `WebSocketSessions` class that fulfils a similar role
to the HTTP request, but that allows sending and receiving data on a websocket
session.

### WebSocketSession

Signature: `WebSocketSession(scope, receive=None, send=None)`

```python
from starlette.websockets import WebSocketSession


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        session = WebSocketSession(self.scope, receive=receive, send=send)
        await session.accept()
        await session.send_text('Hello, world!')
        await session.close()
```

Sessions present a mapping interface, so you can use them in the same
way as a `scope`.

For instance: `session['path']` will return the ASGI path.

#### URL

The session URL is accessed as `session.url`.

The property is actually a subclass of `str`, and also exposes all the
components that can be parsed out of the URL.

For example: `session.url.path`, `session.url.port`, `session.url.scheme`.

#### Headers

Headers are exposed as an immutable, case-insensitive, multi-dict.

For example: `session.headers['sec-websocket-version']`

#### Query Parameters

Headers are exposed as an immutable multi-dict.

For example: `session.query_params['abc']`

### Accepting the connection

* `await session.accept(subprotocol=None)`

### Sending data

* `await session.send_text(data)`
* `await session.send_bytes(data)`
* `await session.send_json(data)`

### Receiving data

* `await session.receive_text()`
* `await session.receive_bytes()`
* `await session.receive_json()`

May raise `starlette.websockets.Disconnect()`.

### Closing the connection

* `await session.close(code=1000)`

### Sending and receiving messages

If you need to send or receive raw ASGI messages then you should use
`session.send()` and `session.receive()` rather than using the raw `send` and
`receive` callables. This will ensure that the session's state is kept
correctly updated.

* `await session.send(message)`
* `await session.receive()`


<p align="center">&mdash; ⭐️ &mdash;</p>
<p align="center"><i>Starlette is <a href="https://github.com/tomchristie/starlette/blob/master/LICENSE.md">BSD licensed</a> code. Designed & built in Brighton, England.</i></p>
