
The test client allows you to make requests against your ASGI application,
using the `requests` library.

```python
from starlette.responses import HTMLResponse
from starlette.testclient import TestClient


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = HTMLResponse('<html><body>Hello, world!</body></html>')
    await response(scope, receive, send)


def test_app():
    client = TestClient(app)
    response = client.get('/')
    assert response.status_code == 200
```

The test client exposes the same interface as any other `requests` session.
In particular, note that the calls to make a request are just standard
function calls, not awaitables.

You can use any of `requests` standard API, such as authentication, session
cookies handling, or file uploads.

By default the `TestClient` will raise any exceptions that occur in the
application. Occasionally you might want to test the content of 500 error
responses, rather than allowing client to raise the server exception. In this
case you should use `client = TestClient(app, raise_server_exceptions=False)`.

### Selecting the Async backend

`TestClient` takes arguments `backend` (a string) and `backend_options` (a dictionary).
These options are passed to `anyio.start_blocking_portal()`. See the [anyio documentation](https://anyio.readthedocs.io/en/stable/basics.html#backend-options)
for more information about the accepted backend options.
By default, `asyncio` is used with default options.

To run `Trio`, pass `backend="trio"`. For example:

```python
def test_app()
    with TestClient(app, backend="trio") as client:
       ...
```

To run `asyncio` with `uvloop`, pass `backend_options={"use_uvloop": True}`.  For example:

```python
def test_app()
    with TestClient(app, backend_options={"use_uvloop": True}) as client:
       ...
```

### Testing WebSocket sessions

You can also test websocket sessions with the test client.

The `requests` library will be used to build the initial handshake, meaning you
can use the same authentication options and other headers between both http and
websocket testing.

```python
from starlette.testclient import TestClient
from starlette.websockets import WebSocket


async def app(scope, receive, send):
    assert scope['type'] == 'websocket'
    websocket = WebSocket(scope, receive=receive, send=send)
    await websocket.accept()
    await websocket.send_text('Hello, world!')
    await websocket.close()


def test_app():
    client = TestClient(app)
    with client.websocket_connect('/') as websocket:
        data = websocket.receive_text()
        assert data == 'Hello, world!'
```

The operations on session are standard function calls, not awaitables.

It's important to use the session within a context-managed `with` block. This
ensure that the background thread on which the ASGI application is properly
terminated, and that any exceptions that occur within the application are
always raised by the test client.

#### Establishing a test session

* `.websocket_connect(url, subprotocols=None, **options)` - Takes the same set of arguments as `requests.get()`.

May raise `starlette.websockets.WebSocketDisconnect` if the application does not accept the websocket connection.

`websocket_connect()` must be used as a context manager (in a `with` block).

#### Sending data

* `.send_text(data)` - Send the given text to the application.
* `.send_bytes(data)` - Send the given bytes to the application.
* `.send_json(data, mode="text")` - Send the given data to the application. Use `mode="binary"` to send JSON over binary data frames.

#### Receiving data

* `.receive_text()` - Wait for incoming text sent by the application and return it.
* `.receive_bytes()` - Wait for incoming bytestring sent by the application and return it.
* `.receive_json(mode="text")` - Wait for incoming json data sent by the application and return it. Use `mode="binary"` to receive JSON over binary data frames.

May raise `starlette.websockets.WebSocketDisconnect`.

#### Closing the connection

* `.close(code=1000)` - Perform a client-side close of the websocket connection.
