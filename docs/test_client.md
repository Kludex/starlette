
The test client allows you to make requests against your ASGI application,
using the `requests` library.

```python
from starlette.responses import HTMLResponse
from starlette.testclient import TestClient


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        response = HTMLResponse('<html><body>Hello, world!</body></html>')
        await response(receive, send)


def test_app():
    client = TestClient(App)
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

### Testing WebSocket sessions

You can also test websocket sessions with the test client.

The `requests` library will be used to build the initial handshake, meaning you
can use the same authentication options and other headers between both http and
websocket testing.

```python
from starlette.testclient import TestClient
from starlette.websockets import WebSocket


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        websocket = WebSocket(self.scope, receive=receive, send=send)
        await websocket.accept()
        await websocket.send_text('Hello, world!')
        await websocket.close()


def test_app():
    client = TestClient(App)
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

May raise `starlette.websockets.Disconnect` if the application does not accept the websocket connection.

#### Sending data

* `.send_text(data)` - Send the given text to the application.
* `.send_bytes(data)` - Send the given bytes to the application.
* `.send_json(data)` - Send the given data to the application.

#### Receiving data

* `.receive_text()` - Wait for incoming text sent by the application and return it.
* `.receive_bytes()` - Wait for incoming bytestring sent by the application and return it.
* `.receive_json()` - Wait for incoming json data sent by the application and return it.

May raise `starlette.websockets.Disconnect`.

#### Closing the connection

* `.close(code=1000)` - Perform a client-side close of the websocket connection.
