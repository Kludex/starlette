
Starlette includes the classes `HTTPEndpoint` and `WebSocketEndpoint` that provide a class-based view pattern for
handling HTTP method dispatching and WebSocket sessions.

### HTTPEndpoint

The `HTTPEndpoint` class can be used as an ASGI application:

```python
from starlette.responses import PlainTextResponse
from starlette.endpoints import HTTPEndpoint


class App(HTTPEndpoint):
    async def get(self, request):
        return PlainTextResponse(f"Hello, world!")
```

If you're using a Starlette application instance to handle routing, you can
dispatch to an `HTTPEndpoint` class by using the `@app.route()` decorator, or the
`app.add_route()` function. Make sure to dispatch to the class itself, rather
than to an instance of the class:

```python
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.endpoints import HTTPEndpoint


app = Starlette()


@app.route("/")
class Homepage(HTTPEndpoint):
    async def get(self, request):
        return PlainTextResponse(f"Hello, world!")


@app.route("/{username}")
class User(HTTPEndpoint):
    async def get(self, request, username):
        return PlainTextResponse(f"Hello, {username}")
```

HTTP endpoint classes will respond with "405 Method not allowed" responses for any
request methods which do not map to a corresponding handler.

### WebSocketEndpoint

The `WebSocketEndpoint` class is an ASGI application that presents a wrapper around
the functionality of a `WebSocket` instance.

The ASGI connection scope is accessible on the endpoint instance via `.scope` and
has an attribute `encoding` which may optionally be set, in order to validate the expected websocket data in the `on_receive` method.

The encoding types are:

* `'json'`
* `'bytes'`
* `'text'`

There are three overridable methods for handling specific ASGI websocket message types:

* `async def on_connect(websocket, **kwargs)`
* `async def on_receive(websocket, data)`
* `async def on_disconnect(websocket, close_code)`

```python
from starlette.endpoints import WebSocketEndpoint


class App(WebSocketEndpoint):
    encoding = 'bytes'

    async def on_connect(self, websocket, **kwargs):
        await websocket.accept()

    async def on_receive(self, websocket, data):
        await websocket.send_bytes(b"Message: " + data)

    async def on_disconnect(self, websocket, close_code):
        pass
```

The `WebSocketEndpoint` can also be used with the `Starlette` application class:

```python
import uvicorn
from starlette.applications import Starlette
from starlette.endpoints import WebSocketEndpoint, HTTPEndpoint
from starlette.responses import HTMLResponse

app = Starlette()

html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Chat</title>
    </head>
    <body>
        <h1>WebSocket Chat</h1>
        <form action="" onsubmit="sendMessage(event)">
            <input type="text" id="messageText" autocomplete="off"/>
            <button>Send</button>
        </form>
        <ul id='messages'>
        </ul>
        <script>
            var ws = new WebSocket("ws://localhost:8000/ws");
            ws.onmessage = function(event) {
                var messages = document.getElementById('messages')
                var message = document.createElement('li')
                var content = document.createTextNode(event.data)
                message.appendChild(content)
                messages.appendChild(message)
            };
            function sendMessage(event) {
                var input = document.getElementById("messageText")
                ws.send(input.value)
                input.value = ''
                event.preventDefault()
            }
        </script>
    </body>
</html>
"""


@app.route("/")
class Homepage(HTTPEndpoint):
    async def get(self, request):
        return HTMLResponse(html)


@app.websocket_route("/ws")
class Echo(WebSocketEndpoint):

    encoding = "text"

    async def on_receive(self, websocket, data):
        await websocket.send_text(f"Message text was: {data}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
```
