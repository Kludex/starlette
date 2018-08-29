
Starlette includes a `Router` class which is an ASGI application that
dispatches to other ASGI applications.

```python
from starlette.routing import Router, Path, PathPrefix
from myproject import Homepage, SubMountedApp


app = Router([
    Path('/', app=Homepage, methods=['GET']),
    PathPrefix('/mount/', app=SubMountedApp)
])
```

Paths can use URI templating style to capture path components.

```python
Path('/users/{username}', app=User, methods=['GET'])
```

Path components are made available in the scope, as `scope["kwargs"]`.

You can also use regular expressions for more complicated matching.

Named capture groups will be included in `scope["kwargs"]`:

```python
Path('/users/(?P<username>[a-zA-Z0-9_]{1,20})', app=User, methods=['GET'])
```

Because each target of the router is an ASGI instance itself, routers
allow for easy composition. For example:

```python
app = Router([
    Path('/', app=Homepage, methods=['GET']),
    PathPrefix('/users', app=Router([
        Path('/', app=Users, methods=['GET', 'POST']),
        Path('/{username}', app=User, methods=['GET']),
    ]))
])
```

The router will respond with "404 Not found" or "406 Method not allowed"
responses for requests which do not match.

### Protocol Routing

You can also route based on the incoming protocol, using the `ProtocolRouter`
class.

```python
from starlette.response import Response
from starlette.routing import ProtocolRouter
from starlette.websockets import WebSocketSession


def http_endpoint(scope):
    return Response("Hello, world", media_type="text/plain")


def websocket_endpoint(scope):
    async def asgi(receive, send):
        session = WebSocketSession(scope, receive, send)
        await session.accept()
        await session.send_json({"hello": "world"})
        await session.close()
    return asgi


app = ProtocolRouter({
    "http": http_endpoint,
    "websocket": websocket_endpoint
})
```
