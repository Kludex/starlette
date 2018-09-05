
Starlette includes an `HTTPEndpoint` class that provides a class-based view pattern which
handles HTTP method dispatching.

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
