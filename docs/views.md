
Starlette includes a `View` class that provides a class-based view pattern which
handles HTTP method dispatching.

The `View` class can be used as an other ASGI application:

```python
from starlette.response import PlainTextResponse
from starlette.views import View


class App(View):
    async def get(self, request):
        return PlainTextResponse(f"Hello, world!")
```

If you're using a Starlette application instance to handle routing, you can
dispatch to a View class by using the `@app.route()` decorator, or the
`app.add_route()` function. Make sure to dispatch to the class itself, rather
than to an instance of the class:

```python
from starlette.app import App
from starlette.response import PlainTextResponse
from starlette.views import View


app = App()


@app.route("/")
class Homepage(View):
    async def get(self, request):
        return PlainTextResponse(f"Hello, world!")


@app.route("/{username}")
class User(View):
    async def get(self, request, username):
        return PlainTextResponse(f"Hello, {username}")
```

Class-based views will respond with "405 Method not allowed" responses for any
request methods which do not map to a corresponding handler.
