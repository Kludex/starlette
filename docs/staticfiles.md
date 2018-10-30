
Starlette also includes a `StaticFiles` class for serving a specific directory:

* `StaticFiles(directory)` - Serve any files in the given `directory`.

You can combine this ASGI application with Starlette's routing to provide
comprehensive static file serving.

```python
from starlette.routing import Router, Mount
from starlette.staticfiles import StaticFiles


app = Router(routes=[
    Mount('/static', app=StaticFiles(directory='static')),
])
```

Static files will respond with "404 Not found" or "405 Method not allowed"
responses for requests which do not match.
