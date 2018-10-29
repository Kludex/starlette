## 0.6.1

Added support for `BaseHTTPMiddleware`, which provides a standard
request/response interface over a regular ASGI middleware.

This means you can write ASGI middleware while still working at
a request/response level, rather than handling ASGI messages directly.

```python
from starlette.middleware.base import BaseHTTPMiddleware


class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Custom-Header'] = 'Example'
        return response
```

## 0.6.0

### request.path_params

The biggest change in 0.6 is that endpoint signatures are no longer:

```python
async def func(request: Request, **kwargs) -> Response
```

Instead we just use:

```python
async def func(request: Request) -> Response
```

The path parameters are available on the request as `request.path_params`.

This is different to most Python webframeworks, but I think it actually ends up
being much more nicely consistent all the way through.

### request.url_for()

Request and WebSocketSession now support URL reversing with `request.url_for(name, **path_params)`.
This method returns a fully qualified `URL` instance.
The URL instance is a string-like object.

### app.url_path_for()

Applications now support URL path reversing with `app.url_path_for(name, **path_params)`.
This method returns a `URL` instance with the path and scheme set.
The URL instance is a string-like object, and will return only the path if coerced to a string.

### app.routes

Applications now support a `.routes` parameter, which returns a list of `[Route|WebSocketRoute|Mount]`.

### Route, WebSocketRoute, Mount

The low level components to `Router` now match the `@app.route()`, `@app.websocket_route()`, and `app.mount()` signatures.
