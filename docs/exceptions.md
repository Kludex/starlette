
Starlette allows you to install custom exception handlers to deal with
how you return responses when errors or handled exceptions occur.

```python
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import HTMLResponse


HTML_404_PAGE = ...
HTML_500_PAGE = ...


async def not_found(request: Request, exc: HTTPException):
    return HTMLResponse(content=HTML_404_PAGE, status_code=exc.status_code)

async def server_error(request: Request, exc: HTTPException):
    return HTMLResponse(content=HTML_500_PAGE, status_code=exc.status_code)


exception_handlers = {
    404: not_found,
    500: server_error
}

app = Starlette(routes=routes, exception_handlers=exception_handlers)
```

If `debug` is enabled and an error occurs, then instead of using the installed
500 handler, Starlette will respond with a traceback response.

```python
app = Starlette(debug=True, routes=routes, exception_handlers=exception_handlers)
```

As well as registering handlers for specific status codes, you can also
register handlers for classes of exceptions.

In particular you might want to override how the built-in `HTTPException` class
is handled. For example, to use JSON style responses:

```python
async def http_exception(request: Request, exc: HTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

exception_handlers = {
    HTTPException: http_exception
}
```

The `HTTPException` is also equipped with the `headers` argument. Which allows the propagation
of the headers to the response class:

```python
async def http_exception(request: Request, exc: HTTPException):
    return JSONResponse(
        {"detail": exc.detail},
        status_code=exc.status_code,
        headers=exc.headers
    )
```

You might also want to override how `WebSocketException` is handled:

```python
async def websocket_exception(websocket: WebSocket, exc: WebSocketException):
    await websocket.close(code=1008)

exception_handlers = {
    WebSocketException: websocket_exception
}
```

## Errors and handled exceptions

It is important to differentiate between handled exceptions and errors.

Handled exceptions do not represent error cases. They are coerced into appropriate
HTTP responses, which are then sent through the standard middleware stack. By default
the `HTTPException` class is used to manage any handled exceptions.

Errors are any other exception that occurs within the application. These cases
should bubble through the entire middleware stack as exceptions. Any error
logging middleware should ensure that it re-raises the exception all the
way up to the server.

In practical terms, the error handled used is `exception_handler[500]` or `exception_handler[Exception]`.
Both keys `500` and `Exception` can be used. See below:

```python
async def handle_error(request: Request, exc: HTTPException):
    # Perform some logic
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

exception_handlers = {
    Exception: handle_error  # or "500: handle_error"
}
```

It's important to notice that in case a [`BackgroundTask`](https://www.starlette.io/background/) raises an exception,
it will be handled by the `handle_error` function, but at that point, the response was already sent. In other words,
the response created by `handle_error` will be discarded. In case the error happens before the response was sent, then
it will use the response object - in the above example, the returned `JSONResponse`.

In order to deal with this behaviour correctly, the middleware stack of a
`Starlette` application is configured like this:

* `ServerErrorMiddleware` - Returns 500 responses when server errors occur.
* Installed middleware
* `ExceptionMiddleware` - Deals with handled exceptions, and returns responses.
* Router
* Endpoints

## HTTPException

The `HTTPException` class provides a base class that you can use for any handled exceptions.
The `ExceptionMiddleware` implementation defaults to returning plain-text HTTP responses for any `HTTPException`.

* `HTTPException(status_code, detail=None, headers=None)`

You should only raise `HTTPException` inside routing or endpoints.
Middleware classes should instead just return appropriate responses directly.

You can use an `HTTPException` on a WebSocket endpoint. In case it's raised before `websocket.accept()`
the connection is not upgraded to a WebSocket connection, and the proper HTTP response is returned.

```python
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.routing import WebSocketRoute
from starlette.websockets import WebSocket


async def websocket_endpoint(websocket: WebSocket):
    raise HTTPException(status_code=400, detail="Bad request")


app = Starlette(routes=[WebSocketRoute("/ws", websocket_endpoint)])
```

## WebSocketException

You can use the `WebSocketException` class to raise errors inside of WebSocket endpoints.

* `WebSocketException(code=1008, reason=None)`

You can set any code valid as defined [in the specification](https://tools.ietf.org/html/rfc6455#section-7.4.1).
