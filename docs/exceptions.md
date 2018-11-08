
Starlette allows you to install custom exception handlers to deal with
how you return responses when errors or handled exceptions occur.

```python
from starlette.applications import Starlette
from starlette.responses import HTMLResponse


HTML_404_PAGE = ...
HTML_500_PAGE = ...


app = Starlette()


@app.exception_handler(404)
async def not_found(request, exc):
    return HTMLResponse(content=HTML_404_PAGE)

@app.exception_handler(500)
async def server_error(request, exc):
    return HTMLResponse(content=HTML_500_PAGE)
```

If `debug` is enabled and an error occurs, then instead of using the installed
500 handler, Starlette will respond with a traceback response.

```python
app = Starlette(debug=True)
```

As well as registering handlers for specific status codes, you can also
register handlers for classes of exceptions.

In particular you might want to override how the built-in `HTTPException` class
is handled. For example, to use JSON style responses:

```python
@app.exception_handler(HTTPException)
async def http_exception(request, exc):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
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

In order to deal with this behaviour correctly, the middleware stack of a
`Starlette` application is configured like this:

* `ServerErrorMiddleware` - Returns 500 responses when server errors occur.
* Installed middleware
* `ExceptionMiddleware` - Deals with handled exceptions, and returns responses.
* Router
* Endpoints

## HTTPException

The `HTTPException` class provides a base class that you can use for any
handled exceptions. The `ExceptionMiddleware` implementation defaults to
returning plain-text HTTP responses for any `HTTPException`.

* `HTTPException(status_code, detail=None)`

You should only raise `HTTPException` inside routing or endpoints. Middleware
classes should instead just return appropriate responses directly.
