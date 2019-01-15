
Starlette includes a `Request` class that gives you a nicer interface onto
the incoming request, rather than accessing the ASGI scope and receive channel directly.

### Request

Signature: `Request(scope, receive=None)`

```python
from starlette.requests import Request
from starlette.response import Response


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        request = Request(self.scope, receive)
        content = '%s %s' % (request.method, request.url.path)
        response = Response(content, media_type='text/plain')
        await response(receive, send)
```

Requests present a mapping interface, so you can use them in the same
way as a `scope`.

For instance: `request['path']` will return the ASGI path.

If you don't need to access the request body you can instantiate a request
without providing an argument to `receive`.

#### Method

The request method is accessed as `request.method`.

#### URL

The request URL is accessed as `request.url`.

The property is a string-like object that exposes all the
components that can be parsed out of the URL.

For example: `request.url.path`, `request.url.port`, `request.url.scheme`.

#### Headers

Headers are exposed as an immutable, case-insensitive, multi-dict.

For example: `request.headers['content-type']`

#### Query Parameters

Headers are exposed as an immutable multi-dict.

For example: `request.query_params['search']`

#### Path Parameters

Router path parameters are exposed as a dictionary interface.

For example: `request.path_params['username']`

#### Client Address

The client's remote address is exposed as a named two-tuple `request.client`.
Either item in the tuple may be `None`.

The hostname or IP address: `request.client.host`

The port number from which the client is connecting: `request.client.port`

#### Cookies

Cookies are exposed as a regular dictionary interface.

For example: `request.cookies.get('mycookie')`

#### Body

There are a few different interfaces for returning the body of the request:

The request body as bytes: `await request.body()`

The request body, parsed as form data or multipart: `await request.form()`

The request body, parsed as JSON: `await request.json()`

You can also access the request body as a stream, using the `async for` syntax:

```python
from starlette.requests import Request
from starlette.responses import Response


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        request = Request(self.scope, receive)
        body = b''
        async for chunk in request.stream():
            body += chunk
        response = Response(body, media_type='text/plain')
        await response(receive, send)
```

If you access `.stream()` then the byte chunks are provided without storing
the entire body to memory. Any subsequent calls to `.body()`, `.form()`, or `.json()`
will raise an error.

In some cases such as long-polling, or streaming responses you might need to
determine if the client has dropped the connection. You can determine this
state with `disconnected = await request.is_disconnected()`.
