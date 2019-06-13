
Starlette includes a few response classes that handle sending back the
appropriate ASGI messages on the `send` channel.

### Response

Signature: `Response(content, status_code=200, headers=None, media_type=None)`

* `content` - A string or bytestring.
* `status_code` - An integer HTTP status code.
* `headers` - A dictionary of strings.
* `media_type` - A string giving the media type. eg. "text/html"

Starlette will automatically include a Content-Length header. It will also
include a Content-Type header, based on the media_type and appending a charset
for text types.

Once you've instantiated a response, you can send it by calling it as an
ASGI application instance.

```python
from starlette.responses import Response


class App:
    def __init__(self, scope):
        assert scope['type'] == 'http'
        self.scope = scope

    async def __call__(self, receive, send):
        response = Response('Hello, world!', media_type='text/plain')
        await response(self.scope, receive, send)
```
#### Set Cookie

Starlette provides a `set_cookie` method to allow you to set cookies on the response object.

Signature: `Response.set_cookie(key, value, max_age=None, expires=None, path="/", domain=None, secure=False, httponly=False)`

* `key` - A string that will be the cookie's key.
* `value` - A string that will be the cookie's value.
* `max_age` - An integer that defines the lifetime of the cookie in seconds. A negative integer or a value of `0` will discard the cookie immediately. `Optional`
* `expires` - An integer that defines the number of seconds until the cookie expires. `Optional`
* `path` - A string that specifies the subset of routes to which the cookie will apply. `Optional`
* `domain` - A string that specifies the domain for which the cookie is valid. `Optional`
* `secure` - A bool indicating that the cookie will only be sent to the server if request is made using SSL and the HTTPS protocol. `Optional`
* `httponly` - A bool indicating that the cookie cannot be accessed via Javascript through `Document.cookie` property, the `XMLHttpRequest` or `Request` APIs. `Optional`

#### Delete Cookie

Conversly, Starlette also provides a `delete_cookie` method to manually expire a set cookie.

Signature: `Response.delete_cookie(key, path='/', domain=None)`


### HTMLResponse

Takes some text or bytes and returns an HTML response.

```python
from starlette.responses import HTMLResponse


class App:
    def __init__(self, scope):
        assert scope['type'] == 'http'
        self.scope = scope

    async def __call__(self, receive, send):
        response = HTMLResponse('<html><body><h1>Hello, world!</h1></body></html>')
        await response(self.scope, receive, send)
```

### PlainTextResponse

Takes some text or bytes and returns an plain text response.

```python
from starlette.responses import PlainTextResponse


class App:
    def __init__(self, scope):
        assert scope['type'] == 'http'
        self.scope = scope

    async def __call__(self, receive, send):
        response = PlainTextResponse('Hello, world!')
        await response(self.scope, receive, send)
```

### JSONResponse

Takes some data and returns an `application/json` encoded response.

```python
from starlette.responses import JSONResponse


class App:
    def __init__(self, scope):
        assert scope['type'] == 'http'
        self.scope = scope

    async def __call__(self, receive, send):
        response = JSONResponse({'hello': 'world'})
        await response(self.scope, receive, send)
```

### UJSONResponse

A JSON response class that uses the optimised `ujson` library for serialisation.

Using `ujson` will result in faster JSON serialisation, but is also less careful
than Python's built-in implementation in how it handles some edge-cases.

In general you *probably* want to stick with `JSONResponse` by default unless
you are micro-optimising a particular endpoint.

```python
from starlette.responses import UJSONResponse


class App:
    def __init__(self, scope):
        assert scope['type'] == 'http'
        self.scope = scope

    async def __call__(self, receive, send):
        response = UJSONResponse({'hello': 'world'})
        await response(self.scope, receive, send)
```

### RedirectResponse

Returns an HTTP redirect. Uses a 302 status code by default.

```python
from starlette.responses import PlainTextResponse, RedirectResponse


class App:
    def __init__(self, scope):
        assert scope['type'] == 'http'
        self.scope = scope

    async def __call__(self, receive, send):
        if self.scope['path'] != '/':
            response = RedirectResponse(url='/')
        else:
            response = PlainTextResponse('Hello, world!')
        await response(self.scope, receive, send)
```

### StreamingResponse

Takes an async generator or a normal generator/iterator and streams the response body.

```python
from starlette.responses import StreamingResponse
import asyncio


async def slow_numbers(minimum, maximum):
    yield('<html><body><ul>')
    for number in range(minimum, maximum + 1):
        yield '<li>%d</li>' % number
        await asyncio.sleep(0.5)
    yield('</ul></body></html>')


class App:
    def __init__(self, scope):
        assert scope['type'] == 'http'
        self.scope = scope

    async def __call__(self, receive, send):
        generator = slow_numbers(1, 10)
        response = StreamingResponse(generator, media_type='text/html')
        await response(self.scope, receive, send)
```

Have in mind that <a href="https://docs.python.org/3/glossary.html#term-file-like-object" target="_blank">file-like</a> objects (like those created by `open()`) are normal iterators. So, you can return them directly in a `StreamingResponse`.

### FileResponse

Asynchronously streams a file as the response.

Takes a different set of arguments to instantiate than the other response types:

* `path` - The filepath to the file to stream.
* `headers` - Any custom headers to include, as a dictionary.
* `media_type` - A string giving the media type. If unset, the filename or path will be used to infer a media type.
* `filename` - If set, this will be included in the response `Content-Disposition`.

File responses will include appropriate `Content-Length`, `Last-Modified` and `ETag` headers.

```python
from starlette.responses import FileResponse


class App:
    def __init__(self, scope):
        assert scope['type'] == 'http'
        self.scope = scope

    async def __call__(self, receive, send):
        response = FileResponse('statics/favicon.ico')
        await response(self.scope, receive, send)
```
