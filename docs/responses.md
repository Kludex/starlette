
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


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = Response('Hello, world!', media_type='text/plain')
    await response(scope, receive, send)
```
#### Set Cookie

Starlette provides a `set_cookie` method to allow you to set cookies on the response object.

Signature: `Response.set_cookie(key, value, max_age=None, expires=None, path="/", domain=None, secure=False, httponly=False, samesite="lax")`

* `key` - A string that will be the cookie's key.
* `value` - A string that will be the cookie's value.
* `max_age` - An integer that defines the lifetime of the cookie in seconds. A negative integer or a value of `0` will discard the cookie immediately. `Optional`
* `expires` - An integer that defines the number of seconds until the cookie expires. `Optional`
* `path` - A string that specifies the subset of routes to which the cookie will apply. `Optional`
* `domain` - A string that specifies the domain for which the cookie is valid. `Optional`
* `secure` - A bool indicating that the cookie will only be sent to the server if request is made using SSL and the HTTPS protocol. `Optional`
* `httponly` - A bool indicating that the cookie cannot be accessed via Javascript through `Document.cookie` property, the `XMLHttpRequest` or `Request` APIs. `Optional`
* `samesite` - A string that specifies the samesite strategy for the cookie. Valid values are `'lax'`, `'strict'` and `'none'`. Defaults to `'lax'`. `Optional`

#### Delete Cookie

Conversly, Starlette also provides a `delete_cookie` method to manually expire a set cookie.

Signature: `Response.delete_cookie(key, path='/', domain=None)`


### HTMLResponse

Takes some text or bytes and returns an HTML response.

```python
from starlette.responses import HTMLResponse


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = HTMLResponse('<html><body><h1>Hello, world!</h1></body></html>')
    await response(scope, receive, send)
```

### PlainTextResponse

Takes some text or bytes and returns a plain text response.

```python
from starlette.responses import PlainTextResponse


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = PlainTextResponse('Hello, world!')
    await response(scope, receive, send)
```

### JSONResponse

Takes some data and returns an `application/json` encoded response.

```python
from starlette.responses import JSONResponse


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = JSONResponse({'hello': 'world'})
    await response(scope, receive, send)
```

#### Custom JSON serialization

If you need fine-grained control over JSON serialization, you can subclass
`JSONResponse` and override the `render` method.

For example, if you wanted to use a third-party JSON library such as
[orjson](https://pypi.org/project/orjson/):

```python
from typing import Any

import orjson
from starlette.responses import JSONResponse


class OrjsonResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return orjson.dumps(content)
```

In general you *probably* want to stick with `JSONResponse` by default unless
you are micro-optimising a particular endpoint or need to serialize non-standard
object types.

### RedirectResponse

Returns an HTTP redirect. Uses a 307 status code by default.

```python
from starlette.responses import PlainTextResponse, RedirectResponse


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    if scope['path'] != '/':
        response = RedirectResponse(url='/')
    else:
        response = PlainTextResponse('Hello, world!')
    await response(scope, receive, send)
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


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    generator = slow_numbers(1, 10)
    response = StreamingResponse(generator, media_type='text/html')
    await response(scope, receive, send)
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


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = FileResponse('statics/favicon.ico')
    await response(scope, receive, send)
```

## Third party middleware

### [SSEResponse(EventSourceResponse)](https://github.com/sysid/sse-starlette)

Server Sent Response implements the ServerSentEvent Protocol: https://www.w3.org/TR/2009/WD-eventsource-20090421.  
It enables event streaming from the server to the client without the complexity of websockets.
