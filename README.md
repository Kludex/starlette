<p align="center">
  <img width="320" height="192" src="https://raw.githubusercontent.com/encode/starlette/master/docs/starlette.png" alt='starlette'>
</p>
<p align="center">
    <em>✨ The little ASGI library that shines. ✨</em>
</p>
<p align="center">
<a href="https://travis-ci.org/encode/starlette">
    <img src="https://travis-ci.org/encode/starlette.svg?branch=master" alt="Build Status">
</a>
<a href="https://codecov.io/gh/encode/starlette">
    <img src="https://codecov.io/gh/encode/starlette/branch/master/graph/badge.svg" alt="Coverage">
</a>
<a href="https://pypi.org/project/starlette/">
    <img src="https://badge.fury.io/py/starlette.svg" alt="Package version">
</a>
</p>

---

Starlette is a small library for working with [ASGI](https://asgi.readthedocs.io/en/latest/).

It gives you `Request` and `Response` classes, request routing, a test client, and a
decorator for writing super-minimal applications.

**Requirements:**

Python 3.6+

**Installation:**

```shell
pip3 install starlette
```

**Example:**

```python
from starlette import Response


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        response = Response('Hello, world!', media_type='text/plain')
        await response(receive, send)
```

You can run the application with any ASGI server, including [uvicorn](http://www.uvicorn.org/), [daphne](https://github.com/django/daphne/), or [hypercorn](https://pgjones.gitlab.io/hypercorn/).

<p align="center">&mdash; ⭐️ &mdash;</p>

## Responses

Starlette includes a few response classes that handle sending back the
appropriate ASGI messages on the `send` channel.

### Response

Signature: `Response(content=b'', status_code=200, headers=None, media_type=None)`

* `content` - A string or bytestring.
* `status_code` - An integer HTTP status code.
* `headers` - A dictionary of strings or list of pairs of strings.
* `media_type` - A string giving the content type.

Starlette will automatically include a content-length header. It will also
set the content-type header, including a charset for text types.

Once you've instantiated a response, you can send it by calling it as an
ASGI application instance.

```python
class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        response = Response('Hello, world!', media_type='text/plain')
        await response(receive, send)
```

### HTMLResponse

Takes some text or bytes and returns an HTML response.

```python
from starlette import HTMLResponse


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        response = HTMLResponse('<html><body><h1>Hello, world!</h1></body></html')
        await response(receive, send)
```

### JSONResponse

Takes some data and returns an `application/json` encoded response.

```python
from starlette import JSONResponse


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        response = JSONResponse({'hello': 'world'})
        await response(receive, send)
```

### StreamingResponse

Takes an async generator and streams the response body.

```python
from starlette import Request, StreamingResponse
import asyncio


async def slow_numbers(minimum, maximum):
    yield('<html><body><ul>')
    for number in range(minimum, maximum + 1):
        yield '<li>%d</li>' % number
        await asyncio.sleep(0.5)
    yield('</ul></body></html>')


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        generator = slow_numbers(1, 10)
        response = StreamingResponse(generator, media_type='text/html')
        await response(receive, send)
```

---

## Requests

Starlette includes a `Request` class that gives you a nicer interface onto
the incoming request, rather than accessing the ASGI scope and receive channel directly.

### Request

Signature: `Request(scope, receive=None)`

```python
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

The property is actually a subclass of `str`, and also exposes all the
components that can be parsed out of the URL.

For example: `request.url.path`, `request.url.port`, `request.url.scheme`.

#### Headers

Headers are exposed as an immutable, case-insensitive, multi-dict.

For example: `request.headers['content-type']`

#### Query Parameters

Headers are exposed as an immutable multi-dict.

For example: `request.query_params['abc']`

#### Body

There are a few different interfaces for returning the body of the request:

The request body as bytes: `await request.body()`

The request body, parsed as JSON: `await request.json()`

You can also access the request body as a stream, using the `async for` syntax:

```python
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
the entire body to memory. Any subsequent calls to `.body()` and `.json()` will
raise an error.

---

## Routing

Starlette includes a `Router` class which is an ASGI application that
dispatches to other ASGI applications.

```python
from starlette import Router, Path, PathPrefix
from myproject import Homepage, StaticFiles


app = Router([
    Path('/', app=Homepage, methods=['GET']),
    PathPrefix('/static', app=StaticFiles, methods=['GET'])
])
```

Paths can use URI templating style to capture path components.

```python
Path('/users/{username}', app=User, methods=['GET'])
```

Path components are made available in the scope, as `scope["kwargs"]`.

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

---

## Test Client

The test client allows you to make requests against your ASGI application,
using the `requests` library.

```python
from starlette import HTMLResponse, TestClient


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        response = HTMLResponse('<html><body>Hello, world!</body></html>')
        await response(receive, send)


def test_app():
    client = TestClient(App)
    response = client.get('/')
    assert response.status_code == 200
```

---

## Decorators

The `asgi_application` decorator takes a request/response function and turns
it into an ASGI application.

The function must take a single `request` argument, and return a response.

The decorator can be applied to either `async` functions, or to standard
functions.

```python
from starlette import asgi_application, HTMLResponse


@asgi_application
async def app(request):
    return HTMLResponse('<html><body>Hello, world!</body></html>')
```

---

<p align="center"><i>Starlette is <a href="https://github.com/tomchristie/starlette/blob/master/LICENSE.md">BSD licensed</a> code.<br/>Designed & built in Brighton, England.</i><br/>&mdash; ⭐️ &mdash;</p>
