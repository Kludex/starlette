
Starlette includes several middleware classes for adding behaviour that is applied across your entire application. These are all implemented as standard ASGI
middleware classes, and can be applied either to Starlette or to any other ASGI application.

The Starlette application class allows you to include the ASGI middleware
in a way that ensures that it remains wrapped by the exception handler.

```python
from starlette.applications import Starlette
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware


app = Starlette()

# Ensure that all requests include an 'example.com' or '*.example.com' host header,
# and strictly enforce https-only access.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['example.com', '*.example.com'])
app.add_middleware(HTTPSRedirectMiddleware)
```

Starlette also allows you to add middleware functions, using a decorator syntax:

```python
@app.middleware("http")
async def add_custom_header(request, call_next):
    response = await call_next(request)
    response.headers['Custom'] = 'Example'
    return response
```

The following middleware implementations are available in the Starlette package:

## CORSMiddleware

Adds appropriate [CORS headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) to outgoing responses in order to allow cross-origin requests from browsers.

The default parameters used by the CORSMiddleware implementation are restrictive by default,
so you'll need to explicitly enable particular origins, methods, or headers, in order
for browsers to be permitted to use them in a Cross-Domain context.

```python
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware


app = Starlette()
app.add_middleware(CORSMiddleware, allow_origins=['*'])
```

The following arguments are supported:

* `allow_origins` - A list of origins that should be permitted to make cross-origin requests. eg. `['https://example.org', 'https://www.example.org']`. You can use `['*']` to allow any origin.
* `allow_origin_regex` - A regex string to match against origins that should be permitted to make cross-origin requests. eg. `'https://.*\.example\.org'`.
* `allow_methods` - A list of HTTP methods that should be allowed for cross-origin requests. Defaults to `['GET']`. You can use `['*']` to allow all standard methods.
* `allow_headers` - A list of HTTP request headers that should be supported for cross-origin requests. Defaults to `[]`. You can use `['*']` to allow all headers. The `Accept`, `Accept-Language`, `Content-Language` and `Content-Type` headers are always allowed for CORS requests.
* `allow_credentials` - Indicate that cookies should be supported for cross-origin requests. Defaults to `False`.
* `expose_headers` - Indicate any response headers that should be made accessible to the browser. Defaults to `[]`.
* `max_age` - Sets a maximum time in seconds for browsers to cache CORS responses. Defaults to `60`.

The middleware responds to two particular types of HTTP request...

#### CORS preflight requests

These are any `OPTION` request with `Origin` and `Access-Control-Request-Method` headers.
In this case the middleware will intercept the incoming request and respond with
appropriate CORS headers, and either a 200 or 400 response for informational purposes.

#### Simple requests

Any request with an `Origin` header. In this case the middleware will pass the
request through as normal, but will include appropriate CORS headers on the response.

## SessionMiddleware

Adds signed cookie-based HTTP sessions. Session information is readable but not modifiable.

Access or modify the session data using the `request.session` dictionary interface.

The following arguments are supported:

* `secret_key` - Should be a random string.
* `session_cookie` - Defaults to "session".

## HTTPSRedirectMiddleware

Enforces that all incoming requests must either be `https` or `wss`. Any incoming
requests to `http` or `ws` will be redirected to the secure scheme instead.

```python
from starlette.applications import Starlette
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware


app = Starlette()
app.add_middleware(HTTPSRedirectMiddleware)
```

There are no configuration options for this middleware class.

## TrustedHostMiddleware

Enforces that all incoming requests have a correctly set `Host` header, in order
to guard against HTTP Host Header attacks.

```python
from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware


app = Starlette()
app.add_middleware(TrustedHostMiddleware, allowed_hosts=['example.com', '*.example.com'])
```

The following arguments are supported:

* `allowed_hosts` - A list of domain names that should be allowed as hostnames. Wildcard
domains such as `*.example.com` are supported for matching subdomains. To allow any
hostname either use `allowed_hosts=["*"]` or omit the middleware.

If an incoming request does not validate correctly then a 400 response will be sent.

## GZipMiddleware

Handles GZip responses for any request that includes `"gzip"` in the `Accept-Encoding` header.

The middleware will handle both standard and streaming responses.

```python
from starlette.applications import Starlette
from starlette.middleware.gzip import GZipMiddleware


app = Starlette()
app.add_middleware(GZipMiddleware, minimum_size=1000)
```

The following arguments are supported:

* `minimum_size` - Do not GZip responses that are smaller than this minimum size in bytes. Defaults to `500`.

## Using ASGI middleware without Starlette

To wrap ASGI middleware around other ASGI applications, you should use the
more general pattern of wrapping the application instance:

```python
app = TrustedHostMiddleware(app, allowed_hosts=['example.com'])
```

You can do this with a Starlette application instance too, but it is preferable
to use `.add_middleware`, as it'll ensure that you don't lose the reference
to the application object, and that the exception handling always wraps around
any other behaviour.

## BaseHTTPMiddleware

An abstract class that allows you to write ASGI middleware against a request/response
interface, rather than dealing with ASGI messages directly.

To implement a middleware class using `BaseHTTPMiddleware`, you must override the
`async def dispatch(request, call_next)` method.

```python
class CustomHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Custom'] = 'Example'
        return response


app = Starlette()
app.add_middleware(CustomHeaderMiddleware)
```

If you want to provide configuration options to the middleware class you should
override the `__init__` method, ensuring that the first argument is `app`, and
any remaining arguments are optional keyword arguments. Make sure to set the `app`
attribute on the class if you do this.

```python
class CustomHeaderMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, header_value='Example'):
        self.app = app
        self.header_value

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Custom'] = self.header_value
        return response


app = Starlette()
app.add_middleware(CustomHeaderMiddleware, header_value='Customized')
```

Middleware classes should not modify their state outside of the `__init__` method.
Instead you should keep any state local to the `dispatch` method, or pass it
around explicitly, rather than mutating the middleware instance.
