
Starlette includes several middleware classes for adding behavior that is applied across
your entire application. These are all implemented as standard ASGI
middleware classes, and can be applied either to Starlette or to any other ASGI application.

The Starlette application class allows you to include the ASGI middleware
in a way that ensures that it remains wrapped by the exception handler.

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

routes = ...

# Ensure that all requests include an 'example.com' or '*.example.com' host header,
# and strictly enforce https-only access.
middleware = [
  Middleware(TrustedHostMiddleware, allowed_hosts=['example.com', '*.example.com']),
  Middleware(HTTPSRedirectMiddleware)
]

app = Starlette(routes=routes, middleware=middleware)
```

Every Starlette application automatically includes two pieces of middleware
by default:

* `ServerErrorMiddleware` - Ensures that application exceptions may return a custom 500 page, or display an application traceback in DEBUG mode. This is *always* the outermost middleware layer.
* `ExceptionMiddleware` - Adds exception handlers, so that particular types of expected exception cases can be associated with handler functions. For example raising `HTTPException(status_code=404)` within an endpoint will end up rendering a custom 404 page.

Middleware is evaluated from top-to-bottom, so the flow of execution in our example
application would look like this:

* Middleware
    * `ServerErrorMiddleware`
    * `TrustedHostMiddleware`
    * `HTTPSRedirectMiddleware`
    * `ExceptionMiddleware`
* Routing
* Endpoint

The following middleware implementations are available in the Starlette package:

## CORSMiddleware

Adds appropriate [CORS headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS) to outgoing responses in order to allow cross-origin requests from browsers.

The default parameters used by the CORSMiddleware implementation are restrictive by default,
so you'll need to explicitly enable particular origins, methods, or headers, in order
for browsers to be permitted to use them in a Cross-Domain context.

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

routes = ...

middleware = [
    Middleware(CORSMiddleware, allow_origins=['*'])
]

app = Starlette(routes=routes, middleware=middleware)
```

The following arguments are supported:

* `allow_origins` - A list of origins that should be permitted to make cross-origin requests. eg. `['https://example.org', 'https://www.example.org']`. You can use `['*']` to allow any origin.
* `allow_origin_regex` - A regex string to match against origins that should be permitted to make cross-origin requests. eg. `'https://.*\.example\.org'`.
* `allow_methods` - A list of HTTP methods that should be allowed for cross-origin requests. Defaults to `['GET']`. You can use `['*']` to allow all standard methods.
* `allow_headers` - A list of HTTP request headers that should be supported for cross-origin requests. Defaults to `[]`. You can use `['*']` to allow all headers. The `Accept`, `Accept-Language`, `Content-Language` and `Content-Type` headers are always allowed for CORS requests.
* `allow_credentials` - Indicate that cookies should be supported for cross-origin requests. Defaults to `False`.
* `expose_headers` - Indicate any response headers that should be made accessible to the browser. Defaults to `[]`.
* `max_age` - Sets a maximum time in seconds for browsers to cache CORS responses. Defaults to `600`.

The middleware responds to two particular types of HTTP request...

#### CORS preflight requests

These are any `OPTIONS` request with `Origin` and `Access-Control-Request-Method` headers.
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
* `max_age` - Session expiry time in seconds. Defaults to 2 weeks. If set to `None` then the cookie will last as long as the browser session.
* `same_site` - SameSite flag prevents the browser from sending session cookie along with cross-site requests. Defaults to `'lax'`.
* `https_only` - Indicate that Secure flag should be set (can be used with HTTPS only). Defaults to `False`.

## HTTPSRedirectMiddleware

Enforces that all incoming requests must either be `https` or `wss`. Any incoming
requests to `http` or `ws` will be redirected to the secure scheme instead.

```python
from starlette.applications import Starlette
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware

routes = ...

middleware = [
    Middleware(HTTPSRedirectMiddleware)
]

app = Starlette(routes=routes, middleware=middleware)
```

There are no configuration options for this middleware class.

## TrustedHostMiddleware

Enforces that all incoming requests have a correctly set `Host` header, in order
to guard against HTTP Host Header attacks.

```python
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

routes = ...

middleware = [
    Middleware(TrustedHostMiddleware, allowed_hosts=['example.com', '*.example.com'])
]

app = Starlette(routes=routes, middleware=middleware)
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
from starlette.middleware import Middleware
from starlette.middleware.gzip import GZipMiddleware


routes = ...

middleware = [
    Middleware(GZipMiddleware, minimum_size=1000)
]

app = Starlette(routes=routes, middleware=middleware)
```

The following arguments are supported:

* `minimum_size` - Do not GZip responses that are smaller than this minimum size in bytes. Defaults to `500`.

## BaseHTTPMiddleware

An abstract class that allows you to write ASGI middleware against a request/response
interface, rather than dealing with ASGI messages directly.

To implement a middleware class using `BaseHTTPMiddleware`, you must override the
`async def dispatch(request, call_next)` method.

```python
from starlette.middleware.base import BaseHTTPMiddleware

class CustomHeaderMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Custom'] = 'Example'
        return response

middleware = [
    Middleware(CustomHeaderMiddleware)
]

app = Starlette(routes=routes, middleware=middleware)
```

If you want to provide configuration options to the middleware class you should
override the `__init__` method, ensuring that the first argument is `app`, and
any remaining arguments are optional keyword arguments. Make sure to set the `app`
attribute on the instance if you do this.

```python
class CustomHeaderMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, header_value='Example'):
        super().__init__(app)
        self.header_value = header_value

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Custom'] = self.header_value
        return response


middleware = [
    Middleware(CustomHeaderMiddleware, header_value='Customized')
]

app = Starlette(routes=routes, middleware=middleware)
```

Middleware classes should not modify their state outside of the `__init__` method.
Instead you should keep any state local to the `dispatch` method, or pass it
around explicitly, rather than mutating the middleware instance.

!!! bug
    Currently, the `BaseHTTPMiddleware` has some known issues:

    - It's not possible to use `BackgroundTasks` with `BaseHTTPMiddleware`. Check [#1438](https://github.com/encode/starlette/issues/1438) for more details.
    - Using `BaseHTTPMiddleware` will prevent changes to [`contextlib.ContextVar`](https://docs.python.org/3/library/contextvars.html#contextvars.ContextVar)s from propagating upwards. That is, if you set a value for a `ContextVar` in your endpoint and try to read it from a middleware you will find that the value is not the same value you set in your endpoint (see [this test](https://github.com/encode/starlette/blob/621abc747a6604825190b93467918a0ec6456a24/tests/middleware/test_base.py#L192-L223) for an example of this behavior).

## Pure ASGI Middleware

Thanks to how ASGI was designed, it is possible to implement middleware as a chain of ASGI applications, where each application calls into the next one.
Each element of the chain is an [`ASGI`](https://asgi.readthedocs.io/en/latest/) application by itself, which per definition, is also a middleware.

This is also an alternative approach in case the limitations of `BaseHTTPMiddleware` are a problem.

### Guiding principles

The most common way to create an ASGI middleware is with a class.

```python
class ASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)
```

The middleware above is the most basic ASGI middleware. It receives an ASGI application as an argument for its constructor, and implements the `async __call__` method. This method should accept `scope`, which contains information about the current connection, and `receive` and `send` which allow to exchange ASGI event messages with the ASGI server (learn more in the [ASGI specification](https://asgi.readthedocs.io/en/latest/specs/index.html)).

As an alternative for the class approach, you can also use a function:

```python
import functools

def asgi_middleware():
    def asgi_decorator(app):
        @functools.wraps(app)
        async def wrapped_app(scope, receive, send):
            await app(scope, receive, send)
        return wrapped_app
    return asgi_decorator
```

!!! info
    The function pattern is not commonly spread, but you can check a more advanced implementation of it on
    [asgi-cors](https://github.com/simonw/asgi-cors/blob/10ef64bfcc6cd8d16f3014077f20a0fb8544ec39/asgi_cors.py).

#### `Scope` types

As we mentioned, the scope holds the information about the connection. There are three types of `scope`s:

- [`lifespan`](https://asgi.readthedocs.io/en/latest/specs/lifespan.html#scope) is a special type of scope that is used for the lifespan of the ASGI application.
- [`http`](https://asgi.readthedocs.io/en/latest/specs/www.html#http-connection-scope) is a type of scope that is used for HTTP requests.
- [`websocket`](https://asgi.readthedocs.io/en/latest/specs/www.html#websocket-connection-scope) is a type of scope that is used for WebSocket connections.

If you want to create a middleware that only runs on HTTP requests, you'd write something like:

```python
class ASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # Do something here!
        await self.app(scope, receive, send)
```
In the example above, if the `scope` type is **not** `http`, meaning that is either `lifespan` or `websocket`, we'll directly call the `self.app`.

The same applies to other scopes.

!!! tip
    Middleware classes should be stateless -- see [Per-request state](#per-request-state) if you do need to store per-request state.

#### Wrapping `send` and `receive`

A common pattern, that you'll probably need to use is to wrap the `send` or `receive` callables.

For example, here's how we could write a middleware that logs the response status code, which we'd obtain
by wrapping the `send` with the `send_wrapper` callable:

```python
class LogStatusCodeMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        status_code = 500

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        await self.app(scope, receive, send_wrapper)

        print("This is a primitive access log")
        print(f"status = {status_code}")
```

!!! info
    You can check a more advanced implementation of the same rationale on [asgi-logger](https://github.com/Kludex/asgi-logger/blob/main/asgi_logger/middleware.py).

#### Type annotations

There are two ways of annotating a middleware: using Starlette itself or [`asgiref`](https://github.com/django/asgiref).

Using Starlette, you can do as:

```python
from starlette.types import ASGIApp, Message, Scope, Receive, Send


class ASGIMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_wrapper(message: Message) -> None:
            # ... Do something
            await send(message)

        await self.app(scope, receive, send_wrapper)
```

Although this is easy, you may prefer to be more strict. In which case, you'd need to use `asgiref`:

```python
from asgiref.typing import ASGI3Application, Scope, ASGISendCallable
from asgiref.typing import ASGIReceiveEvent, ASGISendEvent


class ASGIMiddleware:
    def __init__(self, app: ASGI3Application) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable) -> None:
        if scope["type"] == "http":
            async def send_wrapper(message: ASGISendEvent) -> None:
                await send(message)
            return await self.app(scope, receive, send_wrapper)
        await self.app(scope, receive, send)
```

!!! info
    If you're curious about the `ASGI3Application` type on the snippet above, you can read more about ASGI versions on the [Legacy Applications section on the ASGI
    documentation](https://asgi.readthedocs.io/en/latest/specs/main.html#legacy-applications).

### Reusing Starlette components

If you need to work with request or response data, you may find it more convenient to reuse Starlette data structures ([`Request`](requests.md#request), [`Headers`](requests.md#headers), [`QueryParams`](requests.md#query-parameters), [`URL`](requests.md#url), etc) rather than work with raw ASGI data. All these components can be built from the ASGI `scope`, `receive` and `send`, allowing you to work on pure ASGI middleware at a higher level of abstraction.

For example, we can create a `Request` object, and work with it.
```python
from starlette.requests import Request

class ASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            request = Request(scope, receive, send)
            # Do something here!
        await self.app(scope, receive, send)
```

Or we might use `MutableHeaders` to change the response headers:

```python
from starlette.datastructures import MutableHeaders

class ExtraResponseHeadersMiddleware:
    def __init__(self, app, headers):
        self.app = app
        self.headers = headers

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def wrapped_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in self.headers:
                    headers.append(key, value)
            await send(message)

        await self.app(scope, receive, wrapped_send)
```

### Per-request state

ASGI middleware classes should be stateless, as we typically don't want to leak state across requests.

The risk is low when defining wrappers inside `__call__`, as state would typically be defined as inline variables.

But if the middleware grows larger and more complex, you might be tempted to refactor wrappers as methods. Still, state should not be stored in the middleware instance. This means that the middleware should not have attributes that would change across requests or connections. If the middleware has an attribute, for example set in the `__init__()` method, nothing else should change it afterwards. Instead, if you need to manipulate per-request state, you may write a separate `Responder` class:

```python
from functools import partial

from starlette.datastructures import Headers

class TweakMiddleware:
    """
    Make a change to the response body if 'X-Tweak' is
    present in the response headers.
    """

    async def __call_(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        responder = TweakResponder(self.app)
        await responder(scope, receive, send)

class TweakResponder:
    def __init__(self, app):
        self.app = app
        self.should_tweak = False

    async def __call__(self, scope, receive, send):
        send = partial(self.maybe_send_with_tweaks, send=send)
        await self.app(scope, receive, send)

    async def maybe_send_with_tweaks(self, message, send):
        if message["type"] == "http.response.start":
            headers = Headers(raw=message["headers"])
            self.should_tweak = headers.get("X-Tweak") == "1"
            await send(message)
            return

        if message["type"] == "http.response.body":
            if not self.should_tweak:
                await send(message)
                return

            # Actually tweak the response body...
```

See also [`GZipMiddleware`](https://github.com/encode/starlette/blob/9ef1b91c9c043197da6c3f38aa153fd874b95527/starlette/middleware/gzip.py) for a full example of this pattern.

### Storing context in `scope`

As we know by now, the `scope` holds the information about the connection.

As per the ASGI specifications, any application can store custom information on the `scope`.
Have in mind that other components could also store data in the same `scope`, so it's important to use a key that has a low chance of being used by other things.

For example, if you are building an application called `super-app` you could have that as a prefix for any keys you put in the `scope`, and then you could have a key called `super-app-transaction-id`.

```python
from uuid import uuid4


class ASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        scope["super-app-transaction-id"] = uuid4()
        await self.app(scope, receive, send)
```
On the example above, we stored a key called "super-app-transaction-id" in the scope. That can be used by the application itself, as the scope is forwarded to it.

!!! important
    This documentation should be enough to have a good basis on how to create an ASGI middleware.
    Nonetheless, there are great articles about the subject:

    - [Introduction to ASGI: Emergence of an Async Python Web Ecosystem](https://florimond.dev/en/posts/2019/08/introduction-to-asgi-async-python-web/)
    - [How to write ASGI middleware](https://pgjones.dev/blog/how-to-write-asgi-middleware-2021/)

## Using middleware in other frameworks

To wrap ASGI middleware around other ASGI applications, you should use the
more general pattern of wrapping the application instance:

```python
app = TrustedHostMiddleware(app, allowed_hosts=['example.com'])
```

You can do this with a Starlette application instance too, but it is preferable
to use the `middleware=<List of Middleware instances>` style, as it will:

* Ensure that everything remains wrapped in a single outermost `ServerErrorMiddleware`.
* Preserves the top-level `app` instance.

## Third party middleware

#### [asgi-auth-github](https://github.com/simonw/asgi-auth-github)

This middleware adds authentication to any ASGI application, requiring users to sign in
using their GitHub account (via [OAuth](https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/)).
Access can be restricted to specific users or to members of specific GitHub organizations or teams.

#### [asgi-csrf](https://github.com/simonw/asgi-csrf)

Middleware for protecting against CSRF attacks. This middleware implements the Double Submit Cookie pattern, where a cookie is set, then it is compared to a csrftoken hidden form field or an `x-csrftoken` HTTP header.

#### [AuthlibMiddleware](https://github.com/aogier/starlette-authlib)

A drop-in replacement for Starlette session middleware, using [authlib's jwt](https://docs.authlib.org/en/latest/jose/jwt.html)
module.

#### [BugsnagMiddleware](https://github.com/ashinabraham/starlette-bugsnag)

A middleware class for logging exceptions to [Bugsnag](https://www.bugsnag.com/).

#### [CSRFMiddleware](https://github.com/frankie567/starlette-csrf)

Middleware for protecting against CSRF attacks. This middleware implements the Double Submit Cookie pattern, where a cookie is set, then it is compared to an `x-csrftoken` HTTP header.

#### [EarlyDataMiddleware](https://github.com/HarrySky/starlette-early-data)

Middleware and decorator for detecting and denying [TLSv1.3 early data](https://tools.ietf.org/html/rfc8470) requests.

#### [PrometheusMiddleware](https://github.com/perdy/starlette-prometheus)

A middleware class for capturing Prometheus metrics related to requests and responses, including in progress requests, timing...

#### [ProxyHeadersMiddleware](https://github.com/encode/uvicorn/blob/master/uvicorn/middleware/proxy_headers.py)

Uvicorn includes a middleware class for determining the client IP address,
when proxy servers are being used, based on the `X-Forwarded-Proto` and `X-Forwarded-For` headers. For more complex proxy configurations, you might want to adapt this middleware.

#### [RateLimitMiddleware](https://github.com/abersheeran/asgi-ratelimit)

A rate limit middleware. Regular expression matches url; flexible rules; highly customizable. Very easy to use.

#### [RequestIdMiddleware](https://github.com/snok/asgi-correlation-id)

A middleware class for reading/generating request IDs and attaching them to application logs.

#### [RollbarMiddleware](https://docs.rollbar.com/docs/starlette)

A middleware class for logging exceptions, errors, and log messages to [Rollbar](https://www.rollbar.com).

#### [SentryMiddleware](https://github.com/encode/sentry-asgi)

A middleware class for logging exceptions to [Sentry](https://sentry.io/).

#### [StarletteOpentracing](https://github.com/acidjunk/starlette-opentracing)

A middleware class that emits tracing info to [OpenTracing.io](https://opentracing.io/) compatible tracers and
can be used to profile and monitor distributed applications.

#### [TimingMiddleware](https://github.com/steinnes/timing-asgi)

A middleware class to emit timing information (cpu and wall time) for each request which
passes through it.  Includes examples for how to emit these timings as statsd metrics.

#### [WSGIMiddleware](https://github.com/abersheeran/a2wsgi)

A middleware class in charge of converting a WSGI application into an ASGI one.
