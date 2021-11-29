
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
* `max_age` - Session expiry time in seconds. Defaults to 2 weeks.
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

#### [SentryMiddleware](https://github.com/encode/sentry-asgi)

A middleware class for logging exceptions to [Sentry](https://sentry.io/).

#### [ProxyHeadersMiddleware](https://github.com/encode/uvicorn/blob/master/uvicorn/middleware/proxy_headers.py)

Uvicorn includes a middleware class for determining the client IP address,
when proxy servers are being used, based on the `X-Forwarded-Proto` and `X-Forwarded-For` headers. For more complex proxy configurations, you might want to adapt this middleware.

#### [TimingMiddleware](https://github.com/steinnes/timing-asgi)

A middleware class to emit timing information (cpu and wall time) for each request which
passes through it.  Includes examples for how to emit these timings as statsd metrics.

#### [asgi-auth-github](https://github.com/simonw/asgi-auth-github)

This middleware adds authentication to any ASGI application, requiring users to sign in
using their GitHub account (via [OAuth](https://developer.github.com/apps/building-oauth-apps/authorizing-oauth-apps/)).
Access can be restricted to specific users or to members of specific GitHub organizations or teams.

#### [PrometheusMiddleware](https://github.com/perdy/starlette-prometheus)

A middleware class for capturing Prometheus metrics related to requests and responses, including in progress requests, timing...

#### [BugsnagMiddleware](https://github.com/ashinabraham/starlette-bugsnag)

A middleware class for logging exceptions to [Bugsnag](https://www.bugsnag.com/).

#### [EarlyDataMiddleware](https://github.com/HarrySky/starlette-early-data)

Middleware and decorator for detecting and denying [TLSv1.3 early data](https://tools.ietf.org/html/rfc8470) requests.

#### [AuthlibMiddleware](https://github.com/aogier/starlette-authlib)

A drop-in replacement for Starlette session middleware, using [authlib's jwt](https://docs.authlib.org/en/latest/jose/jwt.html)
module.

#### [StarletteOpentracing](https://github.com/acidjunk/starlette-opentracing)

A middleware class that emits tracing info to [OpenTracing.io](https://opentracing.io/) compatible tracers and
can be used to profile and monitor distributed applications.

#### [RateLimitMiddleware](https://github.com/abersheeran/asgi-ratelimit)

A rate limit middleware. Regular expression matches url; flexible rules; highly customizable. Very easy to use.

#### [RollbarMiddleware](https://docs.rollbar.com/docs/starlette)

A middleware class for logging exceptions, errors, and log messages to [Rollbar](https://www.rollbar.com).
