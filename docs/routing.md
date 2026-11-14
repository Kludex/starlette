## HTTP Routing

Starlette has a simple but capable request routing system. A routing table
is defined as a list of routes, and passed when instantiating the application.

```python
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route


async def homepage(request):
    return PlainTextResponse("Homepage")

async def about(request):
    return PlainTextResponse("About")


routes = [
    Route("/", endpoint=homepage),
    Route("/about", endpoint=about),
]

app = Starlette(routes=routes)
```

The `endpoint` argument can be one of:

* A regular function or async function, which accepts a single `request`
argument and which should return a response.
* A class that implements the ASGI interface, such as Starlette's [HTTPEndpoint](endpoints.md#httpendpoint).

## Path Parameters

Paths can use URI templating style to capture path components.

```python
Route('/users/{username}', user)
```
By default this will capture characters up to the end of the path or the next `/`.

You can use convertors to modify what is captured. The available convertors are:

* `str` returns a string, and is the default.
* `int` returns a Python integer.
* `float` returns a Python float.
* `uuid` return a Python `uuid.UUID` instance.
* `path` returns the rest of the path, including any additional `/` characters.

Convertors are used by prefixing them with a colon, like so:

```python
Route('/users/{user_id:int}', user)
Route('/floating-point/{number:float}', floating_point)
Route('/uploaded/{rest_of_path:path}', uploaded)
```

If you need a different converter that is not defined, you can create your own.
See below an example on how to create a `datetime` convertor, and how to register it:

```python
from datetime import datetime

from starlette.convertors import Convertor, register_url_convertor


class DateTimeConvertor(Convertor):
    regex = "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(.[0-9]+)?"

    def convert(self, value: str) -> datetime:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")

    def to_string(self, value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%S")

register_url_convertor("datetime", DateTimeConvertor())
```

After registering it, you'll be able to use it as:

```python
Route('/history/{date:datetime}', history)
```

Path parameters are made available in the request, as the `request.path_params`
dictionary.

```python
async def user(request):
    user_id = request.path_params['user_id']
    ...
```

## Handling HTTP methods

Routes can also specify which HTTP methods are handled by an endpoint:

```python
Route('/users/{user_id:int}', user, methods=["GET", "POST"])
```

By default function endpoints will only accept `GET` requests, unless specified.

## Submounting routes

In large applications you might find that you want to break out parts of the
routing table, based on a common path prefix.

```python
routes = [
    Route('/', homepage),
    Mount('/users', routes=[
        Route('/', users, methods=['GET', 'POST']),
        Route('/{username}', user),
    ])
]
```

This style allows you to define different subsets of the routing table in
different parts of your project.

```python
from myproject import users, auth

routes = [
    Route('/', homepage),
    Mount('/users', routes=users.routes),
    Mount('/auth', routes=auth.routes),
]
```

You can also use mounting to include sub-applications within your Starlette
application. For example...

```python
# This is a standalone static files server:
app = StaticFiles(directory="static")

# This is a static files server mounted within a Starlette application,
# underneath the "/static" path.
routes = [
    ...
    Mount("/static", app=StaticFiles(directory="static"), name="static")
]

app = Starlette(routes=routes)
```

## Reverse URL lookups

You'll often want to be able to generate the URL for a particular route,
such as in cases where you need to return a redirect response.

* Signature: `url_for(name, **path_params) -> URL`

```python
routes = [
    Route("/", homepage, name="homepage")
]

# We can use the following to return a URL...
url = request.url_for("homepage")
```

URL lookups can include path parameters...

```python
routes = [
    Route("/users/{username}", user, name="user_detail")
]

# We can use the following to return a URL...
url = request.url_for("user_detail", username=...)
```

If a `Mount` includes a `name`, then submounts should use a `{prefix}:{name}`
style for reverse URL lookups.

```python
routes = [
    Mount("/users", name="users", routes=[
        Route("/", user, name="user_list"),
        Route("/{username}", user, name="user_detail")
    ])
]

# We can use the following to return URLs...
url = request.url_for("users:user_list")
url = request.url_for("users:user_detail", username=...)
```

Mounted applications may include a `path=...` parameter.

```python
routes = [
    ...
    Mount("/static", app=StaticFiles(directory="static"), name="static")
]

# We can use the following to return URLs...
url = request.url_for("static", path="/css/base.css")
```

For cases where there is no `request` instance, you can make reverse lookups
against the application, although these will only return the URL path.

```python
url = app.url_path_for("user_detail", username=...)
```

!!! note "`app.url_path_for()` ignores the `root_path`"
    The application doesn't know the ASGI `root_path` until a request arrives. If your app
    is served under a prefix, use `request.url_for(...).path` instead.

### Paths for links within your site

`request.url_for()` returns an absolute URL, with a scheme and a host. For links to other
pages of the same site, you only need the path:

```python
from starlette.responses import RedirectResponse


async def login(request):
    return RedirectResponse(request.url_for("user_detail", username="tom").path)
```

The path includes the ASGI `root_path`, so it stays correct when a proxy serves your app
under a prefix, as long as the server sets `root_path` (see the next section). The browser
resolves it against the address it already used, so the scheme and host can't be wrong.

The same works in templates:

```html
<link href="{{ url_for('static', path='/css/base.css').path }}" rel="stylesheet" />
```

!!! note "Routes under `Host` need the full URL"
    A route inside a [`Host`](#host-based-routing) can live on a different host than the
    current request. Its path alone would point to the wrong site, so keep the full URL.

### Absolute URLs behind a proxy

Some URLs must be absolute: links in emails, OAuth callbacks, or URLs returned by an API.
`request.url_for()` builds them from the incoming request:

| Part | Source |
| --- | --- |
| Scheme | The ASGI `scheme`, set by the server. |
| Host | The `Host` header, or the ASGI `server` if the header is missing. |
| Path prefix | The ASGI `root_path`. |

Behind a reverse proxy, the server sees the connection from the proxy, not from the client.
To get the public URL, you need all of these:

* The server must trust the `X-Forwarded-Proto` header from the proxy, so the scheme is
  `https`. With Uvicorn, use `--proxy-headers` and `--forwarded-allow-ips`. See
  [Proxies and forwarded headers](https://uvicorn.dev/deployment/#proxies-and-forwarded-headers).
* The proxy must pass the original `Host` header. Uvicorn doesn't read `X-Forwarded-Host`.
  With nginx, add `proxy_set_header Host $host;`.
* If the proxy serves your app under a prefix and strips it, the server must set the ASGI
  `root_path` to that prefix. With Uvicorn, use `--root-path /prefix`.

!!! warning "The client controls the `Host` header"
    Anyone can send a request with `Host: evil.com`, and `url_for()` will return
    `http://evil.com/...`. If that URL ends up in a password reset email or a redirect,
    it sends your users to the attacker. Reject unknown hosts with
    [`TrustedHostMiddleware`](middleware.md#trustedhostmiddleware) whenever you build
    absolute URLs. List your domains in `allowed_hosts`, because the default allows every
    host.

If your public address is fixed, you can skip the `Host` header and set it yourself:

```python
async def auth(request):
    callback = request.url_for("auth_callback").replace(scheme="https", netloc="example.com")
    ...
```

## Host-based routing

If you want to use different routes for the same path based on the `Host` header.

Note that port is removed from the `Host` header when matching.
For example, `Host (host='example.org:3600', ...)` will be processed
even if the `Host` header contains or does not contain a port other than `3600`
(`example.org:5600`, `example.org`).
Therefore, you can specify the port if you need it for use in `url_for`.

There are several ways to connect host-based routes to your application

```python
site = Router(routes=[...])  # Add your `Route` entries here.
api = Router(routes=[...])  # Add your `Route` entries here.
news = Router(routes=[...])  # Add your `Route` entries here.

routes = [
    Host('api.example.org', api, name="site_api")
]

app = Starlette(routes=routes)

app.host('www.example.org', site, name="main_site")

news_host = Host('news.example.org', news)
app.router.routes.append(news_host)
```

URL lookups can include host parameters just like path parameters

```python
routes = [
    Host("{subdomain}.example.org", name="sub", app=Router(routes=[
        Mount("/users", name="users", routes=[
            Route("/", user, name="user_list"),
            Route("/{username}", user, name="user_detail")
        ])
    ]))
]
...
url = request.url_for("sub:users:user_detail", username=..., subdomain=...)
url = request.url_for("sub:users:user_list", subdomain=...)
```

## Route priority

Incoming paths are matched against each `Route` in order.

In cases where more that one route could match an incoming path, you should
take care to ensure that more specific routes are listed before general cases.

For example:

```python
# Don't do this: `/users/me` will never match incoming requests.
routes = [
    Route('/users/{username}', user),
    Route('/users/me', current_user),
]

# Do this: `/users/me` is tested first.
routes = [
    Route('/users/me', current_user),
    Route('/users/{username}', user),
]
```

## Working with Router instances

If you're working at a low-level you might want to use a plain `Router`
instance, rather that creating a `Starlette` application. This gives you
a lightweight ASGI application that just provides the application routing,
without wrapping it up in any middleware.

```python
app = Router(routes=[
    Route('/', homepage),
    Mount('/users', routes=[
        Route('/', users, methods=['GET', 'POST']),
        Route('/{username}', user),
    ])
])
```

## Request body size limits

Use a non-negative `max_body_size` to limit the total number of request body
bytes accepted by an application. The limit includes multipart file data and
multipart encoding overhead. It defaults to `None`, which preserves the existing
unlimited behavior.

```python
app = Starlette(
    routes=[
        Route("/", homepage),
        Route("/upload", upload, methods=["POST"], max_body_size=100 * 1024 * 1024),
    ],
    max_body_size=10 * 1024 * 1024,
)
```

`Router` and `Mount` also accept `max_body_size`. A limit on an inner route,
mount, or router overrides the outer limit after routing. This allows an upload
route to accept a larger body than the rest of the application.

Application middleware runs before routing. If such middleware reads the body,
the application-level limit applies to those bytes before a route can raise the
limit. Keep the application limit large enough for the largest legitimate route
when using body-consuming application middleware.

Starlette counts the actual body bytes received from the ASGI server.
`Content-Length` is used only to reject an oversized request early and is not
trusted to enforce the limit. A reverse proxy request-body limit and a quota on
temporary storage provide additional deployment-level safeguards.

## WebSocket Routing

When working with WebSocket endpoints, you should use `WebSocketRoute`
instead of the usual `Route`.

Path parameters, and reverse URL lookups for `WebSocketRoute` work the same
as HTTP `Route`, which can be found in the HTTP [Route](#http-routing) section above.

```python
from starlette.applications import Starlette
from starlette.routing import WebSocketRoute


async def websocket_index(websocket):
    await websocket.accept()
    await websocket.send_text("Hello, websocket!")
    await websocket.close()


async def websocket_user(websocket):
    name = websocket.path_params["name"]
    await websocket.accept()
    await websocket.send_text(f"Hello, {name}")
    await websocket.close()


routes = [
    WebSocketRoute("/", endpoint=websocket_index),
    WebSocketRoute("/{name}", endpoint=websocket_user),
]

app = Starlette(routes=routes)
```

The `endpoint` argument can be one of:

* An async function, which accepts a single `websocket` argument.
* A class that implements the ASGI interface, such as Starlette's [WebSocketEndpoint](endpoints.md#websocketendpoint).
