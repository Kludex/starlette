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

## Host-based routing

If you want to use different routes for the same path based on the `Host` header.

Note that port is removed from the `Host` header when matching.
For example, `Host (host='example.org:3600', ...)` will be processed
even if the `Host` header contains or does not contain a port other than `3600`
(`example.org:5600`, `example.org`).
Therefore, you can specify the port if you need it for use in `url_for`.

There are several ways to connect host-based routes to your application

```python
site = Router()  # Use eg. `@site.route()` to configure this.
api = Router()  # Use eg. `@api.route()` to configure this.
news = Router()  # Use eg. `@news.route()` to configure this.

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

## Route lookups

By default a `Router` scans its routes in order, calling `matches()` on each one
until a route matches. That is simple and predictable, but the cost grows with the
number of routes, and a request that matches nothing pays for the full scan.

A **route lookup** replaces that scan with something faster, such as a trie or a
native extension, without changing what a match means. The lookup only narrows the
routes a router has to check. Starlette still calls `BaseRoute.matches()` on every
candidate, so path parameters, convertors, `Mount`, `Host`, WebSockets, trailing
slash redirects, `405 Method Not Allowed` and first-registered-wins ordering all
behave exactly as before.

Install one by assigning a factory:

```python
from starlette.applications import Starlette

app = Starlette(routes=routes)
app.route_lookup_factory = SomeRouteLookup
```

The assignment applies to the whole routing tree: mounted applications, routers
behind `Host`, nested mounts, and routers mounted later all inherit it, and each
one compiles its own lookup from its own routes. A nested router that was given a
lookup of its own keeps it. Assign `None` to go back to the plain linear scan.

### Writing a route lookup

A lookup is any object with a `candidates()` method, and a factory is anything that
builds one from a sequence of routes:

```python
from starlette.routing import Route, get_route_path


class PrefixRouteLookup:
    def __init__(self, routes):
        self.positions = {id(route): index for index, route in enumerate(routes)}
        self.buckets = {}
        self.always = []
        for route in routes:
            # Exact type check: a `Route` subclass may override `matches()` and
            # match paths its own `path` does not describe.
            first = route.path.lstrip("/").split("/")[0] if type(route) is Route else ""
            if first and "{" not in first:
                self.buckets.setdefault(first, []).append(route)
            else:
                self.always.append(route)

    def candidates(self, scope):
        first = get_route_path(scope).lstrip("/").split("/")[0]
        bucket = self.buckets.get(first, [])
        return sorted(self.always + bucket, key=lambda route: self.positions[id(route)])
```

Implementations have to honour the following contract, because a route that never
reaches `matches()` silently becomes unreachable:

* `candidates()` must return a **superset** of the routes whose `matches()` would
  return `Match.FULL` or `Match.PARTIAL`. Never filter on `scope["method"]`:
  dropping method mismatches turns a `405 Method Not Allowed` into a `404 Not Found`.
* Candidates must come back in registration order, without duplicates, and must
  come from the route table the lookup was built with.
* Only index a route by its path when you understand its type exactly. Use
  `type(route) is Route`, not `isinstance()`. Anything else, including `Mount`,
  `Host` and custom `BaseRoute` implementations, should be treated as an
  always-candidate.
* `candidates()` is called at least once per request, and again with a modified
  scope for the trailing slash redirect check, so it must return a fresh iterable
  every time and must not cache by scope identity.
* It must be sync, must not mutate the scope, and must not send or receive ASGI
  messages.
* Candidates may be consumed lazily and abandoned as soon as a route matches, so a
  generator must not hold locks across a yield.

Use `starlette.routing.get_route_path()` to get the path a router matches against.
It strips `root_path`, which matters for mounted applications.

### Checking a lookup

`StrictRouteLookup` wraps another factory and verifies the contract on every
request, raising `RouteLookupError` when a candidate is dropped, duplicated,
reordered, or foreign to the route table:

```python
from starlette.routing import StrictRouteLookup

app.route_lookup_factory = StrictRouteLookup(PrefixRouteLookup)
```

It runs the linear scan alongside the lookup, so it is meant for tests, CI and
staging rather than production.

### Rebuilding

Lookups are compiled from a snapshot of `router.routes`, and rebuilt automatically
whenever routes are added, removed, replaced or reordered. Mutating a route object
in place is invisible, so tell the router about it:

```python
route.path = "/changed"
app.router.invalidate_route_lookup()
```

Lookups are compiled during lifespan startup, so a failing lookup surfaces at boot
instead of on the first request. Applications that never run a lifespan can build
them explicitly with `app.router.build_route_lookup()`, and
`app.router.route_lookup` shows the compiled lookup currently in use, or `None`
when the linear scan is being used.
