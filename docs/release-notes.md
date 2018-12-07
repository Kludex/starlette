## 0.9.6

* Add `AuthenticationMiddleware`, and `@requires()` decorator.

## 0.9.5

* Support either `str` or `Secret` for `SessionMiddleware(secret_key=...)`.

## 0.9.4

* Add `config.environ`.
* Add `datastructures.Secret`.
* Add `datastructures.DatabaseURL`.

## 0.9.3

* Add `config.Config(".env")`

## 0.9.2

* Add optional database support.
* Add `request` to GraphQL context.
* Hide any password component in `URL.__repr__`.

## 0.9.1

* Handle startup/shutdown errors properly.

## 0.9.0

* `TestClient` can now be used as a context manager, instead of `LifespanContext`.
* Lifespan is now handled as middleware. Startup and Shutdown events are
visible throughout the middleware stack.

## 0.8.8

* Better support for third-party API schema generators.

## 0.8.7

* Support chunked requests with TestClient.
* Cleanup asyncio tasks properly with WSGIMiddleware.
* Support using TestClient within endpoints, for service mocking.

## 0.8.6

* Session cookies are now set on the root path.

## 0.8.5

* Support URL convertors.
* Support HTTP 304 cache responses from `StaticFiles`.
* Resolve character escaping issue with form data.

## 0.8.4

* Default to empty body on responses.

## 0.8.3

* Add 'name' argument to `@app.route()`.
* Use 'Host' header for URL reconstruction.

## 0.8.2

## StaticFiles

* StaticFiles no longer reads the file for responses to `HEAD` requests.

## 0.8.1

## Templating

* Add a default templating configuration with Jinja2.

Allows the following:

```python
app = Starlette(template_directory="templates")

@app.route('/')
async def homepage(request):
    # `url_for` is available inside the template.
    template = app.get_template('index.html')
    content = template.render(request=request)
    return HTMLResponse(content)
```

## 0.8.0

### Exceptions

* Add support for `@app.exception_handler(404)`.
* Ensure handled exceptions are not seen as errors by the middleware stack.

### SessionMiddleware

* Add `max_age`, and use timestamp-signed cookies. Defaults to two weeks.

### Cookies

* Ensure cookies are strictly HTTP correct.

### StaticFiles

* Check directory exists on instantiation.

## 0.7.4

### Concurrency

* Add `starlette.concurrency.run_in_threadpool`. Now handles `contextvar` support.

## 0.7.3

### Routing

* Add `name=` support to `app.mount()`. This allows eg: `app.mount('/static', StaticFiles(directory='static'), name='static')`.

## 0.7.2

### Middleware

* Add support for `@app.middleware("http")` decorator.

### Routing

* Add "endpoint" to ASGI scope.

## 0.7.1

### Debug tracebacks

* Improve debug traceback information & styling.

### URL routing

* Support mounted URL lookups with "path=", eg. `url_for('static', path=...)`.
* Support nested URL lookups, eg. `url_for('admin:user', username=...)`.
* Add redirect slashes support.
* Add www redirect support.

### Background tasks

* Add background task support to `FileResponse` and `StreamingResponse`.

## 0.7.0

### API Schema support

* Add `app.schema_generator = SchemaGenerator(...)`.
* Add `app.schema` property.
* Add `OpenAPIResponse(...)`.

### GraphQL routing

* Drop `app.add_graphql_route("/", ...)` in favor of more consistent `app.add_route("/", GraphQLApp(...))`.

## 0.6.3

### Routing API

* Support routing to methods.
* Ensure `url_path_for` works with Mount('/{some_path_params}').
* Fix Router(default=) argument.
* Support repeated paths, like: `@app.route("/", methods=["GET"])`, `@app.route("/", methods=["POST"])`
* Use the default ThreadPoolExecutor for all sync endpoints.

## 0.6.2

### SessionMiddleware

Added support for `request.session`, with `SessionMiddleware`.

## 0.6.1

### BaseHTTPMiddleware

Added support for `BaseHTTPMiddleware`, which provides a standard
request/response interface over a regular ASGI middleware.

This means you can write ASGI middleware while still working at
a request/response level, rather than handling ASGI messages directly.

```python
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware


class CustomMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers['Custom-Header'] = 'Example'
        return response


app = Starlette()
app.add_middleware(CustomMiddleware)
```

## 0.6.0

### request.path_params

The biggest change in 0.6 is that endpoint signatures are no longer:

```python
async def func(request: Request, **kwargs) -> Response
```

Instead we just use:

```python
async def func(request: Request) -> Response
```

The path parameters are available on the request as `request.path_params`.

This is different to most Python webframeworks, but I think it actually ends up
being much more nicely consistent all the way through.

### request.url_for()

Request and WebSocketSession now support URL reversing with `request.url_for(name, **path_params)`.
This method returns a fully qualified `URL` instance.
The URL instance is a string-like object.

### app.url_path_for()

Applications now support URL path reversing with `app.url_path_for(name, **path_params)`.
This method returns a `URL` instance with the path and scheme set.
The URL instance is a string-like object, and will return only the path if coerced to a string.

### app.routes

Applications now support a `.routes` parameter, which returns a list of `[Route|WebSocketRoute|Mount]`.

### Route, WebSocketRoute, Mount

The low level components to `Router` now match the `@app.route()`, `@app.websocket_route()`, and `app.mount()` signatures.
