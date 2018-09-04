Starlette also includes an `App` class that nicely ties together all of
its other functionality.

```python
from starlette.app import App
from starlette.response import PlainTextResponse
from starlette.staticfiles import StaticFiles


app = App()
app.debug = True
app.mount("/static", StaticFiles(directory="static"))


@app.route('/')
def homepage(request):
    return PlainTextResponse('Hello, world!')


@app.route('/user/{username}')
def user(request, username):
    return PlainTextResponse('Hello, %s!' % username)


@app.websocket_route('/ws')
async def websocket_endpoint(session):
    await session.accept()
    await session.send_text('Hello, websocket!')
    await session.close()
```

### Instantiating the application

* `App(debug=False)` - Create a new Starlette application.

### Adding routes to the application

You can use any of the following to add handled routes to the application:

* `app.add_route(path, func, methods=["GET"])` - Add an HTTP route. The function may be either a coroutine or a regular function, with a signature like `func(request, **kwargs) -> response`.
* `app.add_websocket_route(path, func)` - Add a websocket session route. The function must be a coroutine, with a signature like `func(session, **kwargs)`.
* `@app.route(path)` - Add an HTTP route, decorator style.
* `@app.websocket_route(path)` - Add a WebSocket route, decorator style.

### Submounting other applications

Submounting applications is a powerful way to include reusable ASGI applications.

* `app.mount(prefix, app)` - Include an ASGI app, mounted under the given path prefix

### Customizing exception handling

You can use either of the following to catch and handle particular types of
exceptions that occur within the application:

* `app.add_exception_handler(exc_class, handler)` - Add an error handler. The handler function may be either a coroutine or a regular function, with a signature like `func(request, exc) -> response`.
* `@app.exception_handler(exc_class)` - Add an error handler, decorator style.
* `app.debug` - Enable or disable error tracebacks in the browser.
