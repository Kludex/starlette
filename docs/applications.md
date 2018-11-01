
Starlette includes an application class `Starlette` that nicely ties together all of
its other functionality.

```python
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.staticfiles import StaticFiles


app = Starlette()
app.debug = True
app.mount('/static', StaticFiles(directory="static"))


@app.route('/')
def homepage(request):
    return PlainTextResponse('Hello, world!')


@app.route('/user/{username}')
def user(request):
    username = request.path_params['username']
    return PlainTextResponse('Hello, %s!' % username)


@app.websocket_route('/ws')
async def websocket_endpoint(websocket):
    await websocket.accept()
    await websocket.send_text('Hello, websocket!')
    await websocket.close()


@app.on_event('startup')
def startup():
    print('Ready to go')
```

### Instantiating the application

* `Starlette(debug=False)` - Create a new Starlette application.

### Adding routes to the application

You can use any of the following to add handled routes to the application:

* `app.add_route(path, func, methods=["GET"])` - Add an HTTP route. The function may be either a coroutine or a regular function, with a signature like `func(request, **kwargs) -> response`.
* `app.add_websocket_route(path, func)` - Add a websocket session route. The function must be a coroutine, with a signature like `func(session, **kwargs)`.
* `@app.route(path)` - Add an HTTP route, decorator style.
* `@app.websocket_route(path)` - Add a WebSocket route, decorator style.

### Adding event handlers to the application

There are two ways to add event handlers:

* `@app.on_event(event_type)` - Add an event, decorator style
* `app.add_event_handler(event_type, func)` - Add an event through a function call.

`event_type` must be specified as either `'startup'` or `'shutdown'`.

### Submounting other applications

Submounting applications is a powerful way to include reusable ASGI applications.

* `app.mount(prefix, app)` - Include an ASGI app, mounted under the given path prefix

### Customizing exception handling

You can use either of the following to catch and handle particular types of
exceptions that occur within the application:

* `app.add_exception_handler(exc_class, handler)` - Add an error handler. The handler function may be either a coroutine or a regular function, with a signature like `func(request, exc) -> response`.
* `@app.exception_handler(exc_class)` - Add an error handler, decorator style.
* `app.debug` - Enable or disable error tracebacks in the browser.
