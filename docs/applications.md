Starlette also includes an `App` class that nicely ties together all of
its other functionality.

```python
from starlette.app import App
from starlette.response import PlainTextResponse
from starlette.staticfiles import StaticFiles


app = App()
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

### Adding routes to the application

You can use any of the following to add handled routes to the application:

* `.add_route(path, func, methods=["GET"])` - Add an HTTP route. The function may be either a coroutine or a regular function, with a signature like `func(request **kwargs) -> response`.
* `.add_websocket_route(path, func)` - Add a websocket session route. The function must be a coroutine, with a signature like `func(session, **kwargs)`.
* `.mount(prefix, app)` - Include an ASGI app, mounted under the given path prefix
* `.route(path)` - Add an HTTP route, decorator style.
* `.websocket_route(path)` - Add a WebSocket route, decorator style.


<p align="center">&mdash; ⭐️ &mdash;</p>
<p align="center"><i>Starlette is <a href="https://github.com/tomchristie/starlette/blob/master/LICENSE.md">BSD licensed</a> code. Designed & built in Brighton, England.</i></p>
