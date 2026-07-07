
Starlette includes support for HTTP/2 and HTTP/3 server push, making it
possible to push resources to the client to speed up page load times.

### `Request.send_push_promise`

Used to initiate a server push for a resource. If server push is not available
this method does nothing.

Signature: `send_push_promise(path)`

* `path` - A string denoting the path of the resource.

```python
from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles


async def homepage(request):
    """
    Homepage which uses server push to deliver the stylesheet.
    """
    await request.send_push_promise("/static/style.css")
    return HTMLResponse(
        '<html><head><link rel="stylesheet" href="/static/style.css"/></head></html>'
    )

routes = [
    Route("/", endpoint=homepage),
    Mount("/static", StaticFiles(directory="static"), name="static")
]

app = Starlette(routes=routes)
```
### `Request.send_early_hints`

Used to initiate HTTP 103 Early Hints for one or more resources. If the
`http.response.early_hint` ASGI extension is not available this method does
nothing.

Signature: `send_early_hints(links)`

* `links` - An iterable of `bytes` containing RFC 8288 `Link` header values.

```python
from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.routing import Route


async def homepage(request):
    """
    Homepage which uses HTTP 103 Early Hints to advertise resources.
    """
    await request.send_early_hints(
        [
            b'</static/style.css>; rel=preload; as=style',
            b'</static/app.js>; rel=modulepreload',
        ]
    )

    return HTMLResponse(
        '<html><head><link rel="stylesheet" href="/static/style.css"/></head></html>'
    )


routes = [
    Route("/", endpoint=homepage),
]

app = Starlette(routes=routes)
```
