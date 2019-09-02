
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
from starlette.staticfiles import StaticFiles

app = Starlette()


@app.route("/")
async def homepage(request):
    """
    Homepage which uses server push to deliver the stylesheet.
    """
    await request.send_push_promise("/static/style.css")
    return HTMLResponse(
        '<html><head><link rel="stylesheet" href="/static/style.css"/></head></html>'
    )


app.mount("/static", StaticFiles(directory="static"))
```
