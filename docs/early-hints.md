Starlette supports [HTTP 103 Early Hints](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/103)
through the ASGI [`http.response.early_hint`](https://asgi.readthedocs.io/en/latest/extensions.html#early-hints)
extension. Early Hints let a client start loading resources while the endpoint prepares the final response.

### `Request.send_early_hints`

Used to send one or more `Link` header values before the final response. If the ASGI server does not support
Early Hints, this method does nothing.

Signature: `send_early_hints(links)`

* `links` - An iterable of strings or bytes containing [RFC 8288](https://www.rfc-editor.org/rfc/rfc8288.html)
  `Link` header values.

```python
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route


async def homepage(request: Request) -> HTMLResponse:
    links = [
        "</static/style.css>; rel=preload; as=style",
        "</static/app.js>; rel=modulepreload",
    ]
    await request.send_early_hints(links)

    # The client can load the hinted resources while this work runs.
    content = await render_homepage()
    return HTMLResponse(content)


app = Starlette(routes=[Route("/", endpoint=homepage)])
```

The ASGI server is responsible for sending Early Hints to the client. For example, Hypercorn supports the
extension over HTTP/2 and HTTP/3. Browsers may ignore Early Hints, so the resources must still be referenced by
the final response.
