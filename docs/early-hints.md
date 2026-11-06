Starlette supports [HTTP 103 Early Hints](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/103)
through the ASGI [`http.response.early_hint`](https://asgi.readthedocs.io/en/latest/extensions.html#early-hints)
extension. Early Hints let a client start loading resources while the endpoint prepares the final response.

### `Request.send_early_hints`

Used to send one or more `Link` header values before the final response. If the ASGI server does not support
Early Hints, this method does nothing.

Signature: `send_early_hints(link, *additional_links)`

* `link` - An [RFC 8288](https://www.rfc-editor.org/rfc/rfc8288.html) `Link` header value.
* `additional_links` - Additional `Link` header values.

```python
from __future__ import annotations

import anyio

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route


async def homepage(request: Request) -> HTMLResponse:
    await request.send_early_hints(
        "</static/style.css>; rel=preload; as=style",
        "</static/app.js>; rel=modulepreload",
    )

    await anyio.sleep(1)
    return HTMLResponse("""
        <!doctype html>
        <html lang="en">
            <head>
                <title>Early Hints</title>
                <link rel="stylesheet" href="/static/style.css">
                <script type="module" src="/static/app.js"></script>
            </head>
            <body><h1>Hello!</h1></body>
        </html>
    """)


async def stylesheet(request: Request) -> Response:
    return Response("body { font-family: sans-serif; }", media_type="text/css")


async def javascript(request: Request) -> Response:
    return Response(
        'document.querySelector("h1").textContent = "Hello from Starlette!";',
        media_type="text/javascript",
    )


app = Starlette(
    routes=[
        Route("/", endpoint=homepage),
        Route("/static/style.css", endpoint=stylesheet),
        Route("/static/app.js", endpoint=javascript),
    ]
)
```

The one-second sleep simulates slow work, such as a database query. You send the hints before this work so
the client can load the stylesheet and script while it waits. This example serves both assets through routes,
so you do not need to create separate static files.

The ASGI server is responsible for sending Early Hints to the client. For example, Hypercorn supports the
extension over HTTP/2 and HTTP/3. Browsers may ignore Early Hints, so the resources must still be referenced by
the final response.
