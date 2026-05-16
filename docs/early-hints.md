
Starlette supports [RFC 8297 "103 Early Hints"][rfc8297], an informational
response a server can emit *before* the final response is ready, letting the
client start preloading critical assets (CSS, JS, fonts, …) while the
application is still doing work.

This is the modern, browser-supported alternative to HTTP/2 Server Push, and is
useful any time the path between the start of a request and the moment the page
HTML is ready is non-trivial (database queries, template rendering, third-party
API calls).

### `Request.send_early_hint`

Sends a `103 Early Hints` response. If the underlying ASGI server does not
advertise the `http.response.early_hint` extension, this method does nothing —
making it safe to call unconditionally.

Signature: `send_early_hint(links)`

* `links` — an iterable of `Link` instances (see below) or raw byte-strings.
  Each entry becomes one `Link:` header value in the 103 response.

It may be called **multiple times** before the final response is sent, but must
be called *before* any `http.response.start` message has been emitted (i.e.
before returning the `Response`).

```python
from starlette.applications import Starlette
from starlette.datastructures import Link
from starlette.responses import HTMLResponse
from starlette.routing import Route


async def homepage(request):
    """
    Homepage that hints the stylesheet and the main script to the client
    before doing its (slow) work.
    """
    await request.send_early_hint(
        [
            Link("/static/style.css", rel="preload", as_="style"),
            Link("/static/app.js", rel="preload", as_="script"),
        ]
    )
    # ... slow database / template / API work ...
    return HTMLResponse(
        '<html><head>'
        '<link rel="stylesheet" href="/static/style.css"/>'
        '<script src="/static/app.js" defer></script>'
        '</head><body>...</body></html>'
    )


app = Starlette(routes=[Route("/", endpoint=homepage)])
```

### `Link`

A helper class in `starlette.datastructures` that builds a single `Link` header
value, as defined by [RFC 8288][rfc8288] (Web Linking). The class handles
parameter quoting per RFC 7230 so you don't have to.

Signature: `Link(target, *, rel=None, **params)`

* `target` — the URI of the related resource. Must not contain `>`.
* `rel` — the link relation type (e.g. `"preload"`, `"preconnect"`,
  `"stylesheet"`). Multiple values can be space-separated (`"preload prefetch"`)
  and will be quoted automatically.
* `**params` — any additional Link parameters. Two normalisation rules apply
  for ergonomics:
    * a **trailing underscore** is stripped, so Python keywords are usable
      (`as_="style"` → `as=style`, `type_="text/css"` → `type=text/css`);
    * **internal underscores** become hyphens (`referrer_policy="..."` →
      `referrer-policy=...`).

  A value of `True` produces a **flag parameter** without `=` (`nopush=True`
  → `nopush`). A value of `None` or `False` is skipped.

```python
from starlette.datastructures import Link

Link("/static/app.css", rel="preload", as_="style")
# bytes() → b'</static/app.css>; rel=preload; as=style'

Link("https://cdn.example.com", rel="preconnect", crossorigin="anonymous")
# bytes() → b'<https://cdn.example.com>; rel=preconnect; crossorigin=anonymous'

Link("/font.woff2", rel="preload", as_="font", type="font/woff2", crossorigin=True)
# bytes() → b'</font.woff2>; rel=preload; as=font; type="font/woff2"; crossorigin'
```

`Link` instances serialise to `bytes` via `bytes(link)` (or `str(link)` for a
text form). Because `send_early_hint` already does this conversion internally,
you usually just pass the instances directly.

### Server support

`Request.send_early_hint` only emits a real `103` on the wire when the ASGI
server signals support by including `"http.response.early_hint"` in
`scope["extensions"]`. The asgiref specification (`extensions.rst#early-hints`)
also lets a server **ignore** the message — for example on HTTP/1.0, where
intermediaries may not handle 1xx informational responses reliably.

Concrete state of the ecosystem at the time of writing:

| Server      | Native support |
|-------------|----------------|
| Uvicorn     | No             |
| Hypercorn   | No             |
| Granian     | No             |
| Daphne      | No             |

Until support lands upstream, you can wrap your ASGI app in a thin adapter that
adds the extension to the scope and intercepts the message at the transport
layer (the exact mechanism depends on the server). When no server-side support
is detected, `send_early_hint` becomes a no-op, so adding the calls to your
code in advance is risk-free.

[rfc8297]: https://www.rfc-editor.org/rfc/rfc8297.html
[rfc8288]: https://www.rfc-editor.org/rfc/rfc8288.html
