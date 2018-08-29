
As well as the `FileResponse` class, Starlette also includes ASGI applications
for serving a specific file or directory:

* `StaticFile(path)` - Serve a single file, given by `path`.
* `StaticFiles(directory)` - Serve any files in the given `directory`.

You can combine these ASGI applications with Starlette's routing to provide
comprehensive static file serving.

```python
from starlette.routing import Router, Path, PathPrefix
from starlette.staticfiles import StaticFile, StaticFiles


app = Router(routes=[
    Path('/', app=StaticFile(path='index.html')),
    PathPrefix('/static', app=StaticFiles(directory='static')),
])
```

Static files will respond with "404 Not found" or "406 Method not allowed"
responses for requests which do not match.
