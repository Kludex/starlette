
Starlette also includes a `StaticFiles` class for serving files in a given directory:

### StaticFiles

Signature: `StaticFiles(directory=None, packages=None, check_dir=True)`

* `directory` - A string denoting a directory path.
* `packages` - A list of strings of python packages.
* `check_dir` - Ensure that the directory exists upon instantiation. Defaults to `True`.

You can combine this ASGI application with Starlette's routing to provide
comprehensive static file serving.

```python
from starlette.routing import Router, Mount
from starlette.staticfiles import StaticFiles


app = Router(routes=[
    Mount('/static', app=StaticFiles(directory='static'), name="static"),
])
```

Static files will respond with "404 Not found" or "405 Method not allowed"
responses for requests which do not match.

The `packages` option can be used to include "static" directories contained within
a python package. The Python "bootstrap4" package is an example of this.

```python
from starlette.routing import Router, Mount
from starlette.staticfiles import StaticFiles


app = Router(routes=[
    Mount('/static', app=StaticFiles(directory='static', packages=['bootstrap4']), name="static"),
])
```

You may prefer to include static files directly inside the "static" directory
rather than using Python packaging to include static files, but it can be useful
for bundling up reusable components.
