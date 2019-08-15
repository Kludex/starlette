<p align="center">
  <a href="https://www.starlette.io/"><img width="420px" src="https://raw.githubusercontent.com/encode/starlette/master/docs/img/starlette.png" alt='starlette'></a>
</p>
<p align="center">
    <em>✨ The little ASGI framework that shines. ✨</em>
</p>
<p align="center">
<a href="https://travis-ci.org/encode/starlette">
    <img src="https://travis-ci.org/encode/starlette.svg?branch=master" alt="Build Status">
</a>
<a href="https://codecov.io/gh/encode/starlette">
    <img src="https://codecov.io/gh/encode/starlette/branch/master/graph/badge.svg" alt="Coverage">
</a>
<a href="https://pypi.org/project/starlette/">
    <img src="https://badge.fury.io/py/starlette.svg" alt="Package version">
</a>
</p>

---

**Documentation**: [https://www.starlette.io/](https://www.starlette.io/)

**Community**: [https://discuss.encode.io/c/starlette](https://discuss.encode.io/c/starlette)

---

# Starlette

Starlette is a lightweight [ASGI](https://asgi.readthedocs.io/en/latest/) framework/toolkit,
which is ideal for building high performance asyncio services.

It is production-ready, and gives you the following:

* Seriously impressive performance.
* WebSocket support.
* GraphQL support.
* In-process background tasks.
* Startup and shutdown events.
* Test client built on `requests`.
* CORS, GZip, Static Files, Streaming responses.
* Session and Cookie support.
* 100% test coverage.
* 100% type annotated codebase.
* Zero hard dependencies.

## Requirements

Python 3.6+

## Installation

```shell
$ pip3 install starlette
```

You'll also want to install an ASGI server, such as [uvicorn](http://www.uvicorn.org/), [daphne](https://github.com/django/daphne/), or [hypercorn](https://pgjones.gitlab.io/hypercorn/).

```shell
$ pip3 install uvicorn
```

## Example

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
import uvicorn

app = Starlette(debug=True)


@app.route('/')
async def homepage(request):
    return JSONResponse({'hello': 'world'})

if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)
```

For a more complete example, see [encode/starlette-example](https://github.com/encode/starlette-example).

## Dependencies

Starlette does not have any hard dependencies, but the following are optional:

* [`requests`][requests] - Required if you want to use the `TestClient`.
* [`aiofiles`][aiofiles] - Required if you want to use `FileResponse` or `StaticFiles`.
* [`jinja2`][jinja2] - Required if you want to use `Jinja2Templates`.
* [`python-multipart`][python-multipart] - Required if you want to support form parsing, with `request.form()`.
* [`itsdangerous`][itsdangerous] - Required for `SessionMiddleware` support.
* [`pyyaml`][pyyaml] - Required for `SchemaGenerator` support.
* [`graphene`][graphene] - Required for `GraphQLApp` support.
* [`ujson`][ujson] - Required if you want to use `UJSONResponse`.

You can install all of these with `pip3 install starlette[full]`.

## Framework or Toolkit

Starlette is designed to be used either as a complete framework, or as
an ASGI toolkit. You can use any of its components independently.

```python
from starlette.responses import PlainTextResponse


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = PlainTextResponse('Hello, world!')
    await response(scope, receive, send)
```

Run the `app` application in `example.py`:

```shell
$ uvicorn example:app
INFO: Started server process [11509]
INFO: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Run uvicorn with `--reload` to enable auto-reloading on code changes.

## Modularity

The modularity that Starlette is designed on promotes building re-usable
components that can be shared between any ASGI framework. This should enable
an ecosystem of shared middleware and mountable applications.

The clean API separation also means it's easier to understand each component
in isolation.

## Performance

Independent TechEmpower benchmarks show Starlette applications running under Uvicorn
as [one of the fastest Python frameworks available](https://www.techempower.com/benchmarks/#section=data-r17&hw=ph&test=fortune&l=zijzen-1). *(\*)*

For high throughput loads you should:

* Make sure to install `ujson` and use `UJSONResponse`.
* Run using gunicorn using the `uvicorn` worker class.
* Use one or two workers per-CPU core. (You might need to experiment with this.)
* Disable access logging.

Eg.

```shell
gunicorn -w 4 -k uvicorn.workers.UvicornWorker --log-level warning example:app
```

Several of the ASGI servers also have pure Python implementations available,
so you can also run under `PyPy` if your application code has parts that are
CPU constrained.

Either programatically:

```python
uvicorn.run(..., http='h11', loop='asyncio')
```

Or using Gunicorn:

```shell
gunicorn -k uvicorn.workers.UvicornH11Worker ...
```

<p align="center">&mdash; ⭐️ &mdash;</p>
<p align="center"><i>Starlette is <a href="https://github.com/encode/starlette/blob/master/LICENSE.md">BSD licensed</a> code. Designed & built in Brighton, England.</i></p>

[requests]: http://docs.python-requests.org/en/master/
[aiofiles]: https://github.com/Tinche/aiofiles
[jinja2]: http://jinja.pocoo.org/
[python-multipart]: https://andrew-d.github.io/python-multipart/
[graphene]: https://graphene-python.org/
[itsdangerous]: https://pythonhosted.org/itsdangerous/
[sqlalchemy]: https://www.sqlalchemy.org
[pyyaml]: https://pyyaml.org/wiki/PyYAMLDocumentation
[ujson]: https://github.com/esnme/ultrajson
