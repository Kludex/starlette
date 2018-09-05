<p align="center">
  <img width="320" height="192" src="https://raw.githubusercontent.com/encode/starlette/master/docs/starlette.png" alt='starlette'>
</p>
<p align="center">
    <em>✨ The little ASGI library that shines. ✨</em>
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


# Introduction

Starlette is a small library for working with [ASGI](https://asgi.readthedocs.io/en/latest/).

It gives you `Request` and `Response` classes, request routing, websocket support,
static files support, and a test client.

## Requirements

Python 3.6+

## Installation

```shell
$ pip3 install starlette
```

## Example

```python
from starlette.responses import Response


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        response = Response('Hello, world!', media_type='text/plain')
        await response(receive, send)
```

You can run the application with any ASGI server, including [uvicorn](http://www.uvicorn.org/), [daphne](https://github.com/django/daphne/), or [hypercorn](https://pgjones.gitlab.io/hypercorn/).

Install the Uvicorn ASGI server:

```shell
$ pip3 install uvicorn
[...]
Successfully installed uvicorn
```

Run the `App` application in `example.py`:

```shell
$ uvicorn run example:App
INFO: Started server process [11509]
INFO: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

<p align="center">&mdash; ⭐️ &mdash;</p>
<p align="center"><i>Starlette is <a href="https://github.com/tomchristie/starlette/blob/master/LICENSE.md">BSD licensed</a> code. Designed & built in Brighton, England.</i></p>
