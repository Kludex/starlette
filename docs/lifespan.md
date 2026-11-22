
Starlette applications can register a lifespan handler for dealing with
code that needs to run before the application starts up, or when the application
is shutting down.

```python
import contextlib

from starlette.applications import Starlette


@contextlib.asynccontextmanager
async def lifespan(app):
    async with some_async_resource():
        print("Run at startup!")
        yield
        print("Run on shutdown!")


routes = [
    ...
]

app = Starlette(routes=routes, lifespan=lifespan)
```

Starlette will not start serving any incoming requests until the lifespan has been run.

The lifespan teardown will run once all connections have been closed, and
any in-process background tasks have completed.

Consider using [`anyio.create_task_group()`](https://anyio.readthedocs.io/en/stable/tasks.html)
for managing asynchronous tasks.

## Lifespan State

The lifespan has the concept of `state`, which is a dictionary that
can be used to share the objects between the lifespan, and the requests.

```python
import contextlib
from typing import AsyncIterator, TypedDict

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route


class State(TypedDict):
    http_client: httpx.AsyncClient


@contextlib.asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[State]:
    async with httpx.AsyncClient() as client:
        yield {"http_client": client}


async def homepage(request: Request) -> PlainTextResponse:
    client = request.state.http_client
    response = await client.get("https://www.example.com")
    return PlainTextResponse(response.text)


app = Starlette(
    lifespan=lifespan,
    routes=[Route("/", homepage)]
)
```

The `state` received on the requests is a **shallow** copy of the state received on the
lifespan handler.

## Accessing State

The state can be accessed using either attribute-style or dictionary-style syntax.

The dictionary-style syntax was introduced in Starlette 0.52.0 (January 2026), with the idea of
improving type safety when using the lifespan state, given that `Request` became a generic over
the state type.

```python
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TypedDict

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route


class State(TypedDict):
    http_client: httpx.AsyncClient


@asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[State]:
    async with httpx.AsyncClient() as client:
        yield {"http_client": client}


async def homepage(request: Request[State]) -> PlainTextResponse:
    client = request.state["http_client"]

    reveal_type(client)  # Revealed type is 'httpx.AsyncClient'

    response = await client.get("https://www.example.com")
    return PlainTextResponse(response.text)

app = Starlette(lifespan=lifespan, routes=[Route("/", homepage)])
```

This also works with WebSockets:

```python
async def websocket_endpoint(websocket: WebSocket[State]) -> None:
    await websocket.accept()
    client = websocket.state["http_client"]
    response = await client.get("https://www.example.com")
    await websocket.send_text(response.text)
    await websocket.close()


app = Starlette(lifespan=lifespan, routes=[WebSocketRoute("/ws", websocket_endpoint)])
```

!!! note
    There were many attempts to make this work with attribute-style access instead of
    dictionary-style access, but none were satisfactory, given they would have been
    breaking changes, or there were typing limitations.

    For more details, see:

    - [@Kludex/starlette#issues/3005](https://github.com/Kludex/starlette/issues/3005)
    - [@python/typing#discussions/1457](https://github.com/python/typing/discussions/1457)
    - [@Kludex/starlette#pull/3036](https://github.com/Kludex/starlette/pull/3036)

## Mounted Applications

Applications mounted with `Mount` or `Host` run their own lifespan.

```python
import contextlib

from starlette.applications import Starlette
from starlette.routing import Mount


@contextlib.asynccontextmanager
async def admin_lifespan(app):
    print("Admin startup")
    yield
    print("Admin shutdown")


@contextlib.asynccontextmanager
async def lifespan(app):
    print("Root startup")
    yield
    print("Root shutdown")


admin = Starlette(lifespan=admin_lifespan)
app = Starlette(routes=[Mount("/admin", app=admin)], lifespan=lifespan)
```

The parent lifespan starts first, then each mounted application in route order. Shutdown runs in reverse
order. This is the same nesting as `async with` blocks, so a mounted application can rely on resources the
parent opened.

Each mounted application runs the ASGI lifespan protocol in its own task, inside a task group owned by the
parent. A mounted application that fails to start stops the whole startup, and the ones already started are
shut down.

State yielded by a mounted application is merged into the same lifespan `state`, so its requests can read it.

Mounted applications that do not support lifespan, like `StaticFiles`, are skipped.

!!! warning "Remove manual lifespan forwarding"
    If your parent lifespan already enters a mounted application's lifespan by hand, remove that code.
    Otherwise, the mounted lifespan runs twice.

## Running lifespan in tests

You should use `TestClient` as a context manager, to ensure that the lifespan is called.

```python
from example import app
from starlette.testclient import TestClient


def test_homepage():
    with TestClient(app) as client:
        # Application's lifespan is called on entering the block.
        response = client.get("/")
        assert response.status_code == 200

    # And the lifespan's teardown is run when exiting the block.
```
