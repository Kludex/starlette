
Starlette applications can register multiple event handlers for dealing with
code that needs to run before the application starts up, or when the application
is shutting down.

## Registering events

These event handlers can either be `async` coroutines, or regular synchronous
functions.

The event handlers should be included on the application like so:

```python
from starlette.applications import Starlette


async def some_startup_task():
    pass

async def some_shutdown_task():
    pass

routes = [
    ...
]

app = Starlette(
    routes=routes,
    on_startup=[some_startup_task],
    on_shutdown=[some_shutdown_task]
)
```

Starlette will not start serving any incoming requests until all of the
registered startup handlers have completed.

The shutdown handlers will run once all connections have been closed, and
any in-process background tasks have completed.

A single lifespan `asynccontextmanager` handler can be used instead of
separate startup and shutdown handlers:

```python
import contextlib
import anyio
from starlette.applications import Starlette


@contextlib.asynccontextmanager
async def lifespan(app):
    async with some_async_resource():
        yield


routes = [
    ...
]

app = Starlette(routes=routes, lifespan=lifespan)
```

Consider using [`anyio.create_task_group()`](https://anyio.readthedocs.io/en/stable/tasks.html)
for managing asynchronous tasks.

## Lifespan State

The event handlers also accept a `state` argument, which is a dictionary
that can be used to share the objects between the startup and shutdown handlers,
and the requests.

```python
import httpx
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route


async def startup(state):
    state["http_client"] = httpx.AsyncClient()

async def shutdown(state):
    await state["http_client"].aclose()

async def homepage(request):
    res = await request.state.http_client.get("https://example.org")
    # Do something with the response.
    return PlainTextResponse("Hello, world!")


app = Starlette(
    routes=[Route("/", homepage)],
    on_startup=[startup],
    on_shutdown=[shutdown]
)
```

Analogously, the single lifespan `asynccontextmanager` can be used.

```python
import contextlib
from typing import TypedDict

import httpx
from starlette.applications import Starlette
from starlette.routing import Route


class State(TypedDict):
    http_client: httpx.AsyncClient


@contextlib.asynccontextmanager
async def lifespan(app: Starlette) -> State:
    async with httpx.AsyncClient() as client:
        yield {"http_client": client}


app = Starlette(
    lifespan=lifespan,
    routes=[Route("/", homepage)]
)
```

The `state` received on the requests is a **shallow** copy of the state received on the
startup event.

## Running event handlers in tests

You might want to explicitly call into your event handlers in any test setup
or test teardown code.

Alternatively, you can use `TestClient` as a context manager, to ensure that
startup and shutdown events are called.

```python
from example import app
from starlette.testclient import TestClient


def test_homepage():
    with TestClient(app) as client:
        # Application 'on_startup' handlers are called on entering the block.
        response = client.get("/")
        assert response.status_code == 200

    # Application 'on_shutdown' handlers are called on exiting the block.
```
