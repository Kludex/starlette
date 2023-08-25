
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
