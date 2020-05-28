
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
