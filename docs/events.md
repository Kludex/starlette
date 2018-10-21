
Starlette applications can register multiple event handlers for dealing with
code that needs to run before the application starts up, or when the application
is shutting down.

## Registering events

These event handlers can either be `async` coroutines, or regular syncronous
functions.

The event handlers can be registered with a decorator syntax, like so:

```python
from starlette.applications import Starlette


app = Starlette()

@app.on_event('startup')
async def open_database_connection_pool():
    ...

@app.on_event('cleanup')
async def close_database_connection_pool():
    ...
```
Or as a regular function call:

```python
from starlette.applications import Starlette


app = Starlette()

async def open_database_connection_pool():
    ...

async def close_database_connection_pool():
    ...

app.add_event_handler('startup', open_database_connection_pool)
app.add_event_handler('cleanup', close_database_connection_pool)

```

Starlette will not start serving any incoming requests until all of the
registered startup handlers have completed.

The cleanup handlers will run once all connections have been closed, and
any in-process background tasks have completed.

**Note**: The ASGI lifespan protocol has only recently been added to the spec,
and is only currently supported by the `uvicorn` server. Make sure to use the
latest `uvicorn` release if you need startup/cleanup support.

## Running event handers in tests

You might want to explicitly call into your event handlers in any test setup
or test teardown code.

Alternatively, Starlette provides a context manager that ensures the
lifespan events are called.

```python
from example import app
from starlette.lifespan import LifespanContext
from starlette.testclient import TestClient


def test_homepage():
    with LifespanContext(app):
        # Application 'startup' handlers are called on entering the block.
        client = TestClient(app)
        response = client.get("/")
        assert response.status_code == 200

    # Application 'cleanup' handlers are called on exiting the block.
```
