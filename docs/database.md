Starlette includes optional database support. There is currently only a driver
for Postgres databases, but MySQL and SQLite support is planned.

Enabling the built-in database support requires `sqlalchemy`, and an appropriate database driver. Currently this means `asyncpg` is a requirement.

The database support is completely optional - you can either include the middleware or not, or you can build alternative kinds of backends instead. It does not
include support for an ORM, but it does support using queries built using
[SQLAlchemy Core][sqlalchemy-core].

Here's a complete example, that includes table definitions, installing the
`DatabaseMiddleware`, and a couple of endpoints that interact with the database.

```python
import os
import sqlalchemy
from starlette.applications import Starlette
from starlette.middleware.database import DatabaseMiddleware
from starlette.responses import JSONResponse


metadata = sqlalchemy.MetaData()

notes = sqlalchemy.Table(
    "notes",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("text", sqlalchemy.String),
    sqlalchemy.Column("completed", sqlalchemy.Boolean),
)

app = Starlette()
app.add_middleware(DatabaseMiddleware, database_url=os.environ['DATABASE_URL'])


@app.route("/notes", methods=["GET"])
async def list_notes(request):
    query = notes.select()
    results = await request.database.fetchall(query)
    content = [
        {
            "text": result["text"],
            "completed": result["completed"]
        }
        for result in results
    ]
    return JSONResponse(content)


@app.route("/notes", methods=["POST"])
async def add_note(request):
    data = await request.json()
    query = notes.insert().values(
       text=data["text"],
       completed=data["completed"]
    )
    await request.database.execute(query)
    return JSONResponse({
        "text": data["text"],
        "completed": data["completed"]
    })
```

## Queries

Queries may be made with as [SQLAlchemy Core queries][sqlalchemy-core], or as raw SQL.

The following are supported:

* `request.database.fetchall(query)`
* `request.database.fetchone(query)`
* `request.database.fetchval(query)`
* `request.database.execute(query)`

## Transactions

Database transactions are available either as an endpoint decorator, as a
context manager, or as a low-level API.

Using a decorator on an endpoint:

```python
from starlette.databases import transaction

@transaction
async def populate_note(request):
    # This database insert occurs within a transaction.
    # It will be rolled back by the `RuntimeError`.
    query = notes.insert().values(text="you won't see me", completed=True)
    await request.database.execute(query)
    raise RuntimeError()
```

Using a context manager:

```python
async def populate_note(request):
    async with request.database.transaction():
        # This database insert occurs within a transaction.
        # It will be rolled back by the `RuntimeError`.
        query = notes.insert().values(text="you won't see me", completed=True)
        await request.database.execute(query)
        raise RuntimeError()
```

Using the low-level API:

```python
async def populate_note(request):
    transaction = request.database.transaction()
    transaction.start()
    try:
        # This database insert occurs within a transaction.
        # It will be rolled back by the `RuntimeError`.
        query = notes.insert().values(text="you won't see me", completed=True)
        await request.database.execute(query)
        raise RuntimeError()
    except:
        transaction.rollback()
        raise
    else:
        transaction.commit()
```

## Test isolation:

Use rollback_on_shutdown when instantiating DatabaseMiddleware to support test-isolated sessions.

```python
app.add_middleware(
    DatabaseMiddleware,
    database_url=os.environ['DATABASE_URL'],
    rollback_on_shutdown=os.environ['TESTING']
)
```

You'll need to use TestClient as a context manager, in order to perform application startup/shutdown.

```python
with TestClient(app) as client:
    # Entering the block performs application startup.
    ...
    # Exiting the block performs application shutdown.
```

If you're using `py.test` you can create a fixture for the test client, like so:

**conftest.py**:

```python
@pytest.fixture()
def client():
    with TestClient(app) as client:
        yield client
```


[sqlalchemy-core]: https://docs.sqlalchemy.org/en/latest/core/
