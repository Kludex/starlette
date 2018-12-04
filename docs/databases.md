Starlette includes optional database support. There is currently only a driver
for Postgres databases, but MySQL and SQLite support is planned.

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
async def populate_notes(request):
    # These database inserts occur within a transaction.
    # If an error occurs they will be rolled back as a group.
    query = notes.insert().values(text="buy the groceries", completed=True)
    await request.database.execute(query)
    query = notes.insert().values(text="take the dog for a walk", completed=False)
    await request.database.execute(query)
    query = notes.insert().values(text="interview preparation", completed=True)
    await request.database.execute(query)
```

Using a context manager:

```python
async def populate_notes(request):
    async with request.database.transaction():
        # These database inserts occur within a transaction.
        # If an error occurs they will be rolled back as a group.
        query = notes.insert().values(text="buy the groceries", completed=True)
        await request.database.execute(query)
        query = notes.insert().values(text="take the dog for a walk", completed=False)
        await request.database.execute(query)
        query = notes.insert().values(text="interview preparation", completed=True)
        await request.database.execute(query)
```

Using the low-level API:

```python
async def populate_notes(request):
    transaction = request.database.transaction()
    transaction.start()
    try:
        # These database inserts occur within a transaction.
        # If an error occurs they will be rolled back as a group.
        query = notes.insert().values(text="buy the groceries", completed=True)
        await request.database.execute(query)
        query = notes.insert().values(text="take the dog for a walk", completed=False)
        await request.database.execute(query)
        query = notes.insert().values(text="interview preparation", completed=True)
        await request.database.execute(query)
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
