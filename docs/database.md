Starlette includes optional database support. There is currently only a driver
for Postgres databases, but MySQL and SQLite support is planned.

Enabling the built-in database support requires `sqlalchemy`, and an appropriate database driver. Currently this means `asyncpg` is a requirement.

The database support is completely optional - you can either include the middleware or not, or you can build alternative kinds of backends instead. It does not
include support for an ORM, but it does support using queries built using
[SQLAlchemy Core][sqlalchemy-core].

Here's a complete example, that includes table definitions, installing the
`DatabaseMiddleware`, and a couple of endpoints that interact with the database.

```python
import sqlalchemy
from starlette.applications import Starlette
from starlette.config import Config
from starlette.middleware.database import DatabaseMiddleware
from starlette.responses import JSONResponse


# Configuration from environment variables or '.env' file.
config = Config('.env')
DATABASE_URL = config('DATABASE_URL')


# Database table definitions.
metadata = sqlalchemy.MetaData()

notes = sqlalchemy.Table(
    "notes",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("text", sqlalchemy.String),
    sqlalchemy.Column("completed", sqlalchemy.Boolean),
)


# Application setup.
app = Starlette()
app.add_middleware(DatabaseMiddleware, database_url=DATABASE_URL)


# Endpoints.
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

## Test isolation

There are a few things that we want to ensure when running tests against
a service that uses a database. Our requirements should be:

* Use a separate database for testing.
* Create a new test database every time we run the tests.
* Ensure that the database state is isolated between each test case.

Here's how we need to structure our application and tests in order to
meet those requirements:

```python
from starlette.applications import Starlette
from starlette.config import Config

config = Config(".env")

TESTING = config('TESTING', cast=bool, default=False)
DATABASE_URL = config('DATABASE_URL', cast=DatabaseURL)
if TESTING:
  # Use a database name like "test_myapplication" for tests.
  DATABASE_URL = DATABASE_URL.replace(database='test_' + DATABASE_URL.database)


# Use 'rollback_on_shutdown' during testing, to ensure we do not persist
# database changes
app = Starlette()
app.add_middleware(
    DatabaseMiddleware,
    database_url=DATABASE_URL,
    rollback_on_shutdown=TESTING
)
```

We still need to set `TESTING` during a test run, and setup the test database.
Assuming we're using `py.test`, here's how our `conftest.py` might look:

```python
import pytest
from starlette.config import environ
from starlette.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database

# This sets `os.environ`, but provides some additional protection.
# If we placed it below the application import, it would raise an error
# informing us that 'TESTING' had already been read from the environment.
environ['TESTING'] = 'True'

import app


@pytest.fixture(scope="session", autouse=True)
def create_test_database():
  """
  Create a clean database on every test case.
  For safety, we should abort if a database already exists.

  We use the `sqlalchemy_utils` package here for a few helpers in consistently
  creating and dropping the database.
  """
  url = str(app.DATABASE_URL)
  engine = create_engine(url)
  assert not database_exists(url), 'Test database already exists. Aborting tests.'
  create_database(url)             # Create the test database.
  metadata.create_all(engine)      # Create the tables.
  yield                            # Run the tests.
  drop_database(url)               # Drop the test database.


@pytest.fixture()
def client():
    """
    When using the 'client' fixture in test cases, we'll get full database
    rollbacks between test cases:

    def test_homepage(client):
        url = app.url_path_for('homepage')
        response = client.get(url)
        assert response.status_code == 200
    """
    with TestClient(app) as client:
        yield client
```

## Migrations

You'll almost certainly need to be using database migrations in order to manage
incremental changes to the database. For this we'd strongly recommend
[Alembic][alembic], which is written by the author of SQLAlchemy.

```shell
$ pip install alembic
$ pip install psycopg2-binary  # Install an appropriate database driver.
$ alembic init migrations
```

Now, you'll want to set things up so that Alembic references the configured
DATABASE_URL, and uses your table metadata.

In `alembic.ini` remove the following line:

```shell
sqlalchemy.url = driver://user:pass@localhost/dbname
```

In `migrations/env.py`, you need to set the ``'sqlalchemy.url'`` configuration key,
and the `target_metadata` variable. You'll want something like this:

```python
# The Alembic Config object.
config = context.config

# Configure Alembic to use our DATABASE_URL and our table definitions...
import app
config.set_main_option('sqlalchemy.url', str(app.DATABASE_URL))
target_metadata = app.metadata

...
```

**Running migrations during testing**

It is good practice to ensure that your test suite runs the database migrations
every time it creates the test database. This will help catch any issues in your
migration scripts, and will help ensure that the tests are running against
a database that's in a consistent state with your live database.

We can adjust the `create_test_database` fixture slightly:

```python
from alembic import command
from alembic.config import Config

...

@pytest.fixture(scope="session", autouse=True)
def create_test_database():
    url = str(app.DATABASE_URL)
    engine = create_engine(url)
    assert not database_exists(url), 'Test database already exists. Aborting tests.'
    create_database(url)             # Create the test database.
    config = Config("alembic.ini")   # Run the migrations.
    command.upgrade(config, "head")
    yield                            # Run the tests.
    drop_database(url)               # Drop the test database.
```

[sqlalchemy-core]: https://docs.sqlalchemy.org/en/latest/core/
[alembic]: https://alembic.sqlalchemy.org/en/latest/
