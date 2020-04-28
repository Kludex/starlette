Starlette is not strictly tied to any particular database implementation.

You can use it with an asynchronous ORM, such as [GINO](https://python-gino.org/),
or use regular non-async endpoints, and integrate with [SQLAlchemy](https://www.sqlalchemy.org/).

In this documentation we'll demonstrate how to integrate against [the `databases` package](https://github.com/encode/databases),
which provides SQLAlchemy core support against a range of different database drivers.

**Note**: Previous versions of Starlette included a built-in `DatabaseMiddleware`.
This option is currently still available but should be considered as pending deprecation.
It will be removed in a future release. The legacy documentation [is available here](https://github.com/encode/starlette/blob/0.10.2/docs/database.md).

Here's a complete example, that includes table definitions, configuring a `database.Database`
instance, and a couple of endpoints that interact with the database.

**.env**

```ini
DATABASE_URL=sqlite:///test.db
```

**app.py**

```python
import databases
import sqlalchemy
from starlette.applications import Starlette
from starlette.config import Config
from starlette.responses import JSONResponse
from starlette.routing import Route


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

database = databases.Database(DATABASE_URL)


# Main application code.
async def list_notes(request):
    query = notes.select()
    results = await database.fetch_all(query)
    content = [
        {
            "text": result["text"],
            "completed": result["completed"]
        }
        for result in results
    ]
    return JSONResponse(content)

async def add_note(request):
    data = await request.json()
    query = notes.insert().values(
       text=data["text"],
       completed=data["completed"]
    )
    await database.execute(query)
    return JSONResponse({
        "text": data["text"],
        "completed": data["completed"]
    })

routes = [
    Route("/notes", endpoint=list_notes, methods=["GET"]),
    Route("/notes", endpoint=add_note, methods=["POST"]),
]

app = Starlette(
    routes=routes,
    on_startup=[database.connect],
    on_shutdown=[database.disconnect]
)
```

Finally, you will need to create the database tables. It is recommended to use
Alembic, which we briefly go over in [Migrations](#migrations)

## Queries

Queries may be made with as [SQLAlchemy Core queries][sqlalchemy-core].

The following methods are supported:

* `rows = await database.fetch_all(query)`
* `row = await database.fetch_one(query)`
* `async for row in database.iterate(query)`
* `await database.execute(query)`
* `await database.execute_many(query)`

## Transactions

Database transactions are available either as a decorator, as a
context manager, or as a low-level API.

Using a decorator on an endpoint:

```python
@database.transaction()
async def populate_note(request):
    # This database insert occurs within a transaction.
    # It will be rolled back by the `RuntimeError`.
    query = notes.insert().values(text="you won't see me", completed=True)
    await database.execute(query)
    raise RuntimeError()
```

Using a context manager:

```python
async def populate_note(request):
    async with database.transaction():
        # This database insert occurs within a transaction.
        # It will be rolled back by the `RuntimeError`.
        query = notes.insert().values(text="you won't see me", completed=True)
        await request.database.execute(query)
        raise RuntimeError()
```

Using the low-level API:

```python
async def populate_note(request):
    transaction = await database.transaction()
    try:
        # This database insert occurs within a transaction.
        # It will be rolled back by the `RuntimeError`.
        query = notes.insert().values(text="you won't see me", completed=True)
        await database.execute(query)
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
import databases

config = Config(".env")

TESTING = config('TESTING', cast=bool, default=False)
DATABASE_URL = config('DATABASE_URL', cast=databases.DatabaseURL)
TEST_DATABASE_URL = DATABASE_URL.replace(database='test_' + DATABASE_URL.database)

# Use 'force_rollback' during testing, to ensure we do not persist database changes
# between each test case.
if TESTING:
    database = databases.Database(TEST_DATABASE_URL, force_rollback=True)
else:
    database = databases.Database(DATABASE_URL)
```

We still need to set `TESTING` during a test run, and setup the test database.
Assuming we're using `py.test`, here's how our `conftest.py` might look:

```python
import pytest
from starlette.config import environ
from starlette.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database, drop_database

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
  url = str(app.TEST_DATABASE_URL)
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

Then, using our notes example above, create an initial revision:

```shell
alembic revision -m "Create notes table"
```

And populate the new file (within `migrations/versions`) with the necessary directives:

```python

def upgrade():
    op.create_table(
      'notes',
      sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
      sqlalchemy.Column("text", sqlalchemy.String),
      sqlalchemy.Column("completed", sqlalchemy.Boolean),
    )

def downgrade():
    op.drop_table('notes')
```

And run your first migration. Our notes app can now run!

```shell
alembic upgrade head
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
import app

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
