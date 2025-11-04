Starlette is not strictly tied to any particular database implementation.

You can use it with an asynchronous ORM, such as [GINO](https://python-gino.org/) or [SQLAlchemy](https://www.sqlalchemy.org/), or use regular non-async endpoints.

In this documentation we'll demonstrate how to integrate against [SQLAlchemy](https://www.sqlalchemy.org/).

Here's a complete example, that includes table definitions, configuring a database connection, and a couple of endpoints that interact with the database.

```ini title=".env"
DATABASE_URL=sqlite+aiosqlite:///test.db
```

```python title="app.py"
from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import MetaData, select
from sqlalchemy.ext.asyncio import AsyncAttrs, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.engine import make_url

from starlette.applications import Starlette
from starlette.config import Config
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


# Configuration from environment variables or '.env' file.
config = Config(".env")
DATABASE_URL = config(
    "DATABASE_URL", cast=make_url, default="sqlite+aiosqlite:///test.db"
)

# Database table definitions.
metadata = MetaData()


class Base(AsyncAttrs, DeclarativeBase):
    pass


class Note(Base):
    __tablename__ = "notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    text: Mapped[str]
    completed: Mapped[bool]


engine = create_async_engine(DATABASE_URL, echo=True)
async_session = async_sessionmaker(engine, expire_on_commit=False)


# Main application code
@asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    yield
    await engine.dispose()


async def list_notes(request: Request):
    async with async_session() as session:
        query = await session.execute(select(Note))
        results = query.scalars().all()

    return JSONResponse(
        [{"text": result.text, "completed": result.completed} for result in results]
    )


async def add_note(request: Request):
    data = await request.json()
    new_note = Note(text=data["text"], completed=data["completed"])

    async with async_session() as session:
        async with session.begin():
            session.add(new_note)

    return JSONResponse({"text": new_note.text, "completed": new_note.completed})


routes = [
    Route("/notes", endpoint=list_notes, methods=["GET"]),
    Route("/notes", endpoint=add_note, methods=["POST"]),
]

app = Starlette(routes=routes, lifespan=lifespan)

```

Finally, you will need to create the database tables. It is recommended to use
Alembic, which we briefly go over in [Migrations](#migrations)

## Testing

There are a few things that we want to ensure when running tests against
a service that uses a database. Our requirements should be:

- Use a separate database for testing.
- Create a new test database every time we run the tests.
- Ensure that the database state is isolated between each test case.

Install dependencies for testing:

```sh
$ pip install aiosqlite greenlet httpx pytest pytest_asyncio sqlalchemy_utils
```

!!! note

    `pytest-asyncio` requires setting the option `asyncio_default_fixture_loop_scope` but does not provide a default. To suppress this deprecation warning add the following to the project config:

    ```
    # pyproject.toml
    [tool.pytest.ini_options]
    asyncio_default_fixture_loop_scope = "function"
    ```

Here's how we need to structure our application and tests in order to
meet those requirements:

```diff title="app.py"
from starlette.applications import Starlette
from starlette.config import Config

config = Config(".env")

+ TESTING = config("TESTING", cast=bool, default=False)
DATABASE_URL = config(
    "DATABASE_URL", cast=make_url, default="sqlite+aiosqlite:///test.db"
)

+ if TESTING:
+    DATABASE_URL = DATABASE_URL.set(database="test_" + DATABASE_URL.database)

engine = create_async_engine(DATABASE_URL, echo=True)
async_session = async_sessionmaker(engine, expire_on_commit=False)
```

We still need to set `TESTING` during a test run, and setup the test database.
Assuming we're using `pytest`, here's how our `conftest.py` might look:

```python title="conftest.py"
import pytest
import pytest_asyncio

from starlette.config import environ
from starlette.testclient import TestClient

from sqlalchemy_utils import database_exists, create_database, drop_database
from sqlalchemy.util import greenlet_spawn
from sqlalchemy.ext.asyncio import create_async_engine

# This sets `os.environ`, but provides some additional protection.
# If we placed it below the application import, it would raise an error
# informing us that 'TESTING' had already been read from the environment.
environ["TESTING"] = "True"
from app import Base, DATABASE_URL, app


@pytest_asyncio.fixture(scope="function", autouse=True)
async def create_test_database():
    """
    Create a clean database on every test case.
    For safety, we should abort if a database already exists.

    We use the `sqlalchemy_utils` package here for a few helpers in consistently
    creating and dropping the database.
    """
    assert not database_exists(
        DATABASE_URL
    ), "Test database already exists. Aborting tests."

    await greenlet_spawn(create_database, DATABASE_URL)  # Create the test database.

    engine = create_async_engine(DATABASE_URL, echo=True)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)  # Create the tables.

    yield  # Run the tests.
    drop_database(DATABASE_URL)  # Drop the test database.


@pytest.fixture()
def client():
    with TestClient(app) as client:
        yield client

```

When using the 'client' fixture in test cases, we'll get full database rollbacks between test cases:

```python title="test_notes.py"
from app import app


def test_list_notes(client):
    url = app.url_path_for("list_notes")
    response = client.get(url)
    assert response.status_code == 200
    assert response.json() == []


def test_add_note(client):
    url = app.url_path_for("list_notes")
    response = client.post(url, json={"text": "Test note", "completed": False})
    assert response.status_code == 200
    assert response.json() == {"text": "Test note", "completed": False}
    response = client.get(url)
    assert response.status_code == 200
    assert response.json() == [
        {"text": "Test note", "completed": False}
    ], "Note not found in the list"

```

## Migrations

You'll almost certainly need to be using database migrations in order to manage
incremental changes to the database. For this we'd strongly recommend
[Alembic][alembic], which is written by the author of SQLAlchemy.

```shell
$ pip install alembic
$ alembic init -t async migrations
```

Now, you'll want to set things up so that Alembic references the configured
DATABASE_URL, and uses your table metadata.

In `alembic.ini` remove the following line:

```shell
sqlalchemy.url = driver://user:pass@localhost/dbname
```

In `migrations/env.py`, you need to set the `'sqlalchemy.url'` configuration key,
and the `target_metadata` variable. You'll want something like this:

```python
# The Alembic Config object.
config = context.config

# Configure Alembic to use our DATABASE_URL and our table definitions...
from app import DATABASE_URL, metadata
config.set_main_option('sqlalchemy.url', str(DATABASE_URL))
target_metadata = metadata

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
      sa.Column("id", sa.Integer, primary_key=True),
      sa.Column("text", sa.String),
      sa.Column("completed", sa.Boolean),
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

Adjust `migrations/env.py`:

```python
def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""

    connectable = config.attributes.get("connection", None)

    if connectable is None:
        asyncio.run(run_async_migrations())
    else:
        do_run_migrations(connectable)
```

See [Programmatic API use (connection sharing) With Asyncio](https://alembic.sqlalchemy.org/en/latest/cookbook.html#programmatic-api-use-connection-sharing-with-asyncio) from the Alembic docs for more details.

We can adjust the `create_test_database` fixture slightly:

```diff
+ from alembic import command
+ from alembic.config import Config
- from app import Base, DATABASE_URL, app
+ from app import DATABASE_URL, app

...

+ def run_upgrade(connection, cfg):
+   cfg.attributes["connection"] = connection
+   command.upgrade(cfg, "head")


+ async def run_async_upgrade():
+     async_engine = create_async_engine(DATABASE_URL, echo=True)
+     async with async_engine.begin() as conn:
+         await conn.run_sync(run_upgrade, Config("alembic.ini"))

@pytest_asyncio.fixture(scope="function", autouse=True)
async def create_test_database():
    """
    Create a clean database on every test case.
    For safety, we should abort if a database already exists.

    We use the `sqlalchemy_utils` package here for a few helpers in consistently
    creating and dropping the database.
    """
    assert not database_exists(
        DATABASE_URL
    ), "Test database already exists. Aborting tests."

    await greenlet_spawn(create_database, DATABASE_URL)  # Create the test database.

-    engine = create_async_engine(DATABASE_URL, echo=True)
-    async with engine.begin() as conn:
-        await conn.run_sync(Base.metadata.create_all)  # Create the tables.
+   await run_async_upgrade()

    yield  # Run the tests.
    drop_database(DATABASE_URL)  # Drop the test database.
```

[sqlalchemy-core]: https://docs.sqlalchemy.org/en/latest/core/
[alembic]: https://alembic.sqlalchemy.org/en/latest/
