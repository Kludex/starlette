Starlette encourages a strict separation of configuration from code,
following [the twelve-factor pattern][twelve-factor].

Configuration should be stored in environment variables, or in a ".env" file
that is not committed to source control.

**app.py**:

```python
from starlette.applications import Starlette
from starlette.config import Config
from starlette.datastructures import CommaSeparatedStrings, DatabaseURL, Secret

# Config will be read from environment variables and/or ".env" files.
config = Config(".env")

DEBUG = config('DEBUG', cast=bool, default=False)
DATABASE_URL = config('DATABASE_URL', cast=DatabaseURL)
SECRET_KEY = config('SECRET_KEY', cast=Secret)
ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=CommaSeparatedStrings)

app = Starlette()
app.debug = DEBUG
...
```

**.env**:

```shell
# Don't commit this to source control.
# Eg. Include ".env" in your `.gitignore` file.
DEBUG=True
DATABASE_URL=postgresql://localhost/myproject
SECRET_KEY=43n080musdfjt54t-09sdgr
ALLOWED_HOSTS="127.0.0.1", "localhost"
```

## Configuration precedence

The order in which configuration values are read is:

* From an environment variable.
* From the ".env" file.
* The default value given in `config`.

If none of those match, then `config(...)` will raise an error.

## Secrets

For sensitive keys, the `Secret` class is useful, since it helps minimize
occasions where the value it holds could leak out into tracebacks or
other code introspection.

To get the value of a `Secret` instance, you must explicitly cast it to a string.
You should only do this at the point at which the value is used.

```python
>>> from myproject import settings
>>> settings.SECRET_KEY
Secret('**********')
>>> str(settings.SECRET_KEY)
'98n349$%8b8-7yjn0n8y93T$23r'
```

Similarly, the `URL` and `DatabaseURL` class will hide any password component
in their representations.

```python
>>> from myproject import settings
>>> settings.DATABASE_URL
DatabaseURL('postgresql://admin:**********@192.168.0.8/my-application')
>>> str(settings.DATABASE_URL)
'postgresql://admin:Fkjh348htGee4t3@192.168.0.8/my-application'
```

## CommaSeparatedStrings

For holding multiple inside a single config key, the `CommaSeparatedStrings`
type is useful.

```python
>>> from myproject import settings
>>> print(settings.ALLOWED_HOSTS)
CommaSeparatedStrings(['127.0.0.1', 'localhost'])
>>> print(list(settings.ALLOWED_HOSTS))
['127.0.0.1', 'localhost']
>>> print(len(settings.ALLOWED_HOSTS[0]))
2
>>> print(settings.ALLOWED_HOSTS[0])
'127.0.0.1'
```

## Reading or modifying the environment

In some cases you might want to read or modify the environment variables programmatically.
This is particularly useful in testing, where you may want to override particular
keys in the environment.

Rather than reading or writing from `os.environ`, you should use Starlette's
`environ` instance. This instance is a mapping onto the standard `os.environ`
that additionally protects you by raising an error if any environment variable
is set *after* the point that it has already been read by the configuration.

If you're using `pytest`, then you can setup any initial environment in
`tests/conftest.py`.

**tests/conftest.py**:

```python
from starlette.config import environ

environ['TESTING'] = 'TRUE'
```

## A full example

Structuring large applications can be complex. You need proper separation of
configuration and code, database isolation during tests, separate test and
production databases, etc...

Here we'll take a look at a complete example, that demonstrates how
we can start to structure an application.

First, let's keep our settings, our database table definitions, and our
application logic separated:

**myproject/settings.py**:

```python
from starlette.config import Config
from starlette.datastructures import DatabaseURL, Secret

config = Config(".env")

DEBUG = config('DEBUG', cast=bool, default=False)
TESTING = config('TESTING', cast=bool, default=False)
SECRET_KEY = config('SECRET_KEY', cast=Secret)

DATABASE_URL = config('DATABASE_URL', cast=DatabaseURL)
if TESTING:
    DATABASE_URL = DATABASE_URL.replace(database='test_' + DATABASE_URL.database)
```

**myproject/tables.py**:

```python
import sqlalchemy

# Database table definitions.
metadata = sqlalchemy.MetaData()

organisations = sqlalchemy.Table(
    ...
)
```

**myproject/app.py**

```python
from starlette.applications import Starlette
from starlette.middleware.database import DatabaseMiddleware
from starlette.middleware.session import SessionMiddleware
from myproject import settings


app = Starlette()

app.debug = settings.DEBUG

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
)
app.add_middleware(
    DatabaseMiddleware,
    database_url=settings.DATABASE_URL,
    rollback_on_shutdown=settings.TESTING
)

@app.route('/', methods=['GET'])
async def homepage(request):
    ...
```

Now let's deal with our test configuration.
We'd like to create a new test database every time the test suite runs,
and drop it once the tests complete. We'd also like to ensure

**tests/conftest.py**:

```python
from starlette.config import environ
from starlette.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database

# This line would raise an error if we use it after 'settings' has been imported.
environ['TESTING'] = 'TRUE'

from myproject import settings
from myproject.app import app
from myproject.tables import metadata


@pytest.fixture(autouse=True, scope="session")
def setup_test_database():
    """
    Create a clean test database every time the tests are run.
    """
    url = str(settings.DATABASE_URL)
    engine = create_engine(url)
    assert not database_exists(url), 'Test database already exists. Aborting tests.'
    create_database(url)             # Create the test database.
    metadata.create_all(engine)      # Create the tables.
    yield                            # Run the tests.
    drop_database(url)               # Drop the test database.


@pytest.fixture()
def client():
    """
    Make a 'client' fixture available to test cases.
    """
    # Our fixture is created within a context manager. This ensures that
    # application startup and shutdown run for every test case.
    #
    # Because we've configured the DatabaseMiddleware with `rollback_on_shutdown`
    # we'll get a complete rollback to the initial state after each test case runs.
    with TestClient(app) as test_client:
        yield test_client
```

[twelve-factor]: https://12factor.net/config
