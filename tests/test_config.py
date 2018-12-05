import os

import pytest

from starlette.config import Config, Environ, EnvironError
from starlette.datastructures import DatabaseURL


def test_config(tmpdir):
    path = os.path.join(tmpdir, ".env")
    with open(path, "w") as file:
        file.write("# Do not commit to source control\n")
        file.write(
            "DATABASE_URL=postgres://username:password@localhost/database_name\n"
        )
        file.write("REQUEST_HOSTNAME=example.com\n")
        file.write("\n")
        file.write("\n")

    config = Config(path, environ={"DEBUG": "true"})

    DEBUG = config.get("DEBUG", cast=bool)
    DATABASE_URL = config.get("DATABASE_URL", cast=DatabaseURL)
    REQUEST_TIMEOUT = config.get("REQUEST_TIMEOUT", cast=int, default=10)
    REQUEST_HOSTNAME = config.get("REQUEST_HOSTNAME")

    assert DEBUG is True
    assert DATABASE_URL.name == "database_name"
    assert REQUEST_TIMEOUT == 10
    assert REQUEST_HOSTNAME == "example.com"

    with pytest.raises(KeyError):
        config.get("MISSING")

    with pytest.raises(ValueError):
        config.get("DEBUG", cast=int)

    with pytest.raises(ValueError):
        config.get("REQUEST_HOSTNAME", cast=bool)

    os.environ["STARLETTE_EXAMPLE_TEST"] = "123"
    config = Config()
    assert config.get("STARLETTE_EXAMPLE_TEST", cast=int) == 123


def test_environ():
    environ = Environ()

    # We can mutate the environ at this point.
    environ["TESTING"] = "True"
    environ["GONE"] = "123"
    del environ["GONE"]

    # We can read the environ.
    assert environ["TESTING"] == "True"
    assert "GONE" not in environ

    # We cannot mutate these keys now that we've read them.
    with pytest.raises(EnvironError):
        environ["TESTING"] = "False"

    with pytest.raises(EnvironError):
        del environ["GONE"]

    # Test coverage of abstract methods for MutableMapping.
    environ = Environ()
    assert list(iter(environ)) == list(iter(os.environ))
    assert len(environ) == len(os.environ)
