import os

import pytest

from starlette.config import Config, Environ, EnvironError
from starlette.datastructures import URL, Secret

from pathlib import Path


def test_config(tmpdir, monkeypatch):
    path = os.path.join(tmpdir, ".env")
    with open(path, "w") as file:
        file.write("# Do not commit to source control\n")
        file.write("DATABASE_URL=postgres://user:pass@localhost/dbname\n")
        file.write("REQUEST_HOSTNAME=example.com\n")
        file.write("SECRET_KEY=12345\n")
        file.write("BOOL_AS_INT=0\n")
        file.write("\n")
        file.write("\n")

    config = Config(path, environ={"DEBUG": "true"})

    DEBUG = config("DEBUG", cast=bool)
    DATABASE_URL = config("DATABASE_URL", cast=URL)
    REQUEST_TIMEOUT = config("REQUEST_TIMEOUT", cast=int, default=10)
    REQUEST_HOSTNAME = config("REQUEST_HOSTNAME")
    SECRET_KEY = config("SECRET_KEY", cast=Secret)
    assert config("BOOL_AS_INT", cast=bool) is False

    assert DEBUG is True
    assert DATABASE_URL.path == "/dbname"
    assert DATABASE_URL.password == "pass"
    assert DATABASE_URL.username == "user"
    assert REQUEST_TIMEOUT == 10
    assert REQUEST_HOSTNAME == "example.com"
    assert repr(SECRET_KEY) == "Secret('**********')"
    assert str(SECRET_KEY) == "12345"

    with pytest.raises(KeyError):
        config.get("MISSING")

    with pytest.raises(ValueError):
        config.get("DEBUG", cast=int)

    with pytest.raises(ValueError):
        config.get("REQUEST_HOSTNAME", cast=bool)

    config = Config(Path(path))
    REQUEST_HOSTNAME= config("REQUEST_HOSTNAME")
    assert REQUEST_HOSTNAME == "example.com"

    config = Config()
    monkeypatch.setenv("STARLETTE_EXAMPLE_TEST", "123")
    monkeypatch.setenv("BOOL_AS_INT", "1")
    assert config.get("STARLETTE_EXAMPLE_TEST", cast=int) == 123
    assert config.get("BOOL_AS_INT", cast=bool) is True

    monkeypatch.setenv("BOOL_AS_INT", "2")
    with pytest.raises(ValueError):
        config.get("BOOL_AS_INT", cast=bool)

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
