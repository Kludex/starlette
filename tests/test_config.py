import os
import typing
from pathlib import Path
from typing import Any, Optional

import pytest
from typing_extensions import assert_type

from starlette.config import Config, Environ, EnvironError
from starlette.datastructures import URL, Secret


def test_config_types() -> None:
    """
    We use `assert_type` to test the types returned by Config via mypy.
    """
    config = Config(environ={"STR": "some_str_value", "STR_CAST": "some_str_value", "BOOL": "true"})

    assert_type(config("STR"), str)
    assert_type(config("STR_DEFAULT", default=""), str)
    assert_type(config("STR_CAST", cast=str), str)
    assert_type(config("STR_NONE", default=None), Optional[str])
    assert_type(config("STR_CAST_NONE", cast=str, default=None), Optional[str])
    assert_type(config("STR_CAST_STR", cast=str, default=""), str)

    assert_type(config("BOOL", cast=bool), bool)
    assert_type(config("BOOL_DEFAULT", cast=bool, default=False), bool)
    assert_type(config("BOOL_NONE", cast=bool, default=None), Optional[bool])

    def cast_to_int(v: Any) -> int:
        return int(v)

    # our type annotations allow these `cast` and `default` configurations, but
    # the code will error at runtime.
    with pytest.raises(ValueError):
        config("INT_CAST_DEFAULT_STR", cast=cast_to_int, default="true")
    with pytest.raises(ValueError):
        config("INT_DEFAULT_STR", cast=int, default="true")


def test_config(tmpdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

    def cast_to_int(v: typing.Any) -> int:
        return int(v)

    DEBUG = config("DEBUG", cast=bool)
    DATABASE_URL = config("DATABASE_URL", cast=URL)
    REQUEST_TIMEOUT = config("REQUEST_TIMEOUT", cast=int, default=10)
    REQUEST_HOSTNAME = config("REQUEST_HOSTNAME")
    MAIL_HOSTNAME = config("MAIL_HOSTNAME", default=None)
    SECRET_KEY = config("SECRET_KEY", cast=Secret)
    UNSET_SECRET = config("UNSET_SECRET", cast=Secret, default=None)
    EMPTY_SECRET = config("EMPTY_SECRET", cast=Secret, default="")
    assert config("BOOL_AS_INT", cast=bool) is False
    assert config("BOOL_AS_INT", cast=cast_to_int) == 0
    assert config("DEFAULTED_BOOL", cast=cast_to_int, default=True) == 1

    assert DEBUG is True
    assert DATABASE_URL.path == "/dbname"
    assert DATABASE_URL.password == "pass"
    assert DATABASE_URL.username == "user"
    assert REQUEST_TIMEOUT == 10
    assert REQUEST_HOSTNAME == "example.com"
    assert MAIL_HOSTNAME is None
    assert repr(SECRET_KEY) == "Secret('**********')"
    assert str(SECRET_KEY) == "12345"
    assert bool(SECRET_KEY)
    assert not bool(EMPTY_SECRET)
    assert not bool(UNSET_SECRET)

    with pytest.raises(KeyError):
        config.get("MISSING")

    with pytest.raises(ValueError):
        config.get("DEBUG", cast=int)

    with pytest.raises(ValueError):
        config.get("REQUEST_HOSTNAME", cast=bool)

    config = Config(Path(path))
    REQUEST_HOSTNAME = config("REQUEST_HOSTNAME")
    assert REQUEST_HOSTNAME == "example.com"

    config = Config()
    monkeypatch.setenv("STARLETTE_EXAMPLE_TEST", "123")
    monkeypatch.setenv("BOOL_AS_INT", "1")
    assert config.get("STARLETTE_EXAMPLE_TEST", cast=int) == 123
    assert config.get("BOOL_AS_INT", cast=bool) is True

    monkeypatch.setenv("BOOL_AS_INT", "2")
    with pytest.raises(ValueError):
        config.get("BOOL_AS_INT", cast=bool)


def test_missing_env_file_raises(tmpdir: Path) -> None:
    path = os.path.join(tmpdir, ".env")

    with pytest.warns(UserWarning, match=f"Config file '{path}' not found."):
        Config(path)


def test_environ() -> None:
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


def test_config_with_env_prefix(tmpdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = Config(environ={"APP_DEBUG": "value", "ENVIRONMENT": "dev"}, env_prefix="APP_")
    assert config.get("DEBUG") == "value"

    with pytest.raises(KeyError):
        config.get("ENVIRONMENT")
