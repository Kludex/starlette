import os

import pytest

from starlette.config import Config
from starlette.datastructures import URL


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
    DATABASE_URL = config.get("DATABASE_URL", cast=URL)
    REQUEST_TIMEOUT = config.get("REQUEST_TIMEOUT", cast=int, default=10)
    REQUEST_HOSTNAME = config.get("REQUEST_HOSTNAME")

    assert DEBUG is True
    assert str(DATABASE_URL) == "postgres://username:password@localhost/database_name"
    assert (
        repr(DATABASE_URL)
        == "URL('postgres://username:********@localhost/database_name')"
    )
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
