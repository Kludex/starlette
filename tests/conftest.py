import functools
from typing import Any, Callable, Dict

import pytest

from starlette.testclient import TestClient

TestClientFactory = Callable[..., TestClient]


@pytest.fixture
def test_client_factory(
    anyio_backend_name: str,
    anyio_backend_options: Dict[str, Any],
) -> TestClientFactory:
    # anyio_backend_name defined by:
    # https://anyio.readthedocs.io/en/stable/testing.html#specifying-the-backends-to-run-on
    return functools.partial(
        TestClient,
        backend=anyio_backend_name,
        backend_options=anyio_backend_options,
    )
