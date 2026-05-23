from __future__ import annotations

import functools
from typing import Any

import pytest

from starlette.testclient import TestClient, make_anyio_backend_autouse_fixture
from tests.types import TestClientFactory

# Publishes anyio_backend_name into starlette.testclient's ContextVar so
# that TestClient() without a backend kwarg picks up the parametrized
# backend automatically.
_publish_anyio_backend = make_anyio_backend_autouse_fixture()


@pytest.fixture
def test_client_factory(anyio_backend_options: dict[str, Any]) -> TestClientFactory:
    # anyio_backend_name is consumed by the autouse fixture above; the
    # TestClient will auto-detect the backend from the ContextVar.
    return functools.partial(TestClient, backend_options=anyio_backend_options)
