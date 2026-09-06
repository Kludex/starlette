from __future__ import annotations

import functools
from typing import Any, Literal

import pytest

from starlette.testclient import TestClient
from tests.types import TestClientFactory


@pytest.fixture
def test_client_factory(
    anyio_backend_name: Literal["asyncio", "trio"],
    anyio_backend_options: dict[str, Any],
) -> TestClientFactory:
    # anyio_backend_name defined by:
    # https://anyio.readthedocs.io/en/stable/testing.html#specifying-the-backends-to-run-on
    return functools.partial(
        TestClient,
        backend=anyio_backend_name,
        backend_options=anyio_backend_options,
    )
