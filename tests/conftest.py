from __future__ import annotations

import functools
import sys
from collections.abc import Iterator
from typing import Any, Literal

import pytest
from blockbuster import BlockBuster, BlockBusterFunction

from starlette.testclient import TestClient
from tests.types import TestClientFactory


@pytest.fixture(autouse=True)
def blockbuster() -> Iterator[None]:
    bb = BlockBuster("starlette")
    if sys.version_info >= (3, 15):  # pragma: no cover - Requires Python 3.15 or newer.
        # Python 3.15 makes ScandirIterator immutable.
        bb.functions["os.scandir"] = BlockBusterFunction(None, "os.scandir", scanned_modules="starlette")
    bb.functions["os.stat"].can_block_in("/mimetypes.py", "init")
    bb.functions["os.stat"].can_block_in("<frozen linecache>", {"checkcache", "updatecache"})
    bb.activate()
    try:
        yield
    finally:
        bb.deactivate()


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
