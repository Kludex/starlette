from __future__ import annotations

from collections.abc import Iterator

import pytest

from benchmarks._utils import ASGIRunner


@pytest.fixture(scope="module")
def asgi_runner() -> Iterator[ASGIRunner]:
    runner = ASGIRunner()
    yield runner
    runner.close()
