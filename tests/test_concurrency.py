from collections.abc import Iterator
from contextvars import ContextVar

import anyio
import pytest

from starlette.applications import Starlette
from starlette.concurrency import iterate_in_threadpool, run_until_first_complete
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from tests.types import TestClientFactory


@pytest.mark.anyio
async def test_run_until_first_complete() -> None:
    task1_finished = anyio.Event()
    task2_finished = anyio.Event()

    async def task1() -> None:
        task1_finished.set()

    async def task2() -> None:
        await task1_finished.wait()
        await anyio.sleep(0)  # pragma: no cover
        task2_finished.set()  # pragma: no cover

    await run_until_first_complete((task1, {}), (task2, {}))
    assert task1_finished.is_set()
    assert not task2_finished.is_set()


def test_accessing_context_from_threaded_sync_endpoint(
    test_client_factory: TestClientFactory,
) -> None:
    ctxvar: ContextVar[bytes] = ContextVar("ctxvar")
    ctxvar.set(b"data")

    def endpoint(request: Request) -> Response:
        return Response(ctxvar.get())

    app = Starlette(routes=[Route("/", endpoint)])
    client = test_client_factory(app)

    resp = client.get("/")
    assert resp.content == b"data"


@pytest.mark.anyio
async def test_iterate_in_threadpool() -> None:
    class CustomIterable:
        def __iter__(self) -> Iterator[int]:
            yield from range(3)

    assert [v async for v in iterate_in_threadpool(CustomIterable())] == [0, 1, 2]
