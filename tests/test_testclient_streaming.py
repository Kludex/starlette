from __future__ import annotations

import subprocess
import sys
from collections.abc import AsyncGenerator
from contextlib import nullcontext
from typing import Literal

import pytest

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.routing import Route
from tests.types import TestClientFactory


@pytest.mark.parametrize("streaming", [True, False])
@pytest.mark.parametrize("lifespan", [True, False])
def test_streaming_response_copies_mutable_chunks(
    test_client_factory: TestClientFactory, streaming: bool, lifespan: bool
) -> None:
    async def chunks() -> AsyncGenerator[memoryview, None]:
        buffer = bytearray(b"one")
        yield memoryview(buffer)
        buffer[:] = b"two"
        yield memoryview(buffer)

    async def homepage(request: Request) -> StreamingResponse:
        return StreamingResponse(chunks())

    client = test_client_factory(Starlette(routes=[Route("/", homepage)]))
    with client if lifespan else nullcontext():
        if streaming:
            with client.stream("GET", "/") as response:
                assert list(response.iter_raw()) == [b"one", b"two"]
        else:
            assert client.get("/").content == b"onetwo"


@pytest.mark.skipif(sys.platform == "win32", reason="Sending SIGINT with os.kill terminates the process on Windows")
@pytest.mark.parametrize("lifespan", [True, False])
def test_interrupted_request_stops_application(anyio_backend_name: Literal["asyncio", "trio"], lifespan: bool) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from __future__ import annotations

import os
import signal
import sys
import threading
from contextlib import nullcontext

import anyio

from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.testclient import TestClient
from starlette.types import Receive, Scope, Send

started = threading.Event()
finished = threading.Event()


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    try:
        started.set()
        await anyio.sleep_forever()
    finally:
        finished.set()


def interrupt() -> None:
    assert started.wait(5)
    os.kill(os.getpid(), signal.SIGINT)


client = TestClient(Starlette(routes=[Mount("/", app=app)]), backend=sys.argv[1])
failure: KeyboardInterrupt | None = None
with client if sys.argv[2] == "True" else nullcontext():
    thread = threading.Thread(target=interrupt, daemon=True)
    thread.start()
    try:
        client.get("/")
    except KeyboardInterrupt as exc:
        failure = exc
    thread.join(5)
    assert failure is not None
    assert finished.is_set()
""",
            anyio_backend_name,
            str(lifespan),
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
