from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner
from starlette.responses import StreamingResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

KiB = 1024
MiB = 1024 * KiB


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    body_size: int
    chunk_size: int


CASES = (
    BenchmarkCase("1KiB-single", KiB, KiB),
    BenchmarkCase("1MiB-1KiB", MiB, KiB),
    BenchmarkCase("1MiB-64KiB", MiB, 64 * KiB),
    BenchmarkCase("1MiB-single", MiB, MiB),
)


class StreamingApp:
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = chunks

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await StreamingResponse(iter_chunks(self.chunks))(scope, receive, send)


async def iter_chunks(chunks: tuple[bytes, ...]) -> AsyncIterator[bytes]:
    for chunk in chunks:
        yield chunk


def make_chunks(body_size: int, chunk_size: int) -> tuple[bytes, ...]:
    payload = b"x" * body_size
    return tuple(payload[offset : offset + chunk_size] for offset in range(0, body_size, chunk_size))


def http_scope() -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "root_path": "",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 80),
    }


def dispatch(runner: ASGIRunner, app: ASGIApp) -> list[Message]:
    return runner.run(app, http_scope())


@pytest.fixture(scope="module", autouse=True)
def warm_streaming(asgi_runner: ASGIRunner) -> None:
    app = StreamingApp((b"x",))
    for _ in range(100):
        dispatch(asgi_runner, app)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
@pytest.mark.benchmark(max_time=0.5, max_rounds=1)
def test_streaming_response(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture, case: BenchmarkCase) -> None:
    chunks = make_chunks(case.body_size, case.chunk_size)
    messages = benchmark.pedantic(dispatch, args=(asgi_runner, StreamingApp(chunks)), rounds=1)

    assert messages[0] == {"type": "http.response.start", "status": 200, "headers": []}
    assert messages[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
    assert len(messages) == len(chunks) + 2
    assert sum(len(message.get("body", b"")) for message in messages[1:]) == case.body_size
    assert all(message.get("more_body") is True for message in messages[1:-1])
    benchmark.extra_info["body_bytes"] = case.body_size
    benchmark.extra_info["chunk_bytes"] = case.chunk_size
    benchmark.extra_info["chunks"] = len(chunks)
