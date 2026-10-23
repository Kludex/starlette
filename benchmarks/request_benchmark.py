from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner, ChunkedReceive
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

KiB = 1024
MiB = 1024 * KiB

ReadMode = Literal["body", "stream"]


class BodyApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        body = await Request(scope, receive).body()
        await send_length(send, len(body))


class StreamApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        length = 0
        async for chunk in Request(scope, receive).stream():
            length += len(chunk)
        await send_length(send, length)


async def send_length(send: Send, length: int) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": str(length).encode()})


@dataclass(frozen=True)
class BenchmarkCase:
    mode: ReadMode
    body_size: int
    chunk_size: int

    @property
    def id(self) -> str:
        body_size = format_size(self.body_size)
        chunk_size = "single" if self.chunk_size == self.body_size else format_size(self.chunk_size)
        return f"{self.mode}-{body_size}-{chunk_size}"


READ_MODES: tuple[ReadMode, ...] = ("body", "stream")
BODY_CASES = (
    (KiB, KiB),
    (MiB, MiB),
    (MiB, 64 * KiB),
    (10 * MiB, 10 * MiB),
    (10 * MiB, 64 * KiB),
)
CASES = tuple(BenchmarkCase(mode, body_size, chunk_size) for mode in READ_MODES for body_size, chunk_size in BODY_CASES)
APPS: dict[ReadMode, ASGIApp] = {"body": BodyApp(), "stream": StreamApp()}


def format_size(size: int) -> str:
    if size >= MiB:
        return f"{size // MiB}MiB"
    return f"{size // KiB}KiB"


def http_scope() -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "root_path": "",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 80),
    }


def make_chunks(body_size: int, chunk_size: int) -> tuple[bytes, ...]:
    payload = b"x" * body_size
    return tuple(payload[offset : offset + chunk_size] for offset in range(0, body_size, chunk_size))


def dispatch(runner: ASGIRunner, app: ASGIApp, chunks: tuple[bytes, ...]) -> list[Message]:
    return runner.run(app, http_scope(), ChunkedReceive(chunks))


@pytest.fixture(scope="module", autouse=True)
def warm_apps(asgi_runner: ASGIRunner) -> None:
    chunks = (b"x" * KiB,)
    for app in APPS.values():
        for _ in range(100):
            dispatch(asgi_runner, app, chunks)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
@pytest.mark.benchmark(max_time=0.5, max_rounds=1)
def test_request_body(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture, case: BenchmarkCase) -> None:
    chunks = make_chunks(case.body_size, case.chunk_size)
    messages = benchmark.pedantic(dispatch, args=(asgi_runner, APPS[case.mode], chunks), rounds=1)

    assert messages == [
        {"type": "http.response.start", "status": 200, "headers": []},
        {"type": "http.response.body", "body": str(case.body_size).encode()},
    ]
    benchmark.extra_info["read_mode"] = case.mode
    benchmark.extra_info["body_bytes"] = case.body_size
    benchmark.extra_info["chunk_bytes"] = case.chunk_size
    benchmark.extra_info["chunks"] = len(chunks)
