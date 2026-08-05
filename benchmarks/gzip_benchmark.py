from __future__ import annotations

import asyncio
import gzip
import hashlib
import io
import json
from collections.abc import Iterator
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from typing import Literal

import anyio
import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from starlette.middleware.gzip import GZipMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

KiB = 1024
MiB = 1024 * KiB

PayloadKind = Literal["json", "text", "incompressible"]
BypassReason = Literal["below-minimum-size", "content-encoding", "event-stream", "pathsend"]


@dataclass(frozen=True)
class BenchmarkCase:
    payload_kind: PayloadKind
    size: int
    level: int

    @property
    def id(self) -> str:
        size = f"{self.size // MiB}MiB" if self.size >= MiB else f"{self.size // KiB}KiB"
        return f"{self.payload_kind}-{size}-level-{self.level}"


@dataclass(frozen=True)
class BypassCase:
    reason: BypassReason
    body_size: int


class StaticResponseApp:
    def __init__(self, messages: tuple[Message, ...]) -> None:
        self.messages = messages

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        for message in self.messages:
            outgoing_message = dict(message)
            if "headers" in outgoing_message:
                outgoing_message["headers"] = list(outgoing_message["headers"])
            await send(outgoing_message)


class ASGIRunner:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()

    def run(self, app: ASGIApp, scope: Scope) -> list[Message]:
        return self.loop.run_until_complete(run_asgi(app, scope))

    def close(self) -> None:
        self.loop.close()


async def run_asgi(app: ASGIApp, scope: Scope) -> list[Message]:
    messages: list[Message] = []

    async def receive() -> Message:
        raise AssertionError("The benchmark app must not receive a request body")

    async def send(message: Message) -> None:
        messages.append(message)

    await app(scope, receive, send)
    return messages


@dataclass
class ResponsePair:
    loop: asyncio.AbstractEventLoop
    large_app: ASGIApp
    tiny_app: ASGIApp
    scope: Scope
    payload: bytes
    large_task: asyncio.Task[list[Message]] | None = None
    tiny_messages: list[Message] | None = None

    async def warm_worker(self) -> None:
        await anyio.to_thread.run_sync(bool)

    def run_until_tiny_response(self) -> None:
        self.loop.run_until_complete(self._run_until_tiny_response())

    async def _run_until_tiny_response(self) -> None:
        self.large_task = asyncio.create_task(run_asgi(self.large_app, self.scope))
        tiny_task = asyncio.create_task(run_asgi(self.tiny_app, self.scope))
        self.tiny_messages = await tiny_task

    def drain_and_validate(self) -> None:
        self.loop.run_until_complete(self._drain_and_validate())

    async def _drain_and_validate(self) -> None:
        assert self.large_task is not None
        large_messages = await self.large_task
        assert self.tiny_messages is not None

        assert len(large_messages) == 2
        assert large_messages[0]["type"] == "http.response.start"
        assert (b"content-encoding", b"gzip") in large_messages[0]["headers"]
        assert large_messages[1]["type"] == "http.response.body"
        compressed = large_messages[1]["body"]
        assert isinstance(compressed, bytes)
        assert gzip.decompress(compressed) == self.payload

        assert len(self.tiny_messages) == 2
        assert self.tiny_messages[0]["type"] == "http.response.start"
        assert (b"content-encoding", b"gzip") not in self.tiny_messages[0]["headers"]
        assert self.tiny_messages[1] == {"type": "http.response.body", "body": b"{}"}


@contextmanager
def response_pair(large_app: ASGIApp, tiny_app: ASGIApp, scope: Scope, payload: bytes) -> Iterator[ResponsePair]:
    with closing(asyncio.new_event_loop()) as loop:
        pair = ResponsePair(loop, large_app, tiny_app, scope, payload)
        loop.run_until_complete(pair.warm_worker())
        yield pair
        pair.drain_and_validate()


class ResponsivenessBenchmark:
    def __init__(self, large_app: ASGIApp, tiny_app: ASGIApp, scope: Scope, payload: bytes) -> None:
        self.large_app = large_app
        self.tiny_app = tiny_app
        self.scope = scope
        self.payload = payload
        self._stack: ExitStack | None = None
        self._pair: ResponsePair | None = None

    def setup(self) -> None:
        stack = ExitStack()
        pair = stack.enter_context(response_pair(self.large_app, self.tiny_app, self.scope, self.payload))
        self._stack = stack
        self._pair = pair

    def run_until_tiny_response(self) -> None:
        assert self._pair is not None
        self._pair.run_until_tiny_response()

    def teardown(self) -> None:
        assert self._stack is not None
        self._stack.close()
        self._stack = None
        self._pair = None


# All compression levels are compared at 1 MiB. The size curve uses three
# representative levels so that the suite still reaches 10 MiB without making
# every CI run exercise the full large-payload Cartesian product.
PAYLOAD_KINDS: tuple[PayloadKind, ...] = ("json", "text", "incompressible")
CASES = tuple(
    BenchmarkCase(payload_kind, MiB, level) for payload_kind in PAYLOAD_KINDS for level in range(1, 10)
) + tuple(
    BenchmarkCase(payload_kind, size, level)
    for payload_kind in PAYLOAD_KINDS
    for size in (32 * KiB, 256 * KiB, 5 * MiB, 10 * MiB)
    for level in (1, 6, 9)
)


def make_json_payload(size: int) -> bytes:
    """Build a deterministic, valid JSON document of exactly ``size`` bytes."""
    prefix = b'{"requests":['
    padding_prefix = b'],"padding":"'
    suffix = b'"}'
    output = io.BytesIO()
    output.write(prefix)

    index = 0
    while True:
        row = json.dumps(
            {
                "id": index,
                "timestamp": f"2026-08-04T12:{index % 60:02d}:{index * 7 % 60:02d}.{index * 997 % 1000:03d}Z",
                "method": ("GET", "POST", "PATCH", "DELETE")[index % 4],
                "path": f"/api/v1/projects/{index % 1_009}/events/{index * 17 % 65_537}",
                "status": (200, 201, 204, 400, 404, 409, 422, 500)[index % 8],
                "duration_ms": round((index * 37 % 10_000) / 100, 2),
                "request_id": f"{index * 0x9E3779B97F4A7C15 % (1 << 128):032x}",
                "message": ("request completed", "validation failed", "resource updated")[index % 3],
            },
            separators=(",", ":"),
        ).encode()
        separator = b"," if index else b""
        required_tail = len(padding_prefix) + len(suffix)
        if output.tell() + len(separator) + len(row) + required_tail > size:
            break
        output.write(separator)
        output.write(row)
        index += 1

    output.write(padding_prefix)
    output.write(b"x" * (size - output.tell() - len(suffix)))
    output.write(suffix)
    payload = output.getvalue()
    assert len(payload) == size
    return payload


def make_text_payload(size: int) -> bytes:
    paragraph = (
        b"Starlette is a lightweight ASGI framework/toolkit, which is ideal for building async web services in Python. "
        b"It is production-ready and gives you the following: seriously impressive performance, WebSocket support, "
        b"in-process background tasks, startup and shutdown events, and a test client built on HTTPX.\n"
    )
    return (paragraph * (size // len(paragraph) + 1))[:size]


def make_payload(kind: PayloadKind, size: int) -> bytes:
    if kind == "json":
        return make_json_payload(size)
    if kind == "text":
        return make_text_payload(size)
    # SHAKE provides deterministic high-entropy bytes without keeping another
    # 10 MiB random-data buffer alive alongside the returned payload.
    return hashlib.shake_256(b"starlette-gzip-benchmark-v1").digest(size)


def make_bypass_messages(case: BypassCase) -> tuple[Message, ...]:
    headers = [(b"content-type", b"application/json"), (b"content-length", str(case.body_size).encode())]
    if case.reason == "content-encoding":
        headers.append((b"content-encoding", b"br"))
    elif case.reason == "event-stream":
        headers[0] = (b"content-type", b"text/event-stream")

    response_start: Message = {"type": "http.response.start", "status": 200, "headers": headers}
    if case.reason == "pathsend":
        response_body: Message = {"type": "http.response.pathsend", "path": "/tmp/starlette-benchmark"}
    else:
        response_body = {"type": "http.response.body", "body": b"x" * case.body_size}
    return response_start, response_body


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
@pytest.mark.benchmark(max_time=0.5, max_rounds=10)
def test_gzip(benchmark: BenchmarkFixture, case: BenchmarkCase) -> None:
    # Payload construction is intentionally outside the measured region. Cases
    # are function-scoped, so only one source payload is resident at a time.
    payload = make_payload(case.payload_kind, case.size)
    messages: tuple[Message, ...] = (
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
        },
        {"type": "http.response.body", "body": payload},
    )
    app = GZipMiddleware(StaticResponseApp(messages), minimum_size=0, compresslevel=case.level)
    scope: Scope = {"type": "http", "headers": [(b"accept-encoding", b"gzip")]}
    with closing(ASGIRunner()) as runner:
        sent = benchmark.pedantic(runner.run, args=(app, scope), rounds=1)

    assert len(sent) == 2
    assert sent[0]["type"] == "http.response.start"
    assert (b"content-encoding", b"gzip") in sent[0]["headers"]
    assert sent[1]["type"] == "http.response.body"
    compressed = sent[1]["body"]
    assert isinstance(compressed, bytes)

    assert gzip.decompress(compressed) == payload
    benchmark.extra_info["input_bytes"] = len(payload)
    benchmark.extra_info["output_bytes"] = len(compressed)
    benchmark.extra_info["compression_ratio"] = len(compressed) / len(payload)


@pytest.mark.benchmark(max_time=0.5, max_rounds=1)
def test_gzip_event_loop_responsiveness(benchmark: BenchmarkFixture) -> None:
    payload = make_json_payload(10 * MiB)
    large_messages: tuple[Message, ...] = (
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())],
        },
        {"type": "http.response.body", "body": payload},
    )
    tiny_messages: tuple[Message, ...] = (
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json"), (b"content-length", b"2")],
        },
        {"type": "http.response.body", "body": b"{}"},
    )
    large_app = GZipMiddleware(StaticResponseApp(large_messages), compresslevel=9)
    tiny_app = GZipMiddleware(StaticResponseApp(tiny_messages), compresslevel=9)
    scope: Scope = {"type": "http", "headers": [(b"accept-encoding", b"gzip")]}
    responsiveness = ResponsivenessBenchmark(large_app, tiny_app, scope, payload)

    benchmark.pedantic(
        responsiveness.run_until_tiny_response,
        setup=responsiveness.setup,
        teardown=responsiveness.teardown,
        rounds=1,
    )

    benchmark.extra_info["large_response_bytes"] = len(payload)
    benchmark.extra_info["compression_level"] = 9
    benchmark.extra_info["tiny_response_bytes"] = len(b"{}")


@pytest.mark.parametrize(
    "case",
    (
        BypassCase("below-minimum-size", 499),
        BypassCase("content-encoding", MiB),
        BypassCase("event-stream", MiB),
        BypassCase("pathsend", MiB),
    ),
    ids=lambda case: case.reason,
)
@pytest.mark.benchmark(max_time=0.5, max_rounds=10)
def test_gzip_bypass(benchmark: BenchmarkFixture, case: BypassCase) -> None:
    # The response payload is constructed outside the measured region. The
    # benchmark covers the complete GZipMiddleware ASGI call, including fresh
    # ASGI message containers, responder construction, and teardown.
    expected = make_bypass_messages(case)
    app = GZipMiddleware(StaticResponseApp(expected), minimum_size=500)
    scope: Scope = {"type": "http", "headers": [(b"accept-encoding", b"gzip")]}
    if case.reason == "pathsend":
        scope["extensions"] = {"http.response.pathsend": {}}
    with closing(ASGIRunner()) as runner:
        sent = benchmark.pedantic(runner.run, args=(app, scope), rounds=1)

    assert sent == list(expected)
    benchmark.extra_info["response_bytes"] = case.body_size
    benchmark.extra_info["bypass_reason"] = case.reason
