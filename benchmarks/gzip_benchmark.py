from __future__ import annotations

import gzip
import hashlib
import io
import json
from collections.abc import Coroutine
from dataclasses import dataclass
from typing import Literal, cast

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from starlette.middleware.gzip import GZipMiddleware, GZipResponder
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
            outgoing: Message = dict(message)
            if "headers" in outgoing:
                outgoing["headers"] = list(outgoing["headers"])
            await send(outgoing)


class ASGIRunner:
    """Drive an ASGI app that does not suspend on external I/O."""

    def __init__(self) -> None:
        self.messages: list[Message] = []

    async def receive(self) -> Message:
        raise AssertionError("The benchmark app must not receive a request body")

    async def send(self, message: Message) -> None:
        self.messages.append(message)

    def run(self, app: ASGIApp, scope: Scope) -> list[Message]:
        self.messages.clear()
        awaitable = app(scope, self.receive, self.send)
        coroutine = cast(Coroutine[object, object, None], awaitable)
        try:
            yielded = coroutine.send(None)
        except StopIteration:
            return self.messages
        coroutine.close()
        raise AssertionError(f"The benchmark app unexpectedly suspended with {yielded!r}")


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


async def unused_app(scope: Scope, receive: Receive, send: Send) -> None:
    raise AssertionError("The benchmark calls GZipResponder directly")


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


def compress(payload: bytes, level: int) -> bytes:
    responder = GZipResponder(unused_app, minimum_size=0, compresslevel=level)
    with responder.gzip_buffer, responder.gzip_file:
        return responder.apply_compression(payload, more_body=False)


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
    compressed = benchmark(compress, payload, case.level)

    assert gzip.decompress(compressed) == payload
    benchmark.extra_info["input_bytes"] = len(payload)
    benchmark.extra_info["output_bytes"] = len(compressed)
    benchmark.extra_info["compression_ratio"] = len(compressed) / len(payload)


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
    # The response and payload are constructed outside the measured region.
    # The benchmark covers the complete GZipMiddleware ASGI call, including
    # responder and compressor initialization for responses that pass through.
    expected = make_bypass_messages(case)
    app = GZipMiddleware(StaticResponseApp(expected), minimum_size=500)
    runner = ASGIRunner()

    sent = benchmark(runner.run, app, {"type": "http", "headers": [(b"accept-encoding", b"gzip")]})

    assert sent == list(expected)
    benchmark.extra_info["response_bytes"] = case.body_size
    benchmark.extra_info["bypass_reason"] = case.reason
