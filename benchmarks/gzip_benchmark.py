from __future__ import annotations

import gzip
import hashlib
import io
import json
from dataclasses import dataclass
from typing import Literal

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from starlette.middleware.gzip import GZipResponder
from starlette.types import Receive, Scope, Send

KiB = 1024
MiB = 1024 * KiB

PayloadKind = Literal["json", "text", "incompressible"]


@dataclass(frozen=True)
class BenchmarkCase:
    payload_kind: PayloadKind
    size: int
    level: int

    @property
    def id(self) -> str:
        size = f"{self.size // MiB}MiB" if self.size >= MiB else f"{self.size // KiB}KiB"
        return f"{self.payload_kind}-{size}-level-{self.level}"


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
