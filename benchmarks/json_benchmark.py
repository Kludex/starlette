from __future__ import annotations

import json
from dataclasses import dataclass

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner, ChunkedReceive
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

KiB = 1024


@dataclass(frozen=True)
class JSONPayload:
    name: str
    content: list[dict[str, object]]
    body: bytes


@dataclass(frozen=True)
class RequestCase:
    payload: JSONPayload
    chunk_size: int | None

    @property
    def id(self) -> str:
        chunk_size = "single" if self.chunk_size is None else f"{self.chunk_size // KiB}KiB"
        return f"{self.payload.name}-{chunk_size}"


def make_payload(name: str, items: int) -> JSONPayload:
    content: list[dict[str, object]] = [
        {"id": index, "name": f"item-{index}", "enabled": index % 2 == 0} for index in range(items)
    ]
    body = json.dumps(content, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
    return JSONPayload(name, content, body)


SMALL_PAYLOAD = make_payload("1KiB", 25)
LARGE_PAYLOAD = make_payload("1MiB", 22_000)
PAYLOADS = (SMALL_PAYLOAD, LARGE_PAYLOAD)
REQUEST_CASES = (
    RequestCase(SMALL_PAYLOAD, None),
    RequestCase(LARGE_PAYLOAD, None),
    RequestCase(LARGE_PAYLOAD, 64 * KiB),
)


class RequestJSONApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        content = await Request(scope, receive).json()
        await send_result(send, str(len(content)).encode())


class JSONResponseApp:
    def __init__(self, content: list[dict[str, object]]) -> None:
        self.content = content

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await JSONResponse(self.content)(scope, receive, send)


async def send_result(send: Send, body: bytes) -> None:
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": body})


REQUEST_APP = RequestJSONApp()
RESPONSE_APPS: dict[str, ASGIApp] = {payload.name: JSONResponseApp(payload.content) for payload in PAYLOADS}


def http_scope(method: str, headers: list[tuple[bytes, bytes]]) -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "root_path": "",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 80),
    }


def make_chunks(body: bytes, chunk_size: int | None) -> tuple[bytes, ...]:
    if chunk_size is None:
        return (body,)
    return tuple(body[offset : offset + chunk_size] for offset in range(0, len(body), chunk_size))


def dispatch_request(runner: ASGIRunner, chunks: tuple[bytes, ...]) -> list[Message]:
    scope = http_scope("POST", [(b"content-type", b"application/json")])
    return runner.run(REQUEST_APP, scope, ChunkedReceive(chunks))


def dispatch_response(runner: ASGIRunner, app: ASGIApp) -> list[Message]:
    return runner.run(app, http_scope("GET", []))


@pytest.fixture(scope="module", autouse=True)
def warm_apps(asgi_runner: ASGIRunner) -> None:
    chunks = (SMALL_PAYLOAD.body,)
    for _ in range(100):
        dispatch_request(asgi_runner, chunks)
        dispatch_response(asgi_runner, RESPONSE_APPS[SMALL_PAYLOAD.name])


@pytest.mark.parametrize("case", REQUEST_CASES, ids=lambda case: case.id)
@pytest.mark.benchmark(max_time=0.5, max_rounds=1)
def test_request_json(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture, case: RequestCase) -> None:
    chunks = make_chunks(case.payload.body, case.chunk_size)
    messages = benchmark.pedantic(dispatch_request, args=(asgi_runner, chunks), rounds=1)

    assert messages == [
        {"type": "http.response.start", "status": 200, "headers": []},
        {"type": "http.response.body", "body": str(len(case.payload.content)).encode()},
    ]
    benchmark.extra_info["body_bytes"] = len(case.payload.body)
    benchmark.extra_info["chunk_bytes"] = case.chunk_size or len(case.payload.body)
    benchmark.extra_info["chunks"] = len(chunks)
    benchmark.extra_info["items"] = len(case.payload.content)


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda payload: payload.name)
@pytest.mark.benchmark(max_time=0.5, max_rounds=1)
def test_json_response(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture, payload: JSONPayload) -> None:
    messages = benchmark.pedantic(
        dispatch_response,
        args=(asgi_runner, RESPONSE_APPS[payload.name]),
        rounds=1,
    )

    assert messages == [
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-length", str(len(payload.body)).encode()),
                (b"content-type", b"application/json"),
            ],
        },
        {"type": "http.response.body", "body": payload.body},
    ]
    benchmark.extra_info["body_bytes"] = len(payload.body)
    benchmark.extra_info["items"] = len(payload.content)
