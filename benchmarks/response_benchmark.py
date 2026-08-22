from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

PAYLOAD = b"ok"
EXPECTED_HEADERS = [(b"content-length", b"2")]


async def endpoint(request: Request) -> Response:
    return Response(PAYLOAD)


class RawResponseApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": list(EXPECTED_HEADERS)})
        await send({"type": "http.response.body", "body": PAYLOAD})


class ConstructedResponseApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await Response(PAYLOAD)(scope, receive, send)


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    app: ASGIApp


CASES = (
    BenchmarkCase("raw-asgi", RawResponseApp()),
    BenchmarkCase("prebuilt-response", Response(PAYLOAD)),
    BenchmarkCase("constructed-response", ConstructedResponseApp()),
    BenchmarkCase("route", Route("/", endpoint)),
    BenchmarkCase("starlette", Starlette(routes=[Route("/", endpoint)])),
)


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


async def run_asgi(app: ASGIApp) -> list[Message]:
    messages: list[Message] = []

    async def receive() -> Message:
        raise AssertionError("The benchmark app must not receive a request body")

    async def send(message: Message) -> None:
        messages.append(message)

    await app(http_scope(), receive, send)
    return messages


class ASGIRunner:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()

    def run(self, app: ASGIApp) -> list[Message]:
        return self.loop.run_until_complete(run_asgi(app))

    def close(self) -> None:
        self.loop.close()


@pytest.fixture(scope="module")
def runner() -> Iterator[ASGIRunner]:
    runner = ASGIRunner()
    for case in CASES:
        for _ in range(100):
            runner.run(case.app)
    yield runner
    runner.close()


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
@pytest.mark.benchmark(max_time=0.5, max_rounds=20)
def test_minimal_response_dispatch(
    runner: ASGIRunner,
    benchmark: BenchmarkFixture,
    case: BenchmarkCase,
) -> None:
    messages = benchmark(runner.run, case.app)

    assert messages == [
        {"type": "http.response.start", "status": 200, "headers": EXPECTED_HEADERS},
        {"type": "http.response.body", "body": PAYLOAD},
    ]
    benchmark.extra_info["stack"] = case.name
