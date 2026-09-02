from __future__ import annotations

from dataclasses import dataclass

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner
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
        await send({"type": "http.response.start", "status": 200, "headers": EXPECTED_HEADERS})
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


def dispatch(runner: ASGIRunner, app: ASGIApp) -> list[Message]:
    return runner.run(app, http_scope())


@pytest.fixture(scope="module", autouse=True)
def warm_apps(asgi_runner: ASGIRunner) -> None:
    for case in CASES:
        for _ in range(100):
            dispatch(asgi_runner, case.app)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
@pytest.mark.benchmark(max_time=0.5, max_rounds=20)
def test_minimal_response_dispatch(
    asgi_runner: ASGIRunner,
    benchmark: BenchmarkFixture,
    case: BenchmarkCase,
) -> None:
    messages = benchmark(dispatch, asgi_runner, case.app)

    assert messages == [
        {"type": "http.response.start", "status": 200, "headers": EXPECTED_HEADERS},
        {"type": "http.response.body", "body": PAYLOAD},
    ]
    benchmark.extra_info["stack"] = case.name
