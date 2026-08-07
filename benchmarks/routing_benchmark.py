from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route, Router
from starlette.types import ASGIApp, Message, Scope


async def endpoint(request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def build_router(groups: int) -> Router:
    routes: list[Route] = []
    for i in range(groups):
        routes.extend(
            [
                Route(f"/resources{i}", endpoint, methods=["GET", "POST"]),
                Route(f"/resources{i}/{{id:int}}", endpoint, methods=["GET", "PUT", "DELETE"]),
                Route(f"/resources{i}/{{id:int}}/items", endpoint, methods=["GET", "POST"]),
                Route(f"/resources{i}/{{id:int}}/items/{{item}}", endpoint, methods=["GET"]),
            ]
        )
    return Router(routes=routes)


LARGE_ROUTER = build_router(groups=30)  # 120 routes
SMALL_ROUTER = build_router(groups=5)  # 20 routes


def http_scope(method: str, path: str) -> Scope:
    # Built per dispatch: the router mutates the scope while matching, so a
    # fresh one keeps CodSpeed warmup runs from polluting the measured run.
    return {"type": "http", "method": method, "path": path, "root_path": "", "headers": [], "query_string": b""}


async def run_asgi(app: ASGIApp, scope: Scope) -> list[Message]:
    messages: list[Message] = []

    async def receive() -> Message:
        raise AssertionError("The benchmark app must not receive a request body")

    async def send(message: Message) -> None:
        messages.append(message)

    await app(scope, receive, send)
    return messages


class ASGIRunner:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()

    def run(self, app: ASGIApp, method: str, path: str) -> list[Message]:
        return self.loop.run_until_complete(run_asgi(app, http_scope(method, path)))

    def close(self) -> None:
        self.loop.close()


@pytest.fixture(scope="module")
def runner() -> Iterator[ASGIRunner]:
    runner = ASGIRunner()
    yield runner
    runner.close()


def test_routing_static_early(runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(lambda: runner.run(LARGE_ROUTER, "GET", "/resources0"))
    assert messages[0]["status"] == 200


def test_routing_static_late(runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(lambda: runner.run(LARGE_ROUTER, "GET", "/resources29"))
    assert messages[0]["status"] == 200


def test_routing_param_late(runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(lambda: runner.run(LARGE_ROUTER, "GET", "/resources29/123/items/first"))
    assert messages[0]["status"] == 200


def test_routing_miss(runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(lambda: runner.run(LARGE_ROUTER, "GET", "/no/such/path"))
    assert messages[0]["status"] == 404


def test_routing_method_not_allowed(runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(lambda: runner.run(LARGE_ROUTER, "DELETE", "/resources29"))
    assert messages[0]["status"] == 405


def test_routing_small_app(runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(lambda: runner.run(SMALL_ROUTER, "GET", "/resources4/7"))
    assert messages[0]["status"] == 200
