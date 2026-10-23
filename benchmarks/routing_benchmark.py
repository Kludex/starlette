from __future__ import annotations

from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner
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


def dispatch(runner: ASGIRunner, app: ASGIApp, method: str, path: str) -> list[Message]:
    return runner.run(app, http_scope(method, path))


def test_routing_static_early(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(dispatch, asgi_runner, LARGE_ROUTER, "GET", "/resources0")
    assert messages[0]["status"] == 200


def test_routing_static_late(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(dispatch, asgi_runner, LARGE_ROUTER, "GET", "/resources29")
    assert messages[0]["status"] == 200


def test_routing_param_late(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(dispatch, asgi_runner, LARGE_ROUTER, "GET", "/resources29/123/items/first")
    assert messages[0]["status"] == 200


def test_routing_miss(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(dispatch, asgi_runner, LARGE_ROUTER, "GET", "/no/such/path")
    assert messages[0]["status"] == 404


def test_routing_method_not_allowed(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(dispatch, asgi_runner, LARGE_ROUTER, "DELETE", "/resources29")
    assert messages[0]["status"] == 405


def test_routing_small_app(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture) -> None:
    messages = benchmark(dispatch, asgi_runner, SMALL_ROUTER, "GET", "/resources4/7")
    assert messages[0]["status"] == 200
