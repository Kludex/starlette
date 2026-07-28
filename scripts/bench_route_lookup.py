"""Benchmark route lookups against the default linear scan.

    uv run python scripts/bench_route_lookup.py

Reports three things for a few route table sizes:

* end to end `Router` dispatch, hits and misses
* candidate selection on its own, which is the part a lookup replaces
* one time build cost of the lookup
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Sequence

from starlette.responses import PlainTextResponse
from starlette.routing import BaseRoute, Match, Route, Router, RouteLookupFactory, TrieRouteLookup

LOOKUPS: list[tuple[str, RouteLookupFactory | None]] = [
    ("linear", None),
    ("trie", TrieRouteLookup),
]


async def endpoint(request: object) -> PlainTextResponse:
    return PlainTextResponse("ok")


def make_routes(count: int) -> list[BaseRoute]:
    """A REST shaped route table: static collections, typed and string params."""
    routes: list[BaseRoute] = []
    index = 0
    while len(routes) < count:
        name = f"resource{index}"
        routes.extend(
            [
                Route(f"/api/v1/{name}", endpoint),
                Route(f"/api/v1/{name}/{{{name}_id:int}}", endpoint),
                Route(f"/api/v1/{name}/{{{name}_id:int}}/items", endpoint),
                Route(f"/api/v1/{name}/{{{name}_id:int}}/items/{{item_id}}", endpoint),
                Route(f"/api/v1/{name}/{{{name}_id:int}}/items/{{item_id}}/history", endpoint),
            ]
        )
        index += 1
    return routes[:count]


def make_probes(routes: Sequence[BaseRoute]) -> tuple[list[str], list[str]]:
    hits: list[str] = []
    for route in routes:
        path = route.path  # type: ignore[attr-defined]
        path = path.replace("_id:int}", "_id}")
        parts = []
        for segment in path.lstrip("/").split("/"):
            parts.append("7" if segment.endswith("_id}") else segment)
        hits.append("/" + "/".join(parts))

    misses = [path.replace("/api/", "/apiv/", 1) for path in hits]
    for path in misses:
        scope = {"type": "http", "method": "GET", "path": path, "root_path": "", "headers": []}
        assert all(route.matches(scope)[0] == Match.NONE for route in routes), path
    return hits, misses


def scope_for(path: str) -> dict[str, object]:
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "root_path": "",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "http_version": "1.1",
        "client": ("test", 1),
        "server": ("test", 80),
    }


def best_of(runs: int, work: Callable[[], None], iterations: int) -> float:
    best = None
    for _ in range(runs):
        start = time.perf_counter()
        work()
        elapsed = (time.perf_counter() - start) / iterations
        best = elapsed if best is None else min(best, elapsed)
    assert best is not None
    return best


async def bench_dispatch(router: Router, paths: Sequence[str]) -> float:
    scopes = [scope_for(path) for path in paths]

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        return None

    async def work() -> None:
        for scope in scopes:
            await router(dict(scope), receive, send)

    await work()  # warm up and build the lookup

    best = None
    for _ in range(5):
        start = time.perf_counter()
        await work()
        elapsed = (time.perf_counter() - start) / len(scopes)
        best = elapsed if best is None else min(best, elapsed)
    assert best is not None
    return best * 1e6


def bench_resolve(routes: Sequence[BaseRoute], factory: RouteLookupFactory | None, paths: Sequence[str]) -> float:
    """Time the routing decision itself: find the route, without dispatching it."""
    scopes = [scope_for(path) for path in paths]
    candidates: Callable[[dict[str, object]], Sequence[BaseRoute]]
    if factory is None:
        snapshot = tuple(routes)
        candidates = lambda scope: snapshot  # noqa: E731
    else:
        lookup = factory(tuple(routes))
        candidates = lambda scope: list(lookup.candidates(scope))  # noqa: E731

    def work() -> None:
        for scope in scopes:
            partial = None
            for route in candidates(scope):
                match, _ = route.matches(scope)
                if match == Match.FULL:
                    break
                if match == Match.PARTIAL and partial is None:
                    partial = route

    work()
    return best_of(5, work, len(scopes)) * 1e9


def bench_build(routes: Sequence[BaseRoute], factory: RouteLookupFactory | None) -> float:
    if factory is None:
        return 0.0
    snapshot = tuple(routes)

    def work() -> None:
        factory(snapshot)

    work()
    return best_of(5, work, 1) * 1e3


async def main() -> None:
    sizes = [5, 20, 50, 200, 740, 2000]

    rows: list[tuple[str, ...]] = []
    for size in sizes:
        routes = make_routes(size)
        hits, misses = make_probes(routes)
        results: dict[str, tuple[float, float, float, float, float]] = {}
        for name, factory in LOOKUPS:
            router = Router(routes=list(routes))
            router.route_lookup_factory = factory
            hit_us = await bench_dispatch(router, hits)
            miss_us = await bench_dispatch(router, misses)
            hit_ns = bench_resolve(routes, factory, hits)
            miss_ns = bench_resolve(routes, factory, misses)
            build_ms = bench_build(routes, factory)
            results[name] = (hit_us, miss_us, hit_ns, miss_ns, build_ms)

        linear = results["linear"]
        trie = results["trie"]
        rows.append(
            (
                str(size),
                f"{linear[0]:.1f} / {trie[0]:.1f}",
                f"{linear[0] / trie[0]:.1f}x",
                f"{linear[1]:.1f} / {trie[1]:.1f}",
                f"{linear[1] / trie[1]:.1f}x",
                f"{linear[2]:.0f} / {trie[2]:.0f}",
                f"{linear[2] / trie[2]:.1f}x",
                f"{linear[3]:.0f} / {trie[3]:.0f}",
                f"{linear[3] / trie[3]:.1f}x",
                f"{trie[4]:.2f}",
            )
        )

    header = (
        "routes",
        "dispatch hit us",
        "x",
        "dispatch miss us",
        "x",
        "resolve hit ns",
        "x",
        "resolve miss ns",
        "x",
        "build ms",
    )
    print("| " + " | ".join(header) + " |")
    print("|" + "|".join("---" for _ in header) + "|")
    for row in rows:
        print("| " + " | ".join(row) + " |")


if __name__ == "__main__":
    asyncio.run(main())
