from __future__ import annotations

from starlette.responses import PlainTextResponse
from starlette.routing import Host, Mount, Route, RouteIndex, RoutePattern, WebSocketRoute

endpoint = PlainTextResponse("ok")


def test_route_index_refreshes_candidates_and_patterns() -> None:
    candidates = ["first", "second", "fallback"]
    patterns = {
        "first": RoutePattern("/first", {}),
        "second": RoutePattern("/second/{value}", {}),
    }
    indexed: list[str] = []

    def get_pattern(candidate: str) -> RoutePattern | None:
        indexed.append(candidate)
        return patterns.get(candidate)

    index = RouteIndex(candidates, get_pattern)
    assert indexed == ["first", "second", "fallback"]
    candidates.reverse()

    assert index.candidates("/first") == ["fallback", "second", "first"]
    assert indexed == ["first", "second", "fallback", "fallback", "second", "first"]
    assert index.candidates("/missing") == ["fallback", "second", "first"]


def test_route_index_returns_a_new_candidate_list() -> None:
    index = RouteIndex(["first"], lambda candidate: None)

    candidates = index.candidates("/first")
    candidates.clear()

    assert index.candidates("/first") == ["first"]


def test_route_pattern_from_builtin_routes() -> None:
    route = Route("/{value}", endpoint)
    websocket_route = WebSocketRoute("/ws/{value}", endpoint)
    mount = Mount("/mounted", app=PlainTextResponse("mounted"))

    assert RoutePattern.from_route(route) == RoutePattern(route.path, route.param_convertors)
    assert RoutePattern.from_route(websocket_route) == RoutePattern(
        websocket_route.path, websocket_route.param_convertors
    )
    assert RoutePattern.from_route(mount) == RoutePattern(mount.path + "/{path:path}", mount.param_convertors)
    assert RoutePattern.from_route(Host("example.org", app=PlainTextResponse("hosted"))) is None
