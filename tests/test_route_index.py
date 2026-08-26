from __future__ import annotations

from starlette.routing import RouteIndex, RoutePattern


def test_route_index_snapshots_candidates_and_patterns() -> None:
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
    candidates.reverse()

    assert indexed == ["first", "second", "fallback"]
    assert index.candidates("/first") == ["first", "second", "fallback"]
    assert index.candidates("/missing") == ["first", "second", "fallback"]


def test_route_index_returns_a_new_candidate_list() -> None:
    index = RouteIndex(["first"], lambda candidate: None)

    candidates = index.candidates("/first")
    candidates.clear()

    assert index.candidates("/first") == ["first"]
