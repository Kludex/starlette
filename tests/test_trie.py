from __future__ import annotations

import random

import pytest

from starlette import convertors
from starlette._trie import RouteTrie
from starlette.convertors import Convertor, register_url_convertor
from starlette.routing import Route, Router, WebSocketRoute


def build(paths: list[str]) -> tuple[RouteTrie, list[Route]]:
    trie = RouteTrie()
    routes = []
    for index, path in enumerate(paths):
        route = Route(path, endpoint=lambda request: None)
        routes.append(route)
        trie.add(index, route.path, route.param_convertors)
    return trie, routes


def assert_superset(paths: list[str], probes: list[str]) -> None:
    """The trie must never drop a route whose real `path_regex` matches."""
    trie, routes = build(paths)
    for probe in probes:
        oracle = {i for i, route in enumerate(routes) if route.path_regex.match(probe)}
        candidates = set(trie.match_all(probe))
        missed = oracle - candidates
        assert not missed, f"{probe!r} dropped {[paths[i] for i in missed]}"


def test_static_and_param() -> None:
    assert_superset(
        ["/users", "/users/{id}", "/users/me"],
        ["/users", "/users/42", "/users/me", "/users/", "/missing"],
    )


def test_typed_convertors() -> None:
    assert_superset(
        ["/int/{x:int}", "/float/{x:float}", "/uuid/{x:uuid}", "/{x}"],
        ["/int/5", "/int/abc", "/float/2.5", "/uuid/ec38df32-ceda-4cfa-9b4a-1aeb94ad551a", "/x"],
    )


def test_path_convertor_consumes_remainder() -> None:
    assert_superset(
        ["/static/{file:path}", "/static/list"],
        ["/static/a/b/c.txt", "/static/", "/static/list", "/static"],
    )


def test_compound_segment() -> None:
    assert_superset(
        ["/v{n:int}", "/{name}:disable", "/files({id:int})"],
        ["/v5", "/bob:disable", "/files(7)", "/v", "/bob"],
    )


def test_uuid_uppercase_and_dashless() -> None:
    # Starlette's uuid regex is case-insensitive with optional dashes; the trie
    # derives the regex from the convertor, so it must match all three forms.
    assert_superset(
        ["/u/{x:uuid}"],
        [
            "/u/EC38DF32-CEDA-4CFA-9B4A-1AEB94AD551A",
            "/u/ec38df32ceda4cfa9b4a1aeb94ad551a",
            "/u/ec38df32-ceda-4cfa-9b4a-1aeb94ad551a",
        ],
    )


def test_custom_convertor() -> None:
    class HexConvertor(Convertor[int]):
        regex = "[0-9a-f]+"

        def convert(self, value: str) -> int:
            return int(value, 16)

        def to_string(self, value: int) -> str:
            return format(value, "x")

    register_url_convertor("hex_trie_test", HexConvertor())
    try:
        assert_superset(["/h/{x:hex_trie_test}", "/h/{y}"], ["/h/deadbeef", "/h/xyz"])
    finally:
        convertors.CONVERTOR_TYPES.pop("hex_trie_test", None)


def test_alternation_convertor_in_compound_segment() -> None:
    # A convertor whose regex uses alternation must keep segment-local precedence;
    # without grouping, `^x(a|b)y$` would compile as `^xa|by$` and drop `/xby`.
    class AltConvertor(Convertor[str]):
        regex = "a|b"

        def convert(self, value: str) -> str:
            return value

        def to_string(self, value: str) -> str:
            return value

    register_url_convertor("alt_trie_test", AltConvertor())
    try:
        assert_superset(["/x{p:alt_trie_test}y"], ["/xay", "/xby", "/xcy"])
    finally:
        convertors.CONVERTOR_TYPES.pop("alt_trie_test", None)


def test_slash_capable_convertor_in_compound_segment() -> None:
    # A `path` convertor embedded in a compound segment can span URL segments,
    # which the per-segment trie can't index; the route must stay always-candidate.
    assert_superset(
        ["/files-{p:path}", "/static/{p:path}"],
        ["/files-a/b", "/files-a", "/files-", "/static/a/b/c", "/static/"],
    )


def test_shared_param_and_dyn_nodes() -> None:
    # Two routes share a `{str}` param node and a compound `dyn` node.
    assert_superset(
        ["/a/{x}/b", "/a/{y}/c", "/v{n:int}/x", "/v{m:int}/y"],
        ["/a/1/b", "/a/1/c", "/v5/x", "/v5/y"],
    )


def test_websocket_route_indexed() -> None:
    trie = RouteTrie()
    route = WebSocketRoute("/ws/{room}", endpoint=lambda ws: None)
    trie.add(0, route.path, route.param_convertors)
    assert trie.match_all("/ws/lobby") == [0]
    assert trie.match_all("/ws") == []


def test_always_candidate_for_unindexable_path() -> None:
    trie = RouteTrie()
    trie.add(0, None, {})  # e.g. a Mount/Host
    trie.add(1, "/x", {})
    assert 0 in trie.match_all("/anything/at/all")
    assert set(trie.match_all("/x")) == {0, 1}


def test_match_all_is_sorted_registration_order() -> None:
    trie, _ = build(["/items/", "/items/", "/{x}/"])
    assert trie.match_all("/items/") == [0, 1, 2]


def _scope(path: str) -> dict[str, object]:
    return {"type": "http", "method": "GET", "path": path, "headers": []}


def _names(router: Router, path: str) -> list[str]:
    return [r.path for r in router._candidate_routes(_scope(path)) if isinstance(r, Route)]


def test_router_cache_rebuilds_when_routes_added() -> None:
    router = Router(routes=[Route("/a", endpoint=lambda r: None)])
    assert _names(router, "/a") == ["/a"]
    assert _names(router, "/b") == []  # builds and caches the trie
    router.routes.append(Route("/b", endpoint=lambda r: None))
    assert _names(router, "/b") == ["/b"]  # adding a route rebuilds the trie


CONVERTORS = ["", ":int", ":float", ":uuid", ":str"]
STATIC = ["api", "v1", "users", "items", "orders", "me", "bulk", "files", "static"]


def _corpus(n: int, seed: int) -> list[str]:
    rng = random.Random(seed)
    patterns: set[str] = set()
    while len(patterns) < n:
        depth = rng.randint(1, 5)
        parts: list[str] = []
        used = 0
        for _ in range(depth):
            kind = rng.choices(["static", "param", "typed", "compound", "path"], weights=[5, 3, 2, 1, 1])[0]
            if kind == "static":
                parts.append(rng.choice(STATIC))
            elif kind == "param":
                parts.append("{p%d}" % used)
                used += 1
            elif kind == "typed":
                parts.append("{p%d%s}" % (used, rng.choice(CONVERTORS)))
                used += 1
            elif kind == "compound":
                parts.append("{p%d}:%s" % (used, rng.choice(STATIC)))
                used += 1
            else:
                parts.append("{p%d:path}" % used)
                break
        patterns.add("/" + "/".join(parts) + ("/" if rng.random() < 0.4 else ""))
    return sorted(patterns)


@pytest.mark.parametrize("seed", range(25))
def test_differential_fuzz_against_starlette(seed: int) -> None:
    """The trie is the default router, so a dropped match is a silent 404 for
    everyone. This proves the superset property holds against Starlette's own
    `path_regex` across a randomized route corpus and probe set.
    """
    patterns = _corpus(_corpus_size(seed), seed)
    trie, routes = build(patterns)
    rng = random.Random(seed + 1000)
    pool = STATIC + [
        "42",
        "abc",
        "25.5",
        "EC38DF32-CEDA-4CFA-9B4A-1AEB94AD551A",
        "ec38df32-ceda-4cfa-9b4a-1aeb94ad551a",
        "a-b",
        "deadbeef",
    ]
    for _ in range(2000):
        path = "/" + "/".join(rng.choice(pool) for _ in range(rng.randint(1, 6)))
        if rng.random() < 0.4:
            path += "/"
        oracle = {i for i, route in enumerate(routes) if route.path_regex.match(path)}
        candidates = set(trie.match_all(path))
        assert not (oracle - candidates), f"seed={seed} path={path!r} dropped {oracle - candidates}"


def _corpus_size(seed: int) -> int:
    return 40 + seed * 8
