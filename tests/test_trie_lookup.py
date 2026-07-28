from __future__ import annotations

import random

import pytest

from starlette import convertors
from starlette._trie import RouteTrie, _pattern_may_match_slash
from starlette.applications import Starlette
from starlette.convertors import Convertor, StringConvertor, register_url_convertor
from starlette.responses import PlainTextResponse
from starlette.routing import BaseRoute, Host, Mount, Route, Router, TrieRouteLookup, WebSocketRoute
from starlette.testclient import TestClient
from tests.test_route_lookup import (
    CONFORMANCE_PATHS,
    CONFORMANCE_ROUTES,
    assert_route_lookup_conformance,
    named,
    ws_endpoint,
)


def build(paths: list[str]) -> tuple[RouteTrie, list[Route]]:
    trie = RouteTrie()
    routes = []
    for index, path in enumerate(paths):
        route = Route(path, endpoint=named(f"r{index}"))
        routes.append(route)
        trie.add(index, route.path, route.param_convertors)
    return trie, routes


def assert_superset(paths: list[str], probes: list[str]) -> None:
    """The trie must never drop a route whose real `path_regex` matches."""
    trie, routes = build(paths)
    for probe in probes:
        oracle = {index for index, route in enumerate(routes) if route.path_regex.match(probe)}
        candidates = set(trie.match_all(probe))
        dropped = oracle - candidates
        assert not dropped, f"{probe!r} dropped {[paths[index] for index in dropped]}"


# --- Slash detection --------------------------------------------------------


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("[^/]+", False),
        ("[0-9]+", False),
        (r"[0-9]+(\.[0-9]+)?", False),
        ("[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}", False),
        ("[a-z0-9-]+", False),
        ("a|b", False),
        (r"\d+", False),
        (r"\w+", False),
        (r"\-", False),
        ("[]a]", False),
        (r"[\]]", False),
        (r"[\d]", False),
        ("[a-c]", False),
        (".*", True),
        ("a.b", True),
        ("/", True),
        (r"\/", True),
        (r"\S+", True),
        (r"\D+", True),
        (r"\W+", True),
        (r"\x2f", True),
        (r"\1", True),
        ("[^a]", True),
        ("[/]", True),
        (r"[\/]", True),
        ("[!-9]", True),
        (r"[\S]", True),
        (r"[a-\x7f]", True),
        ("[abc", True),
        ("[^/", True),
    ],
)
def test_pattern_slash_detection(pattern: str, expected: bool) -> None:
    assert _pattern_may_match_slash(pattern) is expected


# --- Superset property ------------------------------------------------------


def test_static_and_param() -> None:
    assert_superset(
        ["/users", "/users/{id}", "/users/me", "/"],
        ["/users", "/users/42", "/users/me", "/users/", "/missing", "/", ""],
    )


def test_typed_convertors() -> None:
    assert_superset(
        ["/int/{x:int}", "/float/{x:float}", "/uuid/{x:uuid}", "/{x}"],
        [
            "/int/5",
            "/int/abc",
            "/float/2.5",
            "/uuid/ec38df32-ceda-4cfa-9b4a-1aeb94ad551a",
            "/uuid/EC38DF32CEDA4CFA9B4A1AEB94AD551A",
            "/x",
        ],
    )


def test_path_convertor_consumes_remainder() -> None:
    assert_superset(
        ["/static/{file:path}", "/static/list", "/{everything:path}"],
        ["/static/a/b/c.txt", "/static/", "/static/list", "/static", "/", "/anything/at/all"],
    )


def test_compound_segments() -> None:
    assert_superset(
        ["/v{n:int}", "/{name}:disable", "/files({id:int})", "/x{a:int}y{b:int}z"],
        ["/v5", "/bob:disable", "/files(7)", "/x1y2z", "/v", "/bob"],
    )


def test_slash_capable_convertor_in_compound_segment() -> None:
    # A `path` convertor inside a compound segment can span segments, which the
    # trie cannot index, so the route has to stay an always-candidate.
    assert_superset(
        ["/files-{p:path}", "/static/{p:path}"],
        ["/files-a/b", "/files-a", "/files-", "/static/a/b/c", "/static/"],
    )


def test_shared_nodes() -> None:
    assert_superset(
        ["/a/{x}/b", "/a/{y}/c", "/v{n:int}/x", "/v{m:int}/y"],
        ["/a/1/b", "/a/1/c", "/v5/x", "/v5/y"],
    )


def test_custom_convertor_is_indexed_when_slash_free() -> None:
    class HexConvertor(Convertor[int]):
        regex = "[0-9a-f]+"

        def convert(self, value: str) -> int:
            return int(value, 16)  # pragma: no cover

        def to_string(self, value: int) -> str:
            return format(value, "x")  # pragma: no cover

    register_url_convertor("hex_trie_test", HexConvertor())
    try:
        trie, _ = build(["/h/{x:hex_trie_test}", "/h/{y}"])
        assert trie.always == []  # Indexed, not a fallback.
        assert_superset(["/h/{x:hex_trie_test}", "/h/{y}"], ["/h/deadbeef", "/h/xyz"])
    finally:
        convertors.CONVERTOR_TYPES.pop("hex_trie_test", None)


def test_custom_convertor_with_alternation() -> None:
    # Without grouping, `^x(a|b)y$` would compile as `^xa|by$` and drop `/xby`.
    class AltConvertor(StringConvertor):
        regex = "a|b"

    register_url_convertor("alt_trie_test", AltConvertor())
    try:
        assert_superset(["/x{p:alt_trie_test}y"], ["/xay", "/xby", "/xcy"])
    finally:
        convertors.CONVERTOR_TYPES.pop("alt_trie_test", None)


def test_slash_capable_custom_convertor_falls_back() -> None:
    class AnythingConvertor(Convertor[str]):
        regex = ".+"

        def convert(self, value: str) -> str:
            return value  # pragma: no cover

        def to_string(self, value: str) -> str:
            return value  # pragma: no cover

    register_url_convertor("any_trie_test", AnythingConvertor())
    try:
        trie, _ = build(["/a/{x:any_trie_test}"])
        assert trie.always == [0]
        assert_superset(["/a/{x:any_trie_test}"], ["/a/b", "/a/b/c"])
    finally:
        convertors.CONVERTOR_TYPES.pop("any_trie_test", None)


def test_websocket_routes_are_indexed() -> None:
    trie = RouteTrie()
    route = WebSocketRoute("/ws/{room}", ws_endpoint)
    trie.add(0, route.path, route.param_convertors)
    assert trie.match_all("/ws/lobby") == [0]
    assert trie.match_all("/ws") == []


def test_duplicate_paths_keep_registration_order() -> None:
    trie, _ = build(["/items/", "/items/", "/{x}/"])
    assert trie.match_all("/items/") == [0, 1, 2]


def test_mounts_and_hosts_are_always_candidates() -> None:
    routes: list[BaseRoute] = [
        Mount("/mounted", routes=[Route("/inner", named("inner"))]),
        Host("api.example.org", app=Router()),
        Route("/x", named("x")),
    ]
    lookup = TrieRouteLookup(routes)
    scope = {"type": "http", "method": "GET", "path": "/anything", "root_path": "", "headers": []}

    assert lookup.candidates(scope) == [routes[0], routes[1]]


def test_route_subclasses_are_always_candidates() -> None:
    class HeaderRoute(Route):
        pass

    routes: list[BaseRoute] = [HeaderRoute("/x", named("x")), Route("/y", named("y"))]
    lookup = TrieRouteLookup(routes)
    scope = {"type": "http", "method": "GET", "path": "/y", "root_path": "", "headers": []}

    assert lookup.candidates(scope) == routes


# --- Contract ---------------------------------------------------------------


def test_conformance() -> None:
    assert_route_lookup_conformance(TrieRouteLookup)


def test_narrows_the_conformance_route_table() -> None:
    # The suite is only meaningful if the trie actually narrows.
    lookup = TrieRouteLookup(CONFORMANCE_ROUTES)
    scope = {"type": "http", "method": "GET", "path": "/users/42", "root_path": "", "headers": []}

    assert len(lookup.candidates(scope)) < len(CONFORMANCE_ROUTES)


CONVERTOR_SUFFIXES = ["", ":int", ":float", ":uuid", ":str", ":path"]
STATIC_SEGMENTS = ["api", "v1", "users", "items", "orders", "me", "bulk", "files", "static"]
PROBE_SEGMENTS = STATIC_SEGMENTS + [
    "42",
    "abc",
    "25.5",
    "EC38DF32-CEDA-4CFA-9B4A-1AEB94AD551A",
    "ec38df32ceda4cfa9b4a1aeb94ad551a",
    "a-b",
    "deadbeef",
    "v7",
    "bob:disable",
]


def _corpus(size: int, rng: random.Random) -> list[str]:
    paths: set[str] = set()
    while len(paths) < size:
        parts: list[str] = []
        used = 0
        for _ in range(rng.randint(1, 5)):
            kind = rng.choices(["static", "param", "typed", "compound", "path"], weights=[5, 3, 2, 2, 1])[0]
            if kind == "static":
                parts.append(rng.choice(STATIC_SEGMENTS))
            elif kind == "param":
                parts.append("{p%d}" % used)
            elif kind == "typed":
                parts.append("{p%d%s}" % (used, rng.choice(CONVERTOR_SUFFIXES)))
            elif kind == "compound":
                parts.append(rng.choice(["v{p%d:int}", "{p%d}:disable", "files({p%d:int})", "x{p%d:path}"]) % used)
            else:
                parts.append("{p%d:path}" % used)
            used += 1
            if parts[-1].endswith(":path}"):
                break
        paths.add("/" + "/".join(parts) + ("/" if rng.random() < 0.4 else ""))
    return sorted(paths)


@pytest.mark.parametrize("seed", range(25))
def test_differential_fuzz_against_path_regex(seed: int) -> None:
    """A dropped candidate is a silent 404, so prove the superset property against
    Starlette's own `path_regex` over randomised route tables and paths.
    """
    rng = random.Random(seed)
    paths = _corpus(40 + seed * 8, rng)
    trie, routes = build(paths)

    for _ in range(2000):
        probe = "/" + "/".join(rng.choice(PROBE_SEGMENTS) for _ in range(rng.randint(1, 6)))
        if rng.random() < 0.4:
            probe += "/"
        oracle = {index for index, route in enumerate(routes) if route.path_regex.match(probe)}
        dropped = oracle - set(trie.match_all(probe))
        assert not dropped, f"seed={seed} {probe!r} dropped {[paths[index] for index in dropped]}"


@pytest.mark.parametrize("seed", range(5))
def test_differential_fuzz_uses_the_conformance_oracle(seed: int) -> None:
    rng = random.Random(1000 + seed)
    paths = _corpus(60, rng)
    probes = [
        "/"
        + "/".join(rng.choice(PROBE_SEGMENTS) for _ in range(rng.randint(1, 5)))
        + ("/" if rng.random() < 0.4 else "")
        for _ in range(100)
    ]
    routes = [Route(path, named(f"r{index}")) for index, path in enumerate(paths)]

    assert_route_lookup_conformance(TrieRouteLookup, routes=routes, paths=probes + CONFORMANCE_PATHS)


# --- End to end -------------------------------------------------------------


def test_dispatch_end_to_end() -> None:
    app = Starlette(
        routes=[
            Route("/", named("root")),
            Route("/users/me", named("me")),
            Route("/users/{user_id:int}", named("user")),
            Route("/only-post", named("only-post"), methods=["POST"]),
            Route("/trailing/", named("trailing")),
            Route("/static/{path:path}", named("static")),
            WebSocketRoute("/ws/{room}", ws_endpoint),
            Mount("/mounted", routes=[Route("/inner", named("inner"))]),
            Host("api.example.org", app=Router(routes=[Route("/hosted", named("hosted"))])),
        ]
    )
    app.route_lookup_factory = TrieRouteLookup
    client = TestClient(app)

    assert client.get("/").text == "root {}"
    assert client.get("/users/me").text == "me {}"
    assert client.get("/users/42").text == "user {'user_id': 42}"
    assert client.get("/static/a/b.txt").text == "static {'path': 'a/b.txt'}"
    assert client.get("/mounted/inner").text == "inner {}"
    assert client.get("http://api.example.org/hosted").text == "hosted {}"
    assert client.get("/missing").status_code == 404

    response = client.get("/only-post")
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"

    response = client.get("/trailing", follow_redirects=False)
    assert response.status_code == 307

    with client.websocket_connect("/ws/lobby") as websocket:
        assert websocket.receive_text() == "ws"


def test_dispatch_under_root_path() -> None:
    app = Starlette(routes=[Route("/", named("root")), Route("/users/{id}", named("user"))])
    app.route_lookup_factory = TrieRouteLookup
    client = TestClient(app, root_path="/sub")

    assert client.get("/sub/users/7").text == "user {'id': '7'}"
    # `path == root_path`, so the router matches against an empty route path and
    # falls through to the trailing-slash redirect, same as the linear scan.
    assert client.get("/sub", follow_redirects=False).status_code == 307
    assert client.get("/sub").text == "root {}"
    assert client.get("/sub/").text == "root {}"


def test_lookup_survives_route_changes() -> None:
    app = Starlette(routes=[Route("/a", named("a"))])
    app.route_lookup_factory = TrieRouteLookup
    client = TestClient(app)

    assert client.get("/a").text == "a {}"
    app.routes.append(Route("/b", named("b")))
    assert client.get("/b").text == "b {}"


def test_trie_is_rebuilt_per_router() -> None:
    subapp = Starlette(routes=[Route("/inner", lambda request: PlainTextResponse("inner"))])
    app = Starlette(routes=[Mount("/sub", app=subapp)])
    app.route_lookup_factory = TrieRouteLookup

    with TestClient(app) as client:
        assert isinstance(subapp.router.route_lookup, TrieRouteLookup)
        assert client.get("/sub/inner").text == "inner"
