from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import (
    BaseRoute,
    Host,
    Mount,
    Route,
    RouteLookup,
    RouteLookupError,
    RouteLookupFactory,
    Router,
    StrictRouteLookup,
    WebSocketRoute,
    compile_path,
    get_route_path,
    iter_child_routers,
)
from starlette.staticfiles import StaticFiles
from starlette.testclient import TestClient
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocket


def named(name: str) -> Any:
    def handler(request: Request) -> PlainTextResponse:
        return PlainTextResponse(f"{name} {request.path_params}")

    handler.__name__ = name
    return handler


async def ws_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()
    await websocket.send_text("ws")
    await websocket.close()


# --- Reference lookups ------------------------------------------------------


class AlwaysCandidateLookup:
    """The most conservative conformant lookup: never narrows anything."""

    def __init__(self, routes: Iterable[BaseRoute]) -> None:
        self.routes = tuple(routes)

    def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]:
        return self.routes


class FirstSegmentLookup:
    """Buckets routes by their first literal path segment.

    Deliberately simple, but it really narrows, so it exercises the seam the way a
    trie would. Anything it does not understand exactly stays always-candidate.
    """

    def __init__(self, routes: Iterable[BaseRoute]) -> None:
        routes = tuple(routes)
        self.positions = {id(route): index for index, route in enumerate(routes)}
        self.always: list[BaseRoute] = []
        self.buckets: dict[str, list[BaseRoute]] = {}
        for route in routes:
            segment = self._literal_first_segment(route)
            if segment is None:
                self.always.append(route)
            else:
                self.buckets.setdefault(segment, []).append(route)

    @staticmethod
    def _literal_first_segment(route: BaseRoute) -> str | None:
        # Exact type check: a subclass may override `matches()` and match paths its
        # own `path` does not describe.
        if type(route) is not Route and type(route) is not WebSocketRoute:
            return None
        first = route.path.lstrip("/").split("/")[0]
        if not first or "{" in first:
            return None
        return first

    def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]:
        first = get_route_path(scope).lstrip("/").split("/")[0]
        bucket = self.buckets.get(first)
        if bucket is None:
            return list(self.always)
        return sorted(self.always + bucket, key=lambda route: self.positions[id(route)])


LOOKUPS: list[RouteLookupFactory | None] = [
    None,
    AlwaysCandidateLookup,
    FirstSegmentLookup,
    StrictRouteLookup(AlwaysCandidateLookup),
    StrictRouteLookup(FirstSegmentLookup),
]


@pytest.fixture(params=LOOKUPS, ids=["default", "always", "first-segment", "strict-always", "strict-first-segment"])
def lookup_factory(request: pytest.FixtureRequest) -> RouteLookupFactory | None:
    factory: RouteLookupFactory | None = request.param
    return factory


# --- Conformance suite ------------------------------------------------------

CONFORMANCE_ROUTES: list[BaseRoute] = [
    Route("/", named("root")),
    Route("/users", named("users"), methods=["GET", "POST"]),
    Route("/users/me", named("me")),
    Route("/users/{user_id:int}", named("user")),
    Route("/users/{user_id}/posts/{post_id}", named("post")),
    Route("/v{version:int}/ping", named("versioned")),
    Route("/{username}:disable", named("disable")),
    Route("/files({file_id:int})", named("parens")),
    Route("/uploads/{path:path}", named("uploads")),
    Route("/files-{path:path}", named("compound-path")),
    Route("/only-post", named("only-post"), methods=["POST"]),
    Route("/trailing/", named("trailing")),
    WebSocketRoute("/ws/{room}", ws_endpoint),
    Mount("/mounted", routes=[Route("/inner", named("inner"))]),
    Mount("/static", app=StaticFiles(directory="tests"), name="static"),
    Host("api.example.org", app=Router(routes=[Route("/hosted", named("hosted"))])),
]

CONFORMANCE_PATHS = [
    "/",
    "",
    "/users",
    "/users/",
    "/users/me",
    "/users/42",
    "/users/abc",
    "/users/42/posts/7",
    "/v1/ping",
    "/v/ping",
    "/bob:disable",
    "/files(7)",
    "/uploads/a/b/c.txt",
    "/uploads/",
    "/files-a/b",
    "/files-a",
    "/only-post",
    "/trailing",
    "/trailing/",
    "/ws/lobby",
    "/mounted/inner",
    "/mounted",
    "/static/test_route_lookup.py",
    "/hosted",
    "/missing",
    "/missing/deeper",
]


def assert_route_lookup_conformance(
    factory: RouteLookupFactory,
    routes: Iterable[BaseRoute] | None = None,
    paths: Iterable[str] | None = None,
) -> None:
    """Check a `RouteLookupFactory` against `StrictRouteLookup`.

    Third-party lookups can reuse this: build the lookup under `StrictRouteLookup`
    and probe it, and any dropped, duplicated, reordered or foreign candidate
    raises `RouteLookupError`.
    """
    table = tuple(CONFORMANCE_ROUTES if routes is None else routes)
    lookup = StrictRouteLookup(factory)(table)
    for path in CONFORMANCE_PATHS if paths is None else paths:
        for method in ("GET", "POST", "DELETE"):
            lookup.candidates(
                {
                    "type": "http",
                    "method": method,
                    "path": path,
                    "root_path": "",
                    "headers": [(b"host", b"api.example.org")],
                }
            )
        lookup.candidates(
            {
                "type": "websocket",
                "path": path,
                "root_path": "",
                "headers": [(b"host", b"api.example.org")],
            }
        )


@pytest.mark.parametrize("factory", [AlwaysCandidateLookup, FirstSegmentLookup])
def test_reference_lookups_are_conformant(factory: RouteLookupFactory) -> None:
    assert_route_lookup_conformance(factory)


def test_conformance_suite_catches_a_broken_lookup() -> None:
    class DropsEverything:
        def __init__(self, routes: Iterable[BaseRoute]) -> None: ...

        def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]:
            return []

    with pytest.raises(RouteLookupError, match="dropped"):
        assert_route_lookup_conformance(DropsEverything)


# --- End to end dispatch ----------------------------------------------------


def build_app(lookup_factory: RouteLookupFactory | None) -> Starlette:
    app = Starlette(
        routes=[
            Route("/", named("root")),
            Route("/users", named("users")),
            Route("/users/me", named("me")),
            Route("/users/{user_id:int}", named("user")),
            Route("/only-post", named("only-post"), methods=["POST"]),
            Route("/trailing/", named("trailing")),
            WebSocketRoute("/ws/{room}", ws_endpoint),
            Mount("/mounted", routes=[Route("/inner", named("inner"))]),
            Host("api.example.org", app=Router(routes=[Route("/hosted", named("hosted"))])),
        ]
    )
    app.route_lookup_factory = lookup_factory
    return app


def test_dispatch_matches_default_behaviour(lookup_factory: RouteLookupFactory | None) -> None:
    client = TestClient(build_app(lookup_factory))

    assert client.get("/").text == "root {}"
    assert client.get("/users").text == "users {}"
    # First registered wins: `/users/me` shadows `/users/{user_id:int}`.
    assert client.get("/users/me").text == "me {}"
    assert client.get("/users/42").text == "user {'user_id': 42}"
    assert client.get("/mounted/inner").text == "inner {}"
    assert client.get("/missing").status_code == 404

    # Method mismatch must stay a 405, so lookups may not filter on method.
    response = client.get("/only-post")
    assert response.status_code == 405
    assert response.headers["allow"] == "POST"

    # Trailing slash redirects go through the lookup too.
    response = client.get("/trailing", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"].endswith("/trailing/")

    with client.websocket_connect("/ws/lobby") as websocket:
        assert websocket.receive_text() == "ws"

    assert client.get("http://api.example.org/hosted").text == "hosted {}"


def test_dispatch_under_root_path(lookup_factory: RouteLookupFactory | None) -> None:
    app = build_app(lookup_factory)
    client = TestClient(app, root_path="/sub")

    assert client.get("/sub/users/me").text == "me {}"
    assert client.get("/sub/mounted/inner").text == "inner {}"


def test_nested_mounts_dispatch(lookup_factory: RouteLookupFactory | None) -> None:
    inner = Starlette(routes=[Route("/deep", named("deep"))])
    middle = Starlette(routes=[Mount("/inner", app=inner)])
    app = Starlette(routes=[Mount("/middle", app=middle)])
    app.route_lookup_factory = lookup_factory

    client = TestClient(app)
    assert client.get("/middle/inner/deep").text == "deep {}"


# --- Propagation ------------------------------------------------------------


def factories(*routers: Router) -> list[RouteLookupFactory | None]:
    return [router.route_lookup_factory for router in routers]


def test_propagates_into_mounted_routes() -> None:
    mount = Mount("/api", routes=[Route("/x", named("x"))])
    app = Starlette(routes=[mount])
    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    child = mount._base_app
    assert isinstance(child, Router)
    assert factories(app.router, child) == [FirstSegmentLookup, FirstSegmentLookup]
    assert isinstance(app.router.route_lookup, FirstSegmentLookup)
    assert isinstance(child.route_lookup, FirstSegmentLookup)


def test_propagates_into_mounted_apps_and_routers() -> None:
    router = Router(routes=[Route("/a", named("a"))])
    subapp = Starlette(routes=[Route("/b", named("b"))])
    app = Starlette(routes=[Mount("/router", app=router), Mount("/app", app=subapp)])

    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    assert factories(router, subapp.router) == [FirstSegmentLookup, FirstSegmentLookup]


def test_propagates_through_mount_middleware() -> None:
    # `Mount.app` is the middleware stack; the router lives on `_base_app`.
    subapp = Starlette(routes=[Route("/b", named("b"))])
    mount = Mount("/app", app=subapp, middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=["*"])])
    app = Starlette(routes=[mount])

    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    assert subapp.router.route_lookup_factory is FirstSegmentLookup


def test_propagates_through_host() -> None:
    router = Router(routes=[Route("/hosted", named("hosted"))])
    app = Starlette(routes=[Host("api.example.org", app=router)])

    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    assert router.route_lookup_factory is FirstSegmentLookup


def test_propagates_through_nested_mounts() -> None:
    inner = Starlette(routes=[Route("/deep", named("deep"))])
    middle = Starlette(routes=[Mount("/inner", app=inner)])
    app = Starlette(routes=[Mount("/middle", app=middle)])

    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    assert factories(middle.router, inner.router) == [FirstSegmentLookup, FirstSegmentLookup]


def test_propagation_ignores_opaque_asgi_apps() -> None:
    async def raw_asgi(scope: Scope, receive: Receive, send: Send) -> None: ...  # pragma: no cover

    app = Starlette(
        routes=[
            Mount("/static", app=StaticFiles(directory="tests")),
            Mount("/raw", app=raw_asgi),
        ]
    )
    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()  # must not raise

    assert list(iter_child_routers(app.routes[0])) == []
    assert list(iter_child_routers(app.routes[1])) == []


def test_propagation_reaches_routers_mounted_later() -> None:
    app = Starlette(routes=[Route("/a", named("a"))])
    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    subapp = Starlette(routes=[Route("/b", named("b"))])
    app.routes.append(Mount("/later", app=subapp))
    app.router.build_route_lookup()

    assert subapp.router.route_lookup_factory is FirstSegmentLookup
    assert TestClient(app).get("/later/b").text == "b {}"


def test_explicit_child_configuration_is_not_overwritten() -> None:
    subapp = Starlette(routes=[Route("/b", named("b"))])
    subapp.route_lookup_factory = AlwaysCandidateLookup
    app = Starlette(routes=[Mount("/app", app=subapp)])

    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    assert subapp.route_lookup_factory is AlwaysCandidateLookup


def test_reassignment_updates_inherited_children() -> None:
    subapp = Starlette(routes=[Route("/b", named("b"))])
    app = Starlette(routes=[Mount("/app", app=subapp)])

    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()
    assert factories(subapp.router) == [FirstSegmentLookup]

    app.route_lookup_factory = AlwaysCandidateLookup
    app.router.build_route_lookup()
    assert factories(subapp.router) == [AlwaysCandidateLookup]

    app.route_lookup_factory = None
    app.router.build_route_lookup()
    assert subapp.route_lookup_factory is None
    assert subapp.router.route_lookup is None


def test_same_app_mounted_twice() -> None:
    shared = Starlette(routes=[Route("/b", named("b"))])
    app = Starlette(routes=[Mount("/one", app=shared), Mount("/two", app=shared)])

    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    assert shared.route_lookup_factory is FirstSegmentLookup
    client = TestClient(app)
    assert client.get("/one/b").text == "b {}"
    assert client.get("/two/b").text == "b {}"


def test_cyclic_routing_tree_does_not_recurse_forever() -> None:
    router = Router()
    router.routes.append(Mount("/self", app=router))
    router.route_lookup_factory = FirstSegmentLookup

    router.build_route_lookup()  # must terminate

    assert router.route_lookup_factory is FirstSegmentLookup


def test_custom_route_can_expose_child_routers() -> None:
    child = Router(routes=[Route("/x", named("x"))])

    class CustomMount(Mount):
        def iter_child_routers(self) -> Iterator[Router]:
            yield child

    app = Starlette(routes=[CustomMount("/custom", app=child)])
    app.route_lookup_factory = FirstSegmentLookup
    app.router.build_route_lookup()

    assert child.route_lookup_factory is FirstSegmentLookup


# --- Invalidation -----------------------------------------------------------


def test_added_routes_are_picked_up() -> None:
    app = Starlette(routes=[Route("/a", named("a"))])
    app.route_lookup_factory = FirstSegmentLookup
    client = TestClient(app)

    assert client.get("/a").text == "a {}"
    assert client.get("/b").status_code == 404

    app.routes.append(Route("/b", named("b")))
    assert client.get("/b").text == "b {}"


def test_replaced_route_is_picked_up() -> None:
    app = Starlette(routes=[Route("/a", named("a")), Route("/b", named("b"))])
    app.route_lookup_factory = FirstSegmentLookup
    client = TestClient(app)
    assert client.get("/b").text == "b {}"

    # Same length, so a length-based staleness check would miss this.
    app.routes[1] = Route("/c", named("c"))
    assert client.get("/b").status_code == 404
    assert client.get("/c").text == "c {}"


def test_reordered_routes_are_picked_up() -> None:
    app = Starlette(routes=[Route("/users/{user_id}", named("param")), Route("/users/me", named("me"))])
    app.route_lookup_factory = FirstSegmentLookup
    client = TestClient(app)
    assert client.get("/users/me").text == "param {'user_id': 'me'}"

    app.routes.reverse()
    assert client.get("/users/me").text == "me {}"


def test_route_list_reassignment_is_picked_up() -> None:
    app = Starlette(routes=[Route("/a", named("a"))])
    app.route_lookup_factory = FirstSegmentLookup
    client = TestClient(app)
    assert client.get("/a").text == "a {}"

    app.router.routes = [Route("/b", named("b"))]
    assert client.get("/a").status_code == 404
    assert client.get("/b").text == "b {}"


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda routes: routes.append(Route("/z", named("z"))), id="append"),
        pytest.param(lambda routes: routes.extend([Route("/z", named("z"))]), id="extend"),
        pytest.param(lambda routes: routes.insert(0, Route("/z", named("z"))), id="insert"),
        pytest.param(lambda routes: routes.pop(), id="pop"),
        pytest.param(lambda routes: routes.remove(routes[0]), id="remove"),
        pytest.param(lambda routes: routes.clear(), id="clear"),
        pytest.param(lambda routes: routes.reverse(), id="reverse"),
        pytest.param(lambda routes: routes.sort(key=lambda route: route.path), id="sort"),
        pytest.param(lambda routes: routes.__setitem__(0, Route("/z", named("z"))), id="setitem"),
        pytest.param(lambda routes: routes.__delitem__(0), id="delitem"),
        pytest.param(lambda routes: routes.__iadd__([Route("/z", named("z"))]), id="iadd"),
        pytest.param(lambda routes: routes.__imul__(2), id="imul"),
        pytest.param(lambda routes: routes.__setitem__(slice(0, 1), [Route("/z", named("z"))]), id="setslice"),
    ],
)
def test_every_mutation_invalidates_the_lookup(mutate: Any) -> None:
    router = Router(routes=[Route("/a", named("a")), Route("/b", named("b"))])
    router.route_lookup_factory = AlwaysCandidateLookup
    router.build_route_lookup()

    mutate(router.routes)

    # `_route_candidates` must notice the route list changed under it. The
    # always-candidate lookup replays the snapshot it was compiled from, so a
    # stale table shows up as a mismatch with the live routes.
    assert list(router._route_candidates(http_scope("/a"))) == list(router.routes)


def test_in_place_route_mutation_needs_explicit_invalidation() -> None:
    route = Route("/a", named("a"))
    app = Starlette(routes=[route])
    app.route_lookup_factory = FirstSegmentLookup
    client = TestClient(app)
    assert client.get("/a").text == "a {}"

    route.path = "/b"
    route.path_regex, route.path_format, route.param_convertors = compile_path("/b")
    # The lookup still has it bucketed under "a", and nothing signalled a change.
    assert client.get("/b").status_code == 404

    app.router.invalidate_route_lookup()
    assert client.get("/b").text == "a {}"


# --- StrictRouteLookup ------------------------------------------------------


def strict_lookup(lookup: RouteLookup, routes: list[BaseRoute]) -> RouteLookup:
    return StrictRouteLookup(lambda _: lookup)(tuple(routes))


def http_scope(path: str = "/a") -> Scope:
    return {"type": "http", "method": "GET", "path": path, "root_path": "", "headers": []}


def test_strict_lookup_accepts_a_conformant_lookup() -> None:
    routes: list[BaseRoute] = [Route("/a", named("a")), Route("/b", named("b"))]
    lookup = StrictRouteLookup(FirstSegmentLookup)(tuple(routes))

    assert list(lookup.candidates(http_scope("/a"))) == [routes[0]]


def test_strict_lookup_rejects_dropped_routes() -> None:
    routes: list[BaseRoute] = [Route("/a", named("a"))]

    class Drops:
        def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]:
            return []

    with pytest.raises(RouteLookupError, match="dropped"):
        strict_lookup(Drops(), routes).candidates(http_scope("/a"))


def test_strict_lookup_rejects_method_filtering() -> None:
    # Filtering on method turns a 405 into a 404, so PARTIAL matches count too.
    routes: list[BaseRoute] = [Route("/a", named("a"), methods=["POST"])]

    class FiltersMethods:
        def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]:
            return []

    with pytest.raises(RouteLookupError, match="Match.PARTIAL"):
        strict_lookup(FiltersMethods(), routes).candidates(http_scope("/a"))


def test_strict_lookup_rejects_out_of_order_candidates() -> None:
    routes: list[BaseRoute] = [Route("/a", named("a")), Route("/a", named("a2"))]

    class Reorders:
        def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]:
            return list(reversed(routes))

    with pytest.raises(RouteLookupError, match="out of registration order"):
        strict_lookup(Reorders(), routes).candidates(http_scope("/a"))


def test_strict_lookup_rejects_duplicates() -> None:
    routes: list[BaseRoute] = [Route("/a", named("a"))]

    class Duplicates:
        def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]:
            return [routes[0], routes[0]]

    with pytest.raises(RouteLookupError, match="more than once"):
        strict_lookup(Duplicates(), routes).candidates(http_scope("/a"))


def test_strict_lookup_rejects_foreign_routes() -> None:
    routes: list[BaseRoute] = [Route("/a", named("a"))]
    foreign = Route("/foreign", named("foreign"))

    class Foreign:
        def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]:
            return [foreign]

    with pytest.raises(RouteLookupError, match="not in the route table"):
        strict_lookup(Foreign(), routes).candidates(http_scope("/a"))


def test_strict_lookup_repr() -> None:
    assert "AlwaysCandidateLookup" in repr(StrictRouteLookup(AlwaysCandidateLookup))
    lookup = StrictRouteLookup(AlwaysCandidateLookup)(())
    assert "AlwaysCandidateLookup" in repr(lookup)


# --- Lifecycle --------------------------------------------------------------


def test_lookup_is_built_on_startup() -> None:
    app = Starlette(routes=[Route("/a", named("a"))])
    app.route_lookup_factory = FirstSegmentLookup

    assert app.router.route_lookup is None
    with TestClient(app):
        assert isinstance(app.router.route_lookup, FirstSegmentLookup)


def test_broken_lookup_fails_at_startup() -> None:
    def broken(routes: Iterable[BaseRoute]) -> RouteLookup:
        raise ValueError("unsupported route table")

    app = Starlette(routes=[Route("/a", named("a"))])
    app.route_lookup_factory = broken

    with pytest.raises(ValueError, match="unsupported route table"):
        with TestClient(app):
            pass  # pragma: no cover


def test_startup_builds_nested_routers() -> None:
    subapp = Starlette(routes=[Route("/b", named("b"))])
    app = Starlette(routes=[Mount("/app", app=subapp)])
    app.route_lookup_factory = FirstSegmentLookup

    with TestClient(app):
        assert isinstance(subapp.router.route_lookup, FirstSegmentLookup)


def test_defaults_are_unchanged() -> None:
    app = Starlette(routes=[Route("/a", named("a"))])

    assert app.route_lookup_factory is None
    assert app.router.route_lookup is None
    assert TestClient(app).get("/a").text == "a {}"
    assert app.router.route_lookup is None


def test_router_lookup_can_be_configured_directly() -> None:
    router = Router(routes=[Route("/a", named("a"))])
    router.route_lookup_factory = FirstSegmentLookup

    assert TestClient(router).get("/a").text == "a {}"
    assert isinstance(router.route_lookup, FirstSegmentLookup)
