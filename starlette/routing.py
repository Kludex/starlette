from __future__ import annotations

import contextlib
import functools
import inspect
import re
import traceback
import types
import warnings
from collections.abc import Awaitable, Callable, Collection, Generator, Iterable, Iterator, Sequence
from contextlib import AbstractAsyncContextManager, AbstractContextManager, asynccontextmanager
from enum import Enum
from re import Pattern
from typing import Any, Protocol, SupportsIndex, TypeVar

from starlette._exception_handler import wrap_app_handling_exceptions
from starlette._trie import RouteTrie

# `get_route_path` is part of the public API: route lookup implementations need it to
# resolve the path a router matches against, with `root_path` stripped.
from starlette._utils import get_route_path as get_route_path, is_async_callable
from starlette.concurrency import run_in_threadpool
from starlette.convertors import CONVERTOR_TYPES, Convertor
from starlette.datastructures import URL, Headers, URLPath
from starlette.exceptions import HTTPException, StarletteDeprecationWarning
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Lifespan, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketClose


class NoMatchFound(Exception):
    """
    Raised by `.url_for(name, **path_params)` and `.url_path_for(name, **path_params)`
    if no matching route exists.
    """

    def __init__(self, name: str, path_params: dict[str, Any]) -> None:
        params = ", ".join(list(path_params.keys()))
        super().__init__(f'No route exists for name "{name}" and params "{params}".')


class Match(Enum):
    NONE = 0
    PARTIAL = 1
    FULL = 2


def request_response(
    func: Callable[[Request], Awaitable[Response] | Response],
) -> ASGIApp:
    """
    Takes a function or coroutine `func(request) -> response`,
    and returns an ASGI application.
    """
    f: Callable[[Request], Awaitable[Response]] = (
        func if is_async_callable(func) else functools.partial(run_in_threadpool, func)  # type: ignore[assignment, call-arg]
    )

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive, send)

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            response = await f(request)
            await response(scope, receive, send)

        await wrap_app_handling_exceptions(app, request)(scope, receive, send)

    return app


def websocket_session(
    func: Callable[[WebSocket], Awaitable[None]],
) -> ASGIApp:
    """
    Takes a coroutine `func(session)`, and returns an ASGI application.
    """
    # assert asyncio.iscoroutinefunction(func), "WebSocket endpoints must be async"

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        session = WebSocket(scope, receive=receive, send=send)

        async def app(scope: Scope, receive: Receive, send: Send) -> None:
            await func(session)

        await wrap_app_handling_exceptions(app, session)(scope, receive, send)

    return app


def get_name(endpoint: Callable[..., Any]) -> str:
    return getattr(endpoint, "__name__", endpoint.__class__.__name__)


def replace_params(
    path: str,
    param_convertors: dict[str, Convertor[Any]],
    path_params: dict[str, str],
) -> tuple[str, dict[str, str]]:
    for key, value in list(path_params.items()):
        if "{" + key + "}" in path:
            convertor = param_convertors[key]
            value = convertor.to_string(value)
            path = path.replace("{" + key + "}", value)
            path_params.pop(key)
    return path, path_params


# Match parameters in URL paths, eg. '{param}', and '{param:int}'
PARAM_REGEX = re.compile("{([a-zA-Z_][a-zA-Z0-9_]*)(:[a-zA-Z_][a-zA-Z0-9_]*)?}")


def compile_path(
    path: str,
) -> tuple[Pattern[str], str, dict[str, Convertor[Any]]]:
    """
    Given a path string, like: "/{username:str}",
    or a host string, like: "{subdomain}.mydomain.org", return a three-tuple
    of (regex, format, {param_name:convertor}).

    regex:      "/(?P<username>[^/]+)"
    format:     "/{username}"
    convertors: {"username": StringConvertor()}
    """
    is_host = not path.startswith("/")

    path_regex = "^"
    path_format = ""
    duplicated_params: set[str] = set()

    idx = 0
    param_convertors = {}
    for match in PARAM_REGEX.finditer(path):
        param_name, convertor_type = match.groups("str")
        convertor_type = convertor_type.lstrip(":")
        assert convertor_type in CONVERTOR_TYPES, f"Unknown path convertor '{convertor_type}'"
        convertor = CONVERTOR_TYPES[convertor_type]

        path_regex += re.escape(path[idx : match.start()])
        path_regex += f"(?P<{param_name}>{convertor.regex})"

        path_format += path[idx : match.start()]
        path_format += "{%s}" % param_name

        if param_name in param_convertors:
            duplicated_params.add(param_name)

        param_convertors[param_name] = convertor

        idx = match.end()

    if duplicated_params:
        names = ", ".join(sorted(duplicated_params))
        ending = "s" if len(duplicated_params) > 1 else ""
        raise ValueError(f"Duplicated param name{ending} {names} at path {path}")

    if is_host:
        # Align with `Host.matches()` behavior, which ignores port.
        hostname = path[idx:].split(":")[0]
        path_regex += re.escape(hostname) + "$"
    else:
        path_regex += re.escape(path[idx:]) + "$"

    path_format += path[idx:]

    return re.compile(path_regex), path_format, param_convertors


class BaseRoute:
    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        raise NotImplementedError()  # pragma: no cover

    def url_path_for(self, name: str, /, **path_params: Any) -> URLPath:
        raise NotImplementedError()  # pragma: no cover

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        A route may be used in isolation as a stand-alone ASGI app.
        This is a somewhat contrived case, as they'll almost always be used
        within a Router, but could be useful for some tooling and minimal apps.
        """
        match, child_scope = self.matches(scope)
        if match == Match.NONE:
            if scope["type"] == "http":
                response = PlainTextResponse("Not Found", status_code=404)
                await response(scope, receive, send)
            elif scope["type"] == "websocket":  # pragma: no branch
                websocket_close = WebSocketClose()
                await websocket_close(scope, receive, send)
            return

        scope.update(child_scope)
        await self.handle(scope, receive, send)


class Route(BaseRoute):
    def __init__(
        self,
        path: str,
        endpoint: Callable[..., Any],
        *,
        methods: Collection[str] | None = None,
        name: str | None = None,
        include_in_schema: bool = True,
        middleware: Sequence[Middleware] | None = None,
    ) -> None:
        assert path.startswith("/"), "Routed paths must start with '/'"
        self.path = path
        self.endpoint = endpoint
        self.name = get_name(endpoint) if name is None else name
        self.include_in_schema = include_in_schema

        endpoint_handler = endpoint
        while isinstance(endpoint_handler, functools.partial):
            endpoint_handler = endpoint_handler.func
        if inspect.isfunction(endpoint_handler) or inspect.ismethod(endpoint_handler):
            # Endpoint is function or method. Treat it as `func(request) -> response`.
            self.app = request_response(endpoint)
            if methods is None:
                methods = ["GET"]
        else:
            # Endpoint is a class. Treat it as ASGI.
            self.app = endpoint

        if middleware is not None:
            for cls, args, kwargs in reversed(middleware):
                self.app = cls(self.app, *args, **kwargs)

        if methods is None:
            self.methods = None
        else:
            self.methods = {method.upper() for method in methods}
            if "GET" in self.methods:
                self.methods.add("HEAD")

        self.path_regex, self.path_format, self.param_convertors = compile_path(path)

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        path_params: dict[str, Any]
        if scope["type"] == "http":
            route_path = get_route_path(scope)
            match = self.path_regex.match(route_path)
            if match:
                matched_params = match.groupdict()
                for key, value in matched_params.items():
                    matched_params[key] = self.param_convertors[key].convert(value)
                path_params = dict(scope.get("path_params", {}))
                path_params.update(matched_params)
                child_scope = {"endpoint": self.endpoint, "path_params": path_params}
                if self.methods and scope["method"] not in self.methods:
                    return Match.PARTIAL, child_scope
                else:
                    return Match.FULL, child_scope
        return Match.NONE, {}

    def url_path_for(self, name: str, /, **path_params: Any) -> URLPath:
        seen_params = set(path_params.keys())
        expected_params = set(self.param_convertors.keys())

        if name != self.name or seen_params != expected_params:
            raise NoMatchFound(name, path_params)

        path, remaining_params = replace_params(self.path_format, self.param_convertors, path_params)
        assert not remaining_params
        return URLPath(path=path, protocol="http")

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.methods and scope["method"] not in self.methods:
            headers = {"Allow": ", ".join(self.methods)}
            if "app" in scope:
                raise HTTPException(status_code=405, headers=headers)
            else:
                response = PlainTextResponse("Method Not Allowed", status_code=405, headers=headers)
            await response(scope, receive, send)
        else:
            await self.app(scope, receive, send)

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, Route)
            and self.path == other.path
            and self.endpoint == other.endpoint
            and self.methods == other.methods
        )

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        methods = sorted(self.methods or [])
        path, name = self.path, self.name
        return f"{class_name}(path={path!r}, name={name!r}, methods={methods!r})"


class WebSocketRoute(BaseRoute):
    def __init__(
        self,
        path: str,
        endpoint: Callable[..., Any],
        *,
        name: str | None = None,
        middleware: Sequence[Middleware] | None = None,
    ) -> None:
        assert path.startswith("/"), "Routed paths must start with '/'"
        self.path = path
        self.endpoint = endpoint
        self.name = get_name(endpoint) if name is None else name

        endpoint_handler = endpoint
        while isinstance(endpoint_handler, functools.partial):
            endpoint_handler = endpoint_handler.func
        if inspect.isfunction(endpoint_handler) or inspect.ismethod(endpoint_handler):
            # Endpoint is function or method. Treat it as `func(websocket)`.
            self.app = websocket_session(endpoint)
        else:
            # Endpoint is a class. Treat it as ASGI.
            self.app = endpoint

        if middleware is not None:
            for cls, args, kwargs in reversed(middleware):
                self.app = cls(self.app, *args, **kwargs)

        self.path_regex, self.path_format, self.param_convertors = compile_path(path)

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        path_params: dict[str, Any]
        if scope["type"] == "websocket":
            route_path = get_route_path(scope)
            match = self.path_regex.match(route_path)
            if match:
                matched_params = match.groupdict()
                for key, value in matched_params.items():
                    matched_params[key] = self.param_convertors[key].convert(value)
                path_params = dict(scope.get("path_params", {}))
                path_params.update(matched_params)
                child_scope = {"endpoint": self.endpoint, "path_params": path_params}
                return Match.FULL, child_scope
        return Match.NONE, {}

    def url_path_for(self, name: str, /, **path_params: Any) -> URLPath:
        seen_params = set(path_params.keys())
        expected_params = set(self.param_convertors.keys())

        if name != self.name or seen_params != expected_params:
            raise NoMatchFound(name, path_params)

        path, remaining_params = replace_params(self.path_format, self.param_convertors, path_params)
        assert not remaining_params
        return URLPath(path=path, protocol="websocket")

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, WebSocketRoute) and self.path == other.path and self.endpoint == other.endpoint

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(path={self.path!r}, name={self.name!r})"


class Mount(BaseRoute):
    def __init__(
        self,
        path: str,
        app: ASGIApp | None = None,
        routes: Sequence[BaseRoute] | None = None,
        name: str | None = None,
        *,
        middleware: Sequence[Middleware] | None = None,
    ) -> None:
        assert path == "" or path.startswith("/"), "Routed paths must start with '/'"
        assert app is not None or routes is not None, "Either 'app=...', or 'routes=' must be specified"
        self.path = path.rstrip("/")
        if app is not None:
            self._base_app: ASGIApp = app
        else:
            self._base_app = Router(routes=routes)
        self.app = self._base_app
        if middleware is not None:
            for cls, args, kwargs in reversed(middleware):
                self.app = cls(self.app, *args, **kwargs)
        self.name = name
        self.path_regex, self.path_format, self.param_convertors = compile_path(self.path + "/{path:path}")

    @property
    def routes(self) -> list[BaseRoute]:
        return getattr(self._base_app, "routes", [])

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        path_params: dict[str, Any]
        if scope["type"] in ("http", "websocket"):  # pragma: no branch
            root_path = scope.get("root_path", "")
            route_path = get_route_path(scope)
            match = self.path_regex.match(route_path)
            if match:
                matched_params = match.groupdict()
                for key, value in matched_params.items():
                    matched_params[key] = self.param_convertors[key].convert(value)
                remaining_path = "/" + matched_params.pop("path")
                matched_path = route_path[: -len(remaining_path)]
                path_params = dict(scope.get("path_params", {}))
                path_params.update(matched_params)
                child_scope = {
                    "path_params": path_params,
                    # app_root_path will only be set at the top level scope,
                    # initialized with the (optional) value of a root_path
                    # set above/before Starlette. And even though any
                    # mount will have its own child scope with its own respective
                    # root_path, the app_root_path will always be available in all
                    # the child scopes with the same top level value because it's
                    # set only once here with a default, any other child scope will
                    # just inherit that app_root_path default value stored in the
                    # scope. All this is needed to support Request.url_for(), as it
                    # uses the app_root_path to build the URL path.
                    "app_root_path": scope.get("app_root_path", root_path),
                    "root_path": root_path + matched_path,
                    "endpoint": self.app,
                }
                return Match.FULL, child_scope
        return Match.NONE, {}

    def url_path_for(self, name: str, /, **path_params: Any) -> URLPath:
        if self.name is not None and name == self.name and "path" in path_params:
            # 'name' matches "<mount_name>".
            path_params["path"] = path_params["path"].lstrip("/")
            path, remaining_params = replace_params(self.path_format, self.param_convertors, path_params)
            if not remaining_params:
                return URLPath(path=path)
        elif self.name is None or name.startswith(self.name + ":"):
            if self.name is None:
                # No mount name.
                remaining_name = name
            else:
                # 'name' matches "<mount_name>:<child_name>".
                remaining_name = name[len(self.name) + 1 :]
            path_kwarg = path_params.get("path")
            path_params["path"] = ""
            path_prefix, remaining_params = replace_params(self.path_format, self.param_convertors, path_params)
            if path_kwarg is not None:
                remaining_params["path"] = path_kwarg
            for route in self.routes or []:
                try:
                    url = route.url_path_for(remaining_name, **remaining_params)
                    return URLPath(path=path_prefix.rstrip("/") + str(url), protocol=url.protocol)
                except NoMatchFound:
                    pass
        raise NoMatchFound(name, path_params)

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Mount) and self.path == other.path and self.app == other.app

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        name = self.name or ""
        return f"{class_name}(path={self.path!r}, name={name!r}, app={self.app!r})"


class Host(BaseRoute):
    def __init__(self, host: str, app: ASGIApp, name: str | None = None) -> None:
        assert not host.startswith("/"), "Host must not start with '/'"
        self.host = host
        self.app = app
        self.name = name
        self.host_regex, self.host_format, self.param_convertors = compile_path(host)

    @property
    def routes(self) -> list[BaseRoute]:
        return getattr(self.app, "routes", [])

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        if scope["type"] in ("http", "websocket"):  # pragma:no branch
            headers = Headers(scope=scope)
            host = headers.get("host", "").split(":")[0]
            match = self.host_regex.match(host)
            if match:
                matched_params = match.groupdict()
                for key, value in matched_params.items():
                    matched_params[key] = self.param_convertors[key].convert(value)
                path_params = dict(scope.get("path_params", {}))
                path_params.update(matched_params)
                child_scope = {"path_params": path_params, "endpoint": self.app}
                return Match.FULL, child_scope
        return Match.NONE, {}

    def url_path_for(self, name: str, /, **path_params: Any) -> URLPath:
        if self.name is not None and name == self.name and "path" in path_params:
            # 'name' matches "<mount_name>".
            path = path_params.pop("path")
            host, remaining_params = replace_params(self.host_format, self.param_convertors, path_params)
            if not remaining_params:
                return URLPath(path=path, host=host)
        elif self.name is None or name.startswith(self.name + ":"):
            if self.name is None:
                # No mount name.
                remaining_name = name
            else:
                # 'name' matches "<mount_name>:<child_name>".
                remaining_name = name[len(self.name) + 1 :]
            host, remaining_params = replace_params(self.host_format, self.param_convertors, path_params)
            for route in self.routes or []:
                try:
                    url = route.url_path_for(remaining_name, **remaining_params)
                    return URLPath(path=str(url), protocol=url.protocol, host=host)
                except NoMatchFound:
                    pass
        raise NoMatchFound(name, path_params)

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Host) and self.host == other.host and self.app == other.app

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        name = self.name or ""
        return f"{class_name}(host={self.host!r}, name={name!r}, app={self.app!r})"


_T = TypeVar("_T")


class _AsyncLiftContextManager(AbstractAsyncContextManager[_T]):
    def __init__(self, cm: AbstractContextManager[_T]):
        self._cm = cm

    async def __aenter__(self) -> _T:
        return self._cm.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: types.TracebackType | None,
    ) -> bool | None:
        return self._cm.__exit__(exc_type, exc_value, traceback)


def _wrap_gen_lifespan_context(
    lifespan_context: Callable[[Any], Generator[Any, Any, Any]],
) -> Callable[[Any], AbstractAsyncContextManager[Any]]:
    cmgr = contextlib.contextmanager(lifespan_context)

    @functools.wraps(cmgr)
    def wrapper(app: Any) -> _AsyncLiftContextManager[Any]:
        return _AsyncLiftContextManager(cmgr(app))

    return wrapper


class _DefaultLifespan:
    def __init__(self, router: Router):
        self._router = router

    async def __aenter__(self) -> None:
        pass

    async def __aexit__(self, *exc_info: object) -> None:
        pass

    def __call__(self: _T, app: object) -> _T:
        return self


class RouteLookup(Protocol):
    """Narrows the routes a `Router` has to check for an incoming scope.

    A route lookup never decides a match: `Router` still calls `BaseRoute.matches()`
    on every candidate, so path params, method handling, mounts, hosts and
    registration order stay Starlette's business. The lookup only answers "which
    routes could possibly match?", which lets an implementation replace the linear
    scan with a trie, a radix tree, a native extension, or anything else.

    Implementations must honour the following contract. Breaking it means routes
    silently stop being reachable:

    * `candidates()` must return a **superset** of the routes whose `matches()`
      would return `Match.FULL` **or** `Match.PARTIAL`. Never filter on
      `scope["method"]` or `scope["type"]`: dropping method mismatches turns a
      `405 Method Not Allowed` into a `404 Not Found`.
    * Candidates must be yielded in registration order, without duplicates.
    * Only routes from the `routes` sequence the lookup was built with may be
      returned.
    * A route may only be indexed by its path when its type is understood
      exactly. Use `type(route) is Route`, not `isinstance()`: a subclass may
      override `matches()` and match paths its own `path` does not describe.
      Anything else must be treated as an always-candidate.
    * `candidates()` is called at least once per request, and again with a
      modified scope for the trailing-slash redirect check, so it must not cache
      results by scope identity, and must return a fresh iterable every call.
    * It must be sync, must not mutate the scope, and must not receive or send
      ASGI messages.
    * Candidates may be consumed lazily and abandoned as soon as a route matches,
      so a generator must not hold locks or other resources across a yield.

    Use `starlette.routing.StrictRouteLookup` in tests to verify the contract.
    """

    def candidates(self, scope: Scope, /) -> Iterable[BaseRoute]: ...


# Builds a `RouteLookup` for one router's route table. Receives an immutable
# snapshot of the routes, so the lookup can compile them once, up front.
RouteLookupFactory = Callable[[Sequence[BaseRoute]], RouteLookup]


class RouteLookupError(RuntimeError):
    """Raised by `StrictRouteLookup` when a `RouteLookup` breaks its contract."""


class StrictRouteLookup:
    """A `RouteLookupFactory` wrapper that verifies another factory's output.

    Runs the plain linear scan alongside the wrapped lookup and raises
    `RouteLookupError` when a route that would have matched is missing from the
    candidates, when candidates are out of registration order, duplicated, or
    foreign to the route table.

    Intended for tests, CI and staging. It is slower than no lookup at all.

        app.route_lookup_factory = StrictRouteLookup(ffroute.RouteLookup)
    """

    def __init__(self, factory: RouteLookupFactory) -> None:
        self.factory = factory

    def __call__(self, routes: Sequence[BaseRoute]) -> _StrictRouteLookup:
        return _StrictRouteLookup(self.factory(routes), routes)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.factory!r})"


class _StrictRouteLookup:
    def __init__(self, lookup: RouteLookup, routes: Sequence[BaseRoute]) -> None:
        self.lookup = lookup
        self.routes = routes
        self.positions = {id(route): index for index, route in enumerate(routes)}

    def candidates(self, scope: Scope, /) -> list[BaseRoute]:
        candidates = list(self.lookup.candidates(scope))
        seen: set[int] = set()
        previous = -1
        for route in candidates:
            position = self.positions.get(id(route), -1)
            if position == -1:
                raise RouteLookupError(f"{self.lookup!r} returned {route!r}, which is not in the route table.")
            if id(route) in seen:
                raise RouteLookupError(f"{self.lookup!r} returned {route!r} more than once.")
            if position < previous:
                raise RouteLookupError(f"{self.lookup!r} returned {route!r} out of registration order.")
            seen.add(id(route))
            previous = position

        for route in self.routes:
            if id(route) in seen:
                continue
            match, _ = route.matches(scope)
            if match != Match.NONE:
                raise RouteLookupError(
                    f"{self.lookup!r} dropped {route!r}, which matches "
                    f"{scope['type']} {get_route_path(scope)!r} with {match}."
                )

        return candidates

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.lookup!r})"


class TrieRouteLookup:
    """A `RouteLookupFactory` backed by a segment trie.

    Narrows the routes a router checks by walking the path one segment at a time,
    instead of running every route's `path_regex`. It returns a superset of the
    routes that could match, in registration order, so `Route.matches()` still
    decides and every routing behaviour is preserved.

        app.route_lookup_factory = TrieRouteLookup

    `Route` and `WebSocketRoute` are indexed by path. `Mount`, `Host`, route
    subclasses and anything else are always-candidates, and so are paths the trie
    cannot represent exactly, such as a segment whose convertor could match a '/'.
    """

    def __init__(self, routes: Sequence[BaseRoute]) -> None:
        self.routes = tuple(routes)
        trie = RouteTrie()
        for index, route in enumerate(self.routes):
            # Exact type check: a subclass may override `matches()` and match paths
            # its own `path` does not describe.
            if type(route) is Route or type(route) is WebSocketRoute:
                trie.add(index, route.path, route.param_convertors)
            else:
                trie.add_always(index)
        self.trie = trie

    def candidates(self, scope: Scope, /) -> list[BaseRoute]:
        routes = self.routes
        return [routes[index] for index in self.trie.match_all(get_route_path(scope))]


def _get_router(app: ASGIApp) -> Router | None:
    if isinstance(app, Router):
        return app
    # `Starlette` and FastAPI applications keep their router on `.router`.
    router = getattr(app, "router", None)
    return router if isinstance(router, Router) else None


def iter_child_routers(route: BaseRoute) -> Iterator[Router]:
    """Yield the routers nested inside a route, so a route lookup can be applied
    to a whole routing tree.

    Handles `Mount` and `Host`, whether they wrap a `Router`, a `Starlette`
    application, or an application exposing a `.router`. Mounts wrapping opaque
    ASGI apps, such as `StaticFiles`, yield nothing. Custom route containers can
    take part by implementing `iter_child_routers()` themselves.
    """
    hook = getattr(route, "iter_child_routers", None)
    if hook is not None:
        yield from hook()
        return

    if isinstance(route, Mount):
        # `_base_app` is the unwrapped app: `route.app` may be a middleware stack,
        # and middleware does not expose the router underneath it.
        app: ASGIApp = route._base_app
    elif isinstance(route, Host):
        app = route.app
    else:
        return

    router = _get_router(app)
    if router is not None:
        yield router


class _Unset:
    def __repr__(self) -> str:  # pragma: no cover
        return "<unset>"


# Distinguishes "no route lookup configured, inherit one from a parent router" from
# `None`, which means "explicitly no route lookup".
UNSET: Any = _Unset()


class _RouteList(list[BaseRoute]):
    """A list that counts its own mutations.

    `Router.routes` is public and mutated in place all over Starlette, FastAPI and
    user code. A compiled route lookup has to be rebuilt when that happens, and
    checking route identity on every request would put an O(N) scan back on the hot
    path, which is the cost the lookup exists to remove.
    """

    __slots__ = ("generation",)

    def __init__(self, routes: Iterable[BaseRoute] = ()) -> None:
        super().__init__(routes)
        self.generation = 0

    def append(self, route: BaseRoute) -> None:
        super().append(route)
        self.generation += 1

    def extend(self, routes: Iterable[BaseRoute]) -> None:
        super().extend(routes)
        self.generation += 1

    def insert(self, index: Any, route: BaseRoute) -> None:
        super().insert(index, route)
        self.generation += 1

    def remove(self, route: BaseRoute) -> None:
        super().remove(route)
        self.generation += 1

    def pop(self, index: SupportsIndex = -1) -> BaseRoute:
        route = super().pop(index)
        self.generation += 1
        return route

    def clear(self) -> None:
        super().clear()
        self.generation += 1

    def sort(self, **kwargs: Any) -> None:
        super().sort(**kwargs)
        self.generation += 1

    def reverse(self) -> None:
        super().reverse()
        self.generation += 1

    def __setitem__(self, index: Any, route: Any) -> None:
        super().__setitem__(index, route)
        self.generation += 1

    def __delitem__(self, index: Any) -> None:
        super().__delitem__(index)
        self.generation += 1

    def __iadd__(self, routes: Iterable[BaseRoute]) -> _RouteList:  # type: ignore[override,misc]
        super().__iadd__(routes)
        self.generation += 1
        return self

    def __imul__(self, value: SupportsIndex) -> _RouteList:
        super().__imul__(value)
        self.generation += 1
        return self


class _RouteTable:
    """An immutable snapshot of a router's routes and the lookup compiled for them."""

    __slots__ = ("source", "generation", "routes", "lookup")

    def __init__(
        self,
        source: _RouteList,
        routes: tuple[BaseRoute, ...],
        lookup: RouteLookup | None,
    ) -> None:
        self.source = source
        self.generation = source.generation
        self.routes = routes
        self.lookup = lookup


class Router:
    def __init__(
        self,
        routes: Sequence[BaseRoute] | None = None,
        redirect_slashes: bool = True,
        default: ASGIApp | None = None,
        # the generic to Lifespan[AppType] is the type of the top level application
        # which the router cannot know statically, so we use Any
        lifespan: Lifespan[Any] | None = None,
        *,
        middleware: Sequence[Middleware] | None = None,
    ) -> None:
        self._route_lookup_factory: RouteLookupFactory | None = UNSET
        self._route_lookup_inherited = False
        self._route_table: _RouteTable | None = None
        self.routes = [] if routes is None else list(routes)
        self.redirect_slashes = redirect_slashes
        self.default = self.not_found if default is None else default

        if lifespan is None:
            self.lifespan_context: Lifespan[Any] = _DefaultLifespan(self)

        elif inspect.isasyncgenfunction(lifespan):
            warnings.warn(
                "async generator function lifespans are deprecated, "
                "use an @contextlib.asynccontextmanager function instead",
                StarletteDeprecationWarning,
            )
            self.lifespan_context = asynccontextmanager(lifespan)
        elif inspect.isgeneratorfunction(lifespan):
            warnings.warn(
                "generator function lifespans are deprecated, use an @contextlib.asynccontextmanager function instead",
                StarletteDeprecationWarning,
            )
            self.lifespan_context = _wrap_gen_lifespan_context(lifespan)
        else:
            self.lifespan_context = lifespan

        self.middleware_stack = self.app
        if middleware:
            for cls, args, kwargs in reversed(middleware):
                self.middleware_stack = cls(self.middleware_stack, *args, **kwargs)

    @property
    def routes(self) -> list[BaseRoute]:
        return self._routes

    @routes.setter
    def routes(self, routes: Sequence[BaseRoute]) -> None:
        self._routes = _RouteList(routes)
        self.invalidate_route_lookup()

    @property
    def route_lookup_factory(self) -> RouteLookupFactory | None:
        """The `RouteLookupFactory` used to narrow route matching.

        Assigning applies to this router *and every nested router below it*, so a
        single assignment covers mounted sub-applications, routers behind `Host`,
        and routers mounted later:

            app.route_lookup_factory = ffroute.RouteLookup

        Each router compiles its own lookup from its own routes. A nested router
        that was configured explicitly keeps its own lookup; assign `None` to turn
        the lookup off for a subtree and go back to the plain linear scan.
        """
        factory = self._route_lookup_factory
        return None if factory is UNSET else factory

    @route_lookup_factory.setter
    def route_lookup_factory(self, factory: RouteLookupFactory | None) -> None:
        self._route_lookup_factory = factory
        # Explicit beats inherited: a parent will not overwrite this one.
        self._route_lookup_inherited = False
        self.invalidate_route_lookup()

    @property
    def route_lookup(self) -> RouteLookup | None:
        """The compiled lookup currently in use, or `None` for the linear scan.

        Read-only, and `None` until the lookup is built. Useful to check whether a
        third-party lookup is actually active.
        """
        table = self._route_table
        return None if table is None else table.lookup

    def invalidate_route_lookup(self) -> None:
        """Drop the compiled route table so it is rebuilt on next use.

        Adding, removing or replacing routes is detected automatically. Call this
        after mutating a route object in place, which is invisible from the
        outside:

            route.path = "/changed"
            router.invalidate_route_lookup()
        """
        self._route_table = None

    def build_route_lookup(self) -> None:
        """Compile the route lookup for this router and every nested router.

        Called on lifespan startup, so a broken lookup fails at boot instead of on
        the first request, and no request pays the build cost. Call it directly for
        apps that never run a lifespan.
        """
        visited: set[int] = set()
        stack: list[Router] = [self]
        while stack:
            router = stack.pop()
            if id(router) in visited:
                continue
            visited.add(id(router))
            table = router._build_route_table()
            for route in table.routes:
                stack.extend(iter_child_routers(route))

    def _build_route_table(self) -> _RouteTable:
        source = self._routes
        routes = tuple(source)
        factory = self._route_lookup_factory
        factory = None if factory is UNSET else factory

        # Push the factory down as part of the build: routers mounted after the
        # assignment inherit it too, without the route list having to know about
        # lookups at all.
        for route in routes:
            for child in iter_child_routers(route):
                child._inherit_route_lookup(factory)

        table = _RouteTable(source, routes, None if factory is None else factory(routes))
        self._route_table = table
        return table

    def _inherit_route_lookup(self, factory: RouteLookupFactory | None) -> None:
        if self._route_lookup_factory is not UNSET and not self._route_lookup_inherited:
            return  # Configured explicitly on this router: leave it alone.
        if self._route_lookup_inherited and self._route_lookup_factory is factory:
            return
        self._route_lookup_factory = factory
        self._route_lookup_inherited = True
        self.invalidate_route_lookup()

    def _route_candidates(self, scope: Scope) -> Iterable[BaseRoute]:
        table = self._route_table
        routes = self._routes
        if table is None or table.source is not routes or table.generation != routes.generation:
            table = self._build_route_table()
        lookup = table.lookup
        return table.routes if lookup is None else lookup.candidates(scope)

    async def not_found(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            websocket_close = WebSocketClose()
            await websocket_close(scope, receive, send)
            return

        # If we're running inside a starlette application then raise an
        # exception, so that the configurable exception handler can deal with
        # returning the response. For plain ASGI apps, just return the response.
        if "app" in scope:
            raise HTTPException(status_code=404)
        else:
            response = PlainTextResponse("Not Found", status_code=404)
        await response(scope, receive, send)

    def url_path_for(self, name: str, /, **path_params: Any) -> URLPath:
        for route in self.routes:
            try:
                return route.url_path_for(name, **path_params)
            except NoMatchFound:
                pass
        raise NoMatchFound(name, path_params)

    async def lifespan(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        Handle ASGI lifespan messages, which allows us to manage application
        startup and shutdown events.
        """
        started = False
        app: Any = scope.get("app")
        # Compile now, so a broken route lookup fails startup rather than requests.
        self.build_route_lookup()
        await receive()
        try:
            async with self.lifespan_context(app) as maybe_state:
                if maybe_state is not None:
                    if "state" not in scope:
                        raise RuntimeError('The server does not support "state" in the lifespan scope.')
                    scope["state"].update(maybe_state)
                await send({"type": "lifespan.startup.complete"})
                started = True
                await receive()
        except BaseException:
            exc_text = traceback.format_exc()
            if started:
                await send({"type": "lifespan.shutdown.failed", "message": exc_text})
            else:
                await send({"type": "lifespan.startup.failed", "message": exc_text})
            raise
        else:
            await send({"type": "lifespan.shutdown.complete"})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        The main entry point to the Router class.
        """
        await self.middleware_stack(scope, receive, send)

    async def app(self, scope: Scope, receive: Receive, send: Send) -> None:
        assert scope["type"] in ("http", "websocket", "lifespan")

        if "router" not in scope:
            scope["router"] = self

        if scope["type"] == "lifespan":
            await self.lifespan(scope, receive, send)
            return

        partial = None

        for route in self._route_candidates(scope):
            # Determine if any route matches the incoming scope,
            # and hand over to the matching route if found.
            match, child_scope = route.matches(scope)
            if match == Match.FULL:
                scope.update(child_scope)
                await route.handle(scope, receive, send)
                return
            elif match == Match.PARTIAL and partial is None:
                partial = route
                partial_scope = child_scope

        if partial is not None:
            #  Handle partial matches. These are cases where an endpoint is
            # able to handle the request, but is not a preferred option.
            # We use this in particular to deal with "405 Method Not Allowed".
            scope.update(partial_scope)
            await partial.handle(scope, receive, send)
            return

        route_path = get_route_path(scope)
        if scope["type"] == "http" and self.redirect_slashes and route_path != "/":
            redirect_scope = dict(scope)
            if route_path.endswith("/"):
                redirect_scope["path"] = redirect_scope["path"].rstrip("/")
            else:
                redirect_scope["path"] = redirect_scope["path"] + "/"

            for route in self._route_candidates(redirect_scope):
                match, child_scope = route.matches(redirect_scope)
                if match != Match.NONE:
                    redirect_url = URL(scope=redirect_scope)
                    response = RedirectResponse(url=str(redirect_url))
                    await response(scope, receive, send)
                    return

        await self.default(scope, receive, send)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Router) and self.routes == other.routes

    def mount(self, path: str, app: ASGIApp, name: str | None = None) -> None:  # pragma: no cover
        route = Mount(path, app=app, name=name)
        self.routes.append(route)

    def host(self, host: str, app: ASGIApp, name: str | None = None) -> None:  # pragma: no cover
        route = Host(host, app=app, name=name)
        self.routes.append(route)

    def add_route(
        self,
        path: str,
        endpoint: Callable[[Request], Awaitable[Response] | Response],
        methods: Collection[str] | None = None,
        name: str | None = None,
        include_in_schema: bool = True,
    ) -> None:  # pragma: no cover
        route = Route(
            path,
            endpoint=endpoint,
            methods=methods,
            name=name,
            include_in_schema=include_in_schema,
        )
        self.routes.append(route)

    def add_websocket_route(
        self,
        path: str,
        endpoint: Callable[[WebSocket], Awaitable[None]],
        name: str | None = None,
    ) -> None:  # pragma: no cover
        route = WebSocketRoute(path, endpoint=endpoint, name=name)
        self.routes.append(route)
