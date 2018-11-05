import asyncio
import inspect
import re
import typing
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

from starlette.datastructures import URL, URLPath
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.types import ASGIApp, ASGIInstance, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketClose


class NoMatchFound(Exception):
    """
    Raised by `.url_for(name, **path_params)` and `.url_path_for(name, **path_params)`
    if no matching route exists.
    """

    pass


class Match(Enum):
    NONE = 0
    PARTIAL = 1
    FULL = 2


def request_response(func: typing.Callable) -> ASGIApp:
    """
    Takes a function or coroutine `func(request) -> response`,
    and returns an ASGI application.
    """
    is_coroutine = asyncio.iscoroutinefunction(func)

    def app(scope: Scope) -> ASGIInstance:
        async def awaitable(receive: Receive, send: Send) -> None:
            request = Request(scope, receive=receive)
            if is_coroutine:
                response = await func(request)
            else:
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(None, func, request)
            await response(receive, send)

        return awaitable

    return app


def websocket_session(func: typing.Callable) -> ASGIApp:
    """
    Takes a coroutine `func(session)`, and returns an ASGI application.
    """
    # assert asyncio.iscoroutinefunction(func), "WebSocket endpoints must be async"

    def app(scope: Scope) -> ASGIInstance:
        async def awaitable(receive: Receive, send: Send) -> None:
            session = WebSocket(scope, receive=receive, send=send)
            await func(session)

        return awaitable

    return app


def get_name(endpoint: typing.Callable) -> str:
    if inspect.isfunction(endpoint) or inspect.isclass(endpoint):
        return endpoint.__name__
    return endpoint.__class__.__name__


def replace_params(
    path: str, path_params: typing.Dict[str, str]
) -> typing.Tuple[str, dict]:
    for key, value in list(path_params.items()):
        if "{" + key + "}" in path:
            path_params.pop(key)
            path = path.replace("{" + key + "}", value)
    return path, path_params


class BaseRoute:
    def matches(self, scope: Scope) -> typing.Tuple[Match, Scope]:
        raise NotImplementedError()  # pragma: no cover

    def url_path_for(self, name: str, **path_params: str) -> URLPath:
        raise NotImplementedError()  # pragma: no cover

    def __call__(self, scope: Scope) -> ASGIInstance:
        raise NotImplementedError()  # pragma: no cover


class Route(BaseRoute):
    def __init__(
        self,
        path: str,
        endpoint: typing.Callable,
        *,
        methods: typing.List[str] = None,
        name: str = None,
        include_in_schema: bool = True
    ) -> None:
        assert path.startswith("/"), "Routed paths must always start '/'"
        self.path = path
        self.endpoint = endpoint
        self.name = get_name(endpoint) if name is None else name
        self.include_in_schema = include_in_schema

        if inspect.isfunction(endpoint) or inspect.ismethod(endpoint):
            # Endpoint is function or method. Treat it as `func(request) -> response`.
            self.app = request_response(endpoint)
            if methods is None:
                methods = ["GET"]
        else:
            # Endpoint is a class. Treat it as ASGI.
            self.app = endpoint

        self.methods = methods
        regex = "^" + path + "$"
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]+)", regex)
        self.path_regex = re.compile(regex)
        self.param_names = set(self.path_regex.groupindex.keys())

    def matches(self, scope: Scope) -> typing.Tuple[Match, Scope]:
        if scope["type"] == "http":
            match = self.path_regex.match(scope["path"])
            if match:
                path_params = dict(scope.get("path_params", {}))
                path_params.update(match.groupdict())
                child_scope = dict(scope)
                child_scope["path_params"] = path_params
                if self.methods and scope["method"] not in self.methods:
                    return Match.PARTIAL, child_scope
                else:
                    return Match.FULL, child_scope
        return Match.NONE, {}

    def url_path_for(self, name: str, **path_params: str) -> URLPath:
        if name != self.name or self.param_names != set(path_params.keys()):
            raise NoMatchFound()
        path, remaining_params = replace_params(self.path, path_params)
        assert not remaining_params
        return URLPath(path=path, protocol="http")

    def __call__(self, scope: Scope) -> ASGIInstance:
        if self.methods and scope["method"] not in self.methods:
            if "app" in scope:
                raise HTTPException(status_code=405)
            return PlainTextResponse("Method Not Allowed", status_code=405)
        return self.app(scope)

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, Route)
            and self.path == other.path
            and self.endpoint == other.endpoint
            and self.methods == other.methods
        )


class WebSocketRoute(BaseRoute):
    def __init__(
        self, path: str, endpoint: typing.Callable, *, name: str = None
    ) -> None:
        assert path.startswith("/"), "Routed paths must always start '/'"
        self.path = path
        self.endpoint = endpoint
        self.name = get_name(endpoint) if name is None else name

        if inspect.isfunction(endpoint) or inspect.ismethod(endpoint):
            # Endpoint is function or method. Treat it as `func(websocket)`.
            self.app = websocket_session(endpoint)
        else:
            # Endpoint is a class. Treat it as ASGI.
            self.app = endpoint

        regex = "^" + path + "$"
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]+)", regex)
        self.path_regex = re.compile(regex)
        self.param_names = set(self.path_regex.groupindex.keys())

    def matches(self, scope: Scope) -> typing.Tuple[Match, Scope]:
        if scope["type"] == "websocket":
            match = self.path_regex.match(scope["path"])
            if match:
                path_params = dict(scope.get("path_params", {}))
                path_params.update(match.groupdict())
                child_scope = dict(scope)
                child_scope["path_params"] = path_params
                return Match.FULL, child_scope
        return Match.NONE, {}

    def url_path_for(self, name: str, **path_params: str) -> URLPath:
        if name != self.name or self.param_names != set(path_params.keys()):
            raise NoMatchFound()
        path, remaining_params = replace_params(self.path, path_params)
        assert not remaining_params
        return URLPath(path=path, protocol="websocket")

    def __call__(self, scope: Scope) -> ASGIInstance:
        return self.app(scope)

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, WebSocketRoute)
            and self.path == other.path
            and self.endpoint == other.endpoint
        )


class Mount(BaseRoute):
    def __init__(self, path: str, app: ASGIApp, name: str = None) -> None:
        assert path == "" or path.startswith("/"), "Routed paths must always start '/'"
        self.path = path.rstrip("/")
        self.app = app
        regex = "^" + self.path + "(?P<path>/.*)$"
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]*)", regex)
        self.path_regex = re.compile(regex)
        self.name = name

    @property
    def routes(self) -> typing.List[BaseRoute]:
        return getattr(self.app, "routes", None)

    def matches(self, scope: Scope) -> typing.Tuple[Match, Scope]:
        match = self.path_regex.match(scope["path"])
        if match:
            matched_params = match.groupdict()
            matched_path = matched_params.pop("path")
            path_params = dict(scope.get("path_params", {}))
            path_params.update(matched_params)
            child_scope = dict(scope)
            child_scope["path_params"] = path_params
            child_scope["root_path"] = (
                scope.get("root_path", "") + scope["path"][: -len(matched_path)]
            )
            child_scope["path"] = matched_path
            return Match.FULL, child_scope
        return Match.NONE, {}

    def url_path_for(self, name: str, **path_params: str) -> URLPath:
        if self.name is not None and name == self.name and "path" in path_params:
            # 'name' matches "<mount_name>".
            path_params["path"] = path_params["path"].lstrip("/")
            path, remaining_params = replace_params(self.path + "/{path}", path_params)
            if not remaining_params:
                return URLPath(path=path, protocol="http")
        elif self.name is None or name.startswith(self.name + ":"):
            if self.name is None:
                # No mount name.
                remaining_name = name
            else:
                # 'name' matches "<mount_name>:<child_name>".
                remaining_name = name[len(self.name) + 1 :]
            path, remaining_params = replace_params(self.path, path_params)
            for route in self.routes or []:
                try:
                    url = route.url_path_for(remaining_name, **remaining_params)
                    return URLPath(path=path + str(url), protocol=url.protocol)
                except NoMatchFound as exc:
                    pass
        raise NoMatchFound()

    def __call__(self, scope: Scope) -> ASGIInstance:
        return self.app(scope)

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, Mount)
            and self.path == other.path
            and self.app == other.app
        )


class Router:
    def __init__(
        self,
        routes: typing.List[BaseRoute] = None,
        redirect_slashes: bool = True,
        default: ASGIApp = None,
    ) -> None:
        self.routes = [] if routes is None else routes
        self.redirect_slashes = redirect_slashes
        self.default = self.not_found if default is None else default

    def mount(self, path: str, app: ASGIApp) -> None:
        route = Mount(path, app=app)
        self.routes.append(route)

    def add_route(
        self,
        path: str,
        endpoint: typing.Callable,
        methods: typing.List[str] = None,
        include_in_schema: bool = True,
    ) -> None:
        route = Route(
            path,
            endpoint=endpoint,
            methods=methods,
            include_in_schema=include_in_schema,
        )
        self.routes.append(route)

    def add_websocket_route(self, path: str, endpoint: typing.Callable) -> None:
        route = WebSocketRoute(path, endpoint=endpoint)
        self.routes.append(route)

    def route(
        self,
        path: str,
        methods: typing.List[str] = None,
        include_in_schema: bool = True,
    ) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_route(
                path, func, methods=methods, include_in_schema=include_in_schema
            )
            return func

        return decorator

    def websocket_route(self, path: str) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_websocket_route(path, func)
            return func

        return decorator

    def not_found(self, scope: Scope) -> ASGIInstance:
        if scope["type"] == "websocket":
            return WebSocketClose()

        # If we're running inside a starlette application then raise an
        # exception, so that the configurable exception handler can deal with
        # returning the response. For plain ASGI apps, just return the response.
        if "app" in scope:
            raise HTTPException(status_code=404)
        return PlainTextResponse("Not Found", status_code=404)

    def url_path_for(self, name: str, **path_params: str) -> URLPath:
        for route in self.routes:
            try:
                return route.url_path_for(name, **path_params)
            except NoMatchFound as exc:
                pass
        raise NoMatchFound()

    def __call__(self, scope: Scope) -> ASGIInstance:
        assert scope["type"] in ("http", "websocket")

        if "router" not in scope:
            scope["router"] = self

        partial = None

        for route in self.routes:
            match, child_scope = route.matches(scope)
            if match == Match.FULL:
                return route(child_scope)
            elif match == Match.PARTIAL and partial is None:
                partial = route
                partial_scope = child_scope

        if partial is not None:
            return partial(partial_scope)

        if self.redirect_slashes and not scope["path"].endswith("/"):
            redirect_scope = dict(scope)
            redirect_scope["path"] += "/"

            for route in self.routes:
                match, child_scope = route.matches(redirect_scope)
                if match != Match.NONE:
                    redirect_url = URL(scope=redirect_scope)
                    return RedirectResponse(url=str(redirect_url))

        return self.default(scope)

    def __eq__(self, other: typing.Any) -> bool:
        return isinstance(other, Router) and self.routes == other.routes
