import re
import typing
import inspect
import asyncio
from concurrent.futures import ThreadPoolExecutor

from starlette.requests import Request
from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse
from starlette.types import Scope, ASGIApp, ASGIInstance, Send, Receive
from starlette.websockets import WebSocket, WebSocketClose
from starlette.graphql import GraphQLApp


class NoMatchFound(Exception):
    pass


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
                response = func(request)
            await response(receive, send)

        return awaitable

    return app


def websocket_session(func: typing.Callable) -> ASGIApp:
    """
    Takes a coroutine `func(session)`, and returns an ASGI application.
    """

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


def replace_params(path: str, **path_params: str) -> str:
    for key, value in path_params.items():
        path = path.replace("{" + key + "}", value)
    return path


class BaseRoute:
    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
        raise NotImplementedError()  # pragma: no cover

    def url_for(self, name: str, **path_params: str) -> str:
        raise NotImplementedError()  # pragma: no cover

    def __call__(self, scope: Scope) -> ASGIInstance:
        raise NotImplementedError()  # pragma: no cover


class Route(BaseRoute):
    def __init__(
        self, path: str, *, endpoint: typing.Callable, methods: typing.List[str] = None
    ) -> None:
        self.path = path
        self.endpoint = endpoint
        self.name = get_name(endpoint)

        if inspect.isfunction(endpoint):
            self.app = request_response(endpoint)
            if methods is None:
                methods = ["GET"]
        else:
            self.app = endpoint

        self.methods = methods
        regex = "^" + path + "$"
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]+)", regex)
        self.path_regex = re.compile(regex)
        self.param_names = set(self.path_regex.groupindex.keys())

    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
        if scope["type"] == "http":
            match = self.path_regex.match(scope["path"])
            if match:
                path_params = dict(scope.get("path_params", {}))
                path_params.update(match.groupdict())
                child_scope = dict(scope)
                child_scope["path_params"] = path_params
                return True, child_scope
        return False, {}

    def url_for(self, name: str, **path_params: str) -> str:
        if name != self.name or self.param_names != set(path_params.keys()):
            raise NoMatchFound()
        return replace_params(self.path, **path_params)

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
    def __init__(self, path: str, *, endpoint: typing.Callable) -> None:
        self.path = path
        self.endpoint = endpoint
        self.name = get_name(endpoint)

        if inspect.isfunction(endpoint):
            self.app = websocket_session(endpoint)
        else:
            self.app = endpoint

        regex = "^" + path + "$"
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]+)", regex)
        self.path_regex = re.compile(regex)
        self.param_names = set(self.path_regex.groupindex.keys())

    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
        if scope["type"] == "websocket":
            match = self.path_regex.match(scope["path"])
            if match:
                path_params = dict(scope.get("path_params", {}))
                path_params.update(match.groupdict())
                child_scope = dict(scope)
                child_scope["path_params"] = path_params
                return True, child_scope
        return False, {}

    def url_for(self, name: str, **path_params: str) -> str:
        if name != self.name or self.param_names != set(path_params.keys()):
            raise NoMatchFound()
        return replace_params(self.path, **path_params)

    def __call__(self, scope: Scope) -> ASGIInstance:
        return self.app(scope)

    def __eq__(self, other: typing.Any) -> bool:
        return (
            isinstance(other, WebSocketRoute)
            and self.path == other.path
            and self.endpoint == other.endpoint
        )


class Mount(BaseRoute):
    def __init__(self, path: str, app: ASGIApp) -> None:
        self.path = path
        self.app = app
        regex = "^" + path
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]*)", regex)
        self.path_regex = re.compile(regex)

    @property
    def routes(self) -> typing.List[BaseRoute]:
        return getattr(self.app, "routes", None)

    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
        match = self.path_regex.match(scope["path"])
        if match:
            path_params = dict(scope.get("path_params", {}))
            path_params.update(match.groupdict())
            child_scope = dict(scope)
            child_scope["path_params"] = path_params
            child_scope["root_path"] = scope.get("root_path", "") + match.string
            child_scope["path"] = scope["path"][match.span()[1] :]
            return True, child_scope
        return False, {}

    def url_for(self, name: str, **path_params: str) -> str:
        for route in self.routes or []:
            try:
                return self.path + route.url_for(name, **path_params)
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
        self, routes: typing.List[BaseRoute] = None, default: ASGIApp = None
    ) -> None:
        self.routes = [] if routes is None else routes
        self.default = self.not_found if default is None else default

    def mount(self, path: str, app: ASGIApp) -> None:
        route = Mount(path, app=app)
        self.routes.append(route)

    def add_route(
        self, path: str, endpoint: typing.Callable, methods: typing.List[str] = None
    ) -> None:
        route = Route(path, endpoint=endpoint, methods=methods)
        self.routes.append(route)

    def add_graphql_route(
        self, path: str, schema: typing.Any, executor: typing.Any = None
    ) -> None:
        app = GraphQLApp(schema=schema, executor=executor)
        self.add_route(path, endpoint=app)

    def add_websocket_route(self, path: str, endpoint: typing.Callable) -> None:
        route = WebSocketRoute(path, endpoint=endpoint)
        self.routes.append(route)

    def route(self, path: str, methods: typing.List[str] = None) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_route(path, func, methods=methods)
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

    def url_for(self, name: str, **path_params: str) -> str:
        for route in self.routes:
            try:
                return route.url_for(name, **path_params)
            except NoMatchFound as exc:
                pass
        raise NoMatchFound()

    def __call__(self, scope: Scope) -> ASGIInstance:
        assert scope["type"] in ("http", "websocket")

        for route in self.routes:
            matched, child_scope = route.matches(scope)
            if matched:
                return route(child_scope)
        return self.not_found(scope)

    def __eq__(self, other: typing.Any) -> bool:
        return isinstance(other, Router) and self.routes == other.routes
