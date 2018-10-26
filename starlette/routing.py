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


def request_response(func: typing.Callable) -> ASGIApp:
    """
    Takes a function or coroutine `func(request, **kwargs) -> response`,
    and returns an ASGI application.
    """
    is_coroutine = asyncio.iscoroutinefunction(func)

    def app(scope: Scope) -> ASGIInstance:
        async def awaitable(receive: Receive, send: Send) -> None:
            request = Request(scope, receive=receive)
            kwargs = scope.get("kwargs", {})
            if is_coroutine:
                response = await func(request, **kwargs)
            else:
                response = func(request, **kwargs)
            await response(receive, send)

        return awaitable

    return app


def websocket_session(func: typing.Callable) -> ASGIApp:
    """
    Takes a coroutine `func(session, **kwargs)`, and returns an ASGI application.
    """

    def app(scope: Scope) -> ASGIInstance:
        async def awaitable(receive: Receive, send: Send) -> None:
            session = WebSocket(scope, receive=receive, send=send)
            kwargs = scope.get("kwargs", {})
            await func(session, **kwargs)

        return awaitable

    return app


class Route:
    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
        raise NotImplementedError()  # pragma: no cover

    def __call__(self, scope: Scope) -> ASGIInstance:
        raise NotImplementedError()  # pragma: no cover


class Path(Route):
    def __init__(
        self,
        path: str,
        app: ASGIApp,
        methods: typing.Sequence[str] = None,
        protocol: str = None,
    ) -> None:
        self.path = path
        self.app = app
        self.protocol = protocol
        self.methods = methods
        regex = "^" + path + "$"
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]+)", regex)
        self.path_regex = re.compile(regex)

    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
        if self.protocol is None or scope["type"] == self.protocol:
            match = self.path_regex.match(scope["path"])
            if match:
                kwargs = dict(scope.get("kwargs", {}))
                kwargs.update(match.groupdict())
                child_scope = dict(scope)
                child_scope["kwargs"] = kwargs
                return True, child_scope
        return False, {}

    def __call__(self, scope: Scope) -> ASGIInstance:
        if self.methods and scope["method"] not in self.methods:
            if "app" in scope:
                raise HTTPException(status_code=405)
            return PlainTextResponse("Method Not Allowed", status_code=405)
        return self.app(scope)


class PathPrefix(Route):
    def __init__(
        self, path: str, app: ASGIApp, methods: typing.Sequence[str] = None
    ) -> None:
        self.path = path
        self.app = app
        self.methods = methods
        regex = "^" + path
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]*)", regex)
        self.path_regex = re.compile(regex)

    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
        match = self.path_regex.match(scope["path"])
        if match:
            kwargs = dict(scope.get("kwargs", {}))
            kwargs.update(match.groupdict())
            child_scope = dict(scope)
            child_scope["kwargs"] = kwargs
            child_scope["root_path"] = scope.get("root_path", "") + match.string
            child_scope["path"] = scope["path"][match.span()[1] :]
            return True, child_scope
        return False, {}

    def __call__(self, scope: Scope) -> ASGIInstance:
        if self.methods and scope["method"] not in self.methods:
            if "app" in scope:
                raise HTTPException(status_code=405)
            return PlainTextResponse("Method Not Allowed", status_code=405)
        return self.app(scope)


class Router:
    def __init__(
        self, routes: typing.List[Route] = None, default: ASGIApp = None
    ) -> None:
        self.routes = [] if routes is None else routes
        self.default = self.not_found if default is None else default
        self.executor = ThreadPoolExecutor()

    def mount(
        self, path: str, app: ASGIApp, methods: typing.Sequence[str] = None
    ) -> None:
        prefix = PathPrefix(path, app=app, methods=methods)
        self.routes.append(prefix)

    def add_route(
        self, path: str, route: typing.Callable, methods: typing.Sequence[str] = None
    ) -> None:
        if not inspect.isclass(route):
            route = request_response(route)
            if methods is None:
                methods = ("GET",)

        instance = Path(path, route, protocol="http", methods=methods)
        self.routes.append(instance)

    def add_graphql_route(
        self, path: str, schema: typing.Any, executor: typing.Any = None
    ) -> None:
        route = GraphQLApp(schema=schema, executor=executor)
        self.add_route(path, route, methods=["GET", "POST"])

    def add_websocket_route(self, path: str, route: typing.Callable) -> None:
        if not inspect.isclass(route):
            route = websocket_session(route)

        instance = Path(path, route, protocol="websocket")
        self.routes.append(instance)

    def route(self, path: str, methods: typing.Sequence[str] = None) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_route(path, func, methods=methods)
            return func

        return decorator

    def websocket_route(self, path: str) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_websocket_route(path, func)
            return func

        return decorator

    def __call__(self, scope: Scope) -> ASGIInstance:
        assert scope["type"] in ("http", "websocket")
        scope["executor"] = self.executor

        for route in self.routes:
            matched, child_scope = route.matches(scope)
            if matched:
                return route(child_scope)
        return self.not_found(scope)

    def not_found(self, scope: Scope) -> ASGIInstance:
        if scope["type"] == "websocket":
            return WebSocketClose()

        # If we're running inside a starlette application then raise an
        # exception, so that the configurable exception handler can deal with
        # returning the response. For plain ASGI apps, just return the response.
        if "app" in scope:
            raise HTTPException(status_code=404)
        return PlainTextResponse("Not Found", status_code=404)


class ProtocolRouter:
    def __init__(self, protocols: typing.Dict[str, ASGIApp]) -> None:
        self.protocols = protocols

    def __call__(self, scope: Scope) -> ASGIInstance:
        app = self.protocols[scope["type"]]
        return app(scope)
