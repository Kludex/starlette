from starlette import Response
from starlette.types import Scope, ASGIApp, ASGIInstance
import re
import typing


class Route:
    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
        raise NotImplementedError()  # pragma: no cover

    def __call__(self, scope: Scope) -> ASGIInstance:
        raise NotImplementedError()  # pragma: no cover


class Path(Route):
    def __init__(
        self, path: str, app: ASGIApp, methods: typing.Sequence[str] = ()
    ) -> None:
        self.path = path
        self.app = app
        self.methods = methods
        regex = "^" + path + "$"
        regex = re.sub("{([a-zA-Z_][a-zA-Z0-9_]*)}", r"(?P<\1>[^/]+)", regex)
        self.path_regex = re.compile(regex)

    def matches(self, scope: Scope) -> typing.Tuple[bool, Scope]:
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
            return Response("Method not allowed", 406, media_type="text/plain")
        return self.app(scope)


class PathPrefix(Route):
    def __init__(
        self, path: str, app: ASGIApp, methods: typing.Sequence[str] = ()
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
            return Response("Method not allowed", 406, media_type="text/plain")
        return self.app(scope)


class Router:
    def __init__(self, routes: typing.List[Route], default: ASGIApp = None) -> None:
        self.routes = routes
        self.default = self.not_found if default is None else default

    def __call__(self, scope: Scope) -> ASGIInstance:
        for route in self.routes:
            matched, child_scope = route.matches(scope)
            if matched:
                return route(child_scope)
        return self.not_found(scope)

    def not_found(self, scope: Scope) -> ASGIInstance:
        return Response("Not found", 404, media_type="text/plain")
