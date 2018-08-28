from starlette.request import Request
from starlette.routing import Path, PathPrefix, Router
from starlette.types import ASGIApp, ASGIInstance, Receive, Scope, Send
from starlette.websockets import WebSocketSession
import asyncio


def request_response(func):
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


def websocket_session(func):
    """
    Takes a coroutine `func(session, **kwargs)`, and returns an ASGI application.
    """

    def app(scope: Scope) -> ASGIInstance:
        async def awaitable(receive: Receive, send: Send) -> None:
            session = WebSocketSession(scope, receive=receive, send=send)
            kwargs = scope.get("kwargs", {})
            await func(session, **kwargs)

        return awaitable

    return app


class App:
    def __init__(self) -> None:
        self.router = Router(routes=[])

    def mount(self, path: str, app: ASGIApp):
        prefix = PathPrefix(path, app=app)
        self.router.routes.append(prefix)

    def add_route(self, path: str, route, methods=None) -> None:
        if methods is None:
            methods = ["GET"]
        instance = Path(path, request_response(route), protocol="http", methods=methods)
        self.router.routes.append(instance)

    def add_websocket_route(self, path: str, route) -> None:
        instance = Path(path, websocket_session(route), protocol="websocket")
        self.router.routes.append(instance)

    def route(self, path: str):
        def decorator(func):
            self.add_route(path, func)

        return decorator

    def websocket_route(self, path: str):
        def decorator(func):
            self.add_websocket_route(path, func)

        return decorator

    def __call__(self, scope: Scope) -> ASGIInstance:
        return self.router(scope)
