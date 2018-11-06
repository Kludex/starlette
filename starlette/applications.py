import typing

from starlette.datastructures import URL, URLPath
from starlette.exceptions import ExceptionMiddleware
from starlette.lifespan import LifespanHandler
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import BaseRoute, Router
from starlette.schemas import BaseSchemaGenerator
from starlette.types import ASGIApp, ASGIInstance, Scope


class Starlette:
    def __init__(self, debug: bool = False) -> None:
        self.router = Router()
        self.lifespan_handler = LifespanHandler()
        self.app = self.router
        self.exception_middleware = ExceptionMiddleware(self.router, debug=debug)
        self.schema_generator = None  # type: typing.Optional[BaseSchemaGenerator]

    @property
    def routes(self) -> typing.List[BaseRoute]:
        return self.router.routes

    @property
    def debug(self) -> bool:
        return self.exception_middleware.debug

    @debug.setter
    def debug(self, value: bool) -> None:
        self.exception_middleware.debug = value

    @property
    def schema(self) -> dict:
        assert self.schema_generator is not None
        return self.schema_generator.get_schema(self.routes)

    def on_event(self, event_type: str) -> typing.Callable:
        return self.lifespan_handler.on_event(event_type)

    def mount(self, path: str, app: ASGIApp, name: str = None) -> None:
        self.router.mount(path, app=app, name=name)

    def add_middleware(self, middleware_class: type, **kwargs: typing.Any) -> None:
        self.exception_middleware.app = middleware_class(self.app, **kwargs)

    def add_exception_handler(self, exc_class: type, handler: typing.Callable) -> None:
        self.exception_middleware.add_exception_handler(exc_class, handler)

    def add_event_handler(self, event_type: str, func: typing.Callable) -> None:
        self.lifespan_handler.add_event_handler(event_type, func)

    def add_route(
        self,
        path: str,
        route: typing.Callable,
        methods: typing.List[str] = None,
        include_in_schema: bool = True,
    ) -> None:
        self.router.add_route(path, route, methods=methods)

    def add_websocket_route(self, path: str, route: typing.Callable) -> None:
        self.router.add_websocket_route(path, route)

    def exception_handler(self, exc_class: type) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_exception_handler(exc_class, func)
            return func

        return decorator

    def route(
        self,
        path: str,
        methods: typing.List[str] = None,
        include_in_schema: bool = True,
    ) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.router.add_route(
                path, func, methods=methods, include_in_schema=include_in_schema
            )
            return func

        return decorator

    def websocket_route(self, path: str) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.router.add_websocket_route(path, func)
            return func

        return decorator

    def middleware(self, middleware_type: str) -> typing.Callable:
        assert (
            middleware_type == "http"
        ), 'Currently only middleware("http") is supported.'

        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_middleware(BaseHTTPMiddleware, dispatch=func)
            return func

        return decorator

    def url_path_for(self, name: str, **path_params: str) -> URLPath:
        return self.router.url_path_for(name, **path_params)

    def __call__(self, scope: Scope) -> ASGIInstance:
        scope["app"] = self
        if scope["type"] == "lifespan":
            return self.lifespan_handler(scope)
        return self.exception_middleware(scope)
