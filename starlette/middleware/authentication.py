import functools
import typing

from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    UnauthenticatedUser,
)
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, ASGIInstance, Receive, Scope, Send


class AuthenticationMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        backend: AuthenticationBackend,
        on_error: typing.Callable[[Request, AuthenticationError], Response] = None,
    ) -> None:
        self.app = app
        self.backend = backend
        self.on_error = (
            on_error if on_error is not None else self.default_on_error
        )  # type: typing.Callable[[Request, AuthenticationError], Response]

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] in ["http", "websockets"]:
            return functools.partial(self.asgi, scope=scope)
        return self.app(scope)

    async def asgi(self, receive: Receive, send: Send, scope: Scope) -> None:
        request = Request(scope, receive=receive)
        try:
            auth_result = await self.backend.authenticate(request)
        except AuthenticationError as exc:
            response = self.on_error(request, exc)
            await response(receive, send)
            return

        if auth_result is None:
            auth_result = AuthCredentials(), UnauthenticatedUser()
        scope["auth"], scope["user"] = auth_result
        inner = self.app(scope)
        await inner(receive, send)

    @staticmethod
    def default_on_error(request: Request, exc: Exception) -> Response:
        return PlainTextResponse(str(exc), status_code=400)
