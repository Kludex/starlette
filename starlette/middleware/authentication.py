import functools

from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    UnauthenticatedUser,
)
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, ASGIInstance, Receive, Scope, Send


class AuthenticationMiddleware:
    def __init__(self, app: ASGIApp, backend: AuthenticationBackend) -> None:
        self.app = app
        self.backend = backend

    def __call__(self, scope: Scope) -> ASGIInstance:
        return functools.partial(self.asgi, scope=scope)

    async def asgi(self, receive: Receive, send: Send, scope: Scope) -> None:
        request = Request(scope, receive=receive)
        try:
            auth_result = await self.backend.authenticate(request)
        except AuthenticationError as exc:
            response = PlainTextResponse(str(exc), status_code=400)
            await response(receive, send)
            return

        if auth_result is None:
            auth_result = AuthCredentials(), UnauthenticatedUser()
        scope["auth"], scope["user"] = auth_result
        inner = self.app(scope)
        await inner(receive, send)
