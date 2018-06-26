from starlette.request import Request
from starlette.response import Response
from starlette.types import ASGIInstance, Receive, Send, Scope


def asgi_application(func):
    def app(scope: Scope) -> ASGIInstance:
        async def awaitable(receive: Receive, send: Send) -> None:
            request = Request(scope, receive)
            response = func(request)
            await response(receive, send)

        return awaitable

    return app
