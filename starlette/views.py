from starlette.exceptions import HTTPException
from starlette.request import Request
from starlette.response import Response, PlainTextResponse
from starlette.types import Receive, Send, Scope
import asyncio


class View:
    def __init__(self, scope: Scope):
        self.scope = scope

    async def __call__(self, receive: Receive, send: Send):
        request = Request(self.scope, receive=receive)
        kwargs = self.scope.get("kwargs", {})
        response = await self.dispatch(request, **kwargs)
        await response(receive, send)

    async def dispatch(self, request: Request, **kwargs) -> Response:
        handler_name = "get" if request.method == "HEAD" else request.method.lower()
        handler = getattr(self, handler_name, self.method_not_allowed)
        if asyncio.iscoroutinefunction(handler):
            response = await handler(request, **kwargs)
        else:
            response = handler(request, **kwargs)
        return response

    async def method_not_allowed(self, request: Request, **kwargs) -> Response:
        # If we're running inside a starlette application then raise an
        # exception, so that the configurable exception handler can deal with
        # returning the response. For plain ASGI apps, just return the response.
        if "app" in self.scope:
            raise HTTPException(status_code=405)
        return PlainTextResponse("Method Not Allowed", status_code=405)
