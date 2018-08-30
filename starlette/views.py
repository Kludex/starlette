from starlette.request import Request
from starlette.response import Response, PlainTextResponse
from starlette.types import Receive, Send, Scope


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
        return await handler(request, **kwargs)

    async def method_not_allowed(self, request: Request, **kwargs) -> Response:
        return PlainTextResponse("Method not allowed", 406)
