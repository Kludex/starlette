import html
import traceback
import typing

from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.types import Scope, Receive, Send, Message, ASGIApp, ASGIInstance


def get_debug_response(request: Request, exc: Exception) -> Response:
    accept = request.headers.get("accept", "")
    if "text/html" in accept:
        exc_html = "".join(traceback.format_tb(exc.__traceback__))
        exc_html = html.escape(exc_html)
        content = (
            f"<html><body><h1>500 Server Error</h1><pre>{exc_html}</pre></body></html>"
        )
        return HTMLResponse(content, status_code=500)
    content = "".join(traceback.format_tb(exc.__traceback__))
    return PlainTextResponse(content, status_code=500)


class DebugMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] != "http":
            return self.app(scope)
        return _DebugResponder(self.app, scope)


class _DebugResponder:
    def __init__(self, app: ASGIApp, scope: Scope) -> None:
        self.app = app
        self.scope = scope
        self.response_started = False

    async def __call__(self, receive: Receive, send: Send) -> None:
        self.raw_send = send
        try:
            asgi = self.app(self.scope)
            await asgi(receive, self.send)
        except Exception as exc:
            if not self.response_started:
                request = Request(self.scope)
                response = get_debug_response(request, exc)
                await response(receive, send)
            raise exc from None

    async def send(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.response_started = True
        await self.raw_send(message)
