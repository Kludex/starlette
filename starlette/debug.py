from starlette.datastructures import Headers
from starlette.response import HTMLResponse, PlainTextResponse
import html
import traceback


class DebugMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, scope):
        return _DebugResponder(self.app, scope)


class _DebugResponder:
    def __init__(self, app, scope):
        self.scope = scope
        self.asgi_instance = app(scope)
        self.response_started = False

    async def __call__(self, receive, send):
        self.raw_send = send
        try:
            await self.asgi_instance(receive, self.send)
        except:
            if self.response_started:
                raise
            headers = Headers(self.scope.get("headers", []))
            accept = headers.get("accept", "")
            if "text/html" in accept:
                exc_html = html.escape(traceback.format_exc())
                content = f"<html><body><h1>500 Server Error</h1><pre>{exc_html}</pre></body></html>"
                response = HTMLResponse(content, status_code=500)
            else:
                content = traceback.format_exc()
                response = PlainTextResponse(content, status_code=500)
            await response(receive, send)

    async def send(self, message):
        if message["type"] == "http.response.start":
            self.response_started = True
        await self.raw_send(message)
