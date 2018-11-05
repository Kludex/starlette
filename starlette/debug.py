import traceback

from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.types import ASGIApp, ASGIInstance, Message, Receive, Scope, Send

STYLES = """\
    .traceback-container {border: 1px solid #038BB8;}
    .traceback-title {background-color: #038BB8;color: lemonchiffon;padding: 12px;font-size: 20px;margin-top: 0px;}
    .traceback-content {padding: 5px 0px 20px 20px;}
    .frame-line {font-weight: unset;padding: 10px 10px 10px 20px;background-color: #E4F4FD;
    margin-left: 10px;margin-right: 10px;font: #394D54;color: #191f21;font-size: 17px;border: 1px solid #c7dce8;}
"""

TEMPLATE = """
    <style type='text/css'>{style}</style>
    <title>Starlette Debugger</title>
    <h1>500 Server Error</h1>
    <h2>{error}</h2>
    <div class='traceback-container'>
    <p class='traceback-title'>Traceback</p>
    <div class='traceback-content'>{ext_html}</div>
    </div>
"""

FRAME_TEMPLATE = """
    <p>
    File <span class='debug-filename'>`{frame_filename}`</span>,
    line <i>{frame_lineno}</i>,
    in <b>{frame_name}</b>
    <p class='frame-line'>{frame_line}</p>
    </p>
"""


class DebugGenerator:
    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.traceback_obj = traceback.TracebackException.from_exception(
            exc, capture_locals=True
        )
        self.error = f"{self.traceback_obj.exc_type.__name__}: {self.traceback_obj}"

    @staticmethod
    def gen_frame_html(frame: traceback.FrameSummary) -> str:
        values = {
            "frame_filename": frame.filename,
            "frame_lineno": frame.lineno,
            "frame_name": frame.name,
            "frame_line": frame.line,
        }
        return FRAME_TEMPLATE.format(**values)

    def generate_html(self) -> str:
        ext_html = "".join(
            [self.gen_frame_html(frame) for frame in self.traceback_obj.stack]
        )
        values = {"style": STYLES, "error": self.error, "ext_html": ext_html}

        return TEMPLATE.format(**values)

    def generate_plain_text(self) -> str:
        return "".join(traceback.format_tb(self.exc.__traceback__))


def get_debug_response(request: Request, exc: Exception) -> Response:
    accept = request.headers.get("accept", "")
    debug_gen = DebugGenerator(exc)

    if "text/html" in accept:
        content = debug_gen.generate_html()
        return HTMLResponse(content, status_code=500)
    content = debug_gen.generate_plain_text()
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
