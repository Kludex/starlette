import asyncio
import functools
import traceback
import typing

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, PlainTextResponse, Response
from starlette.types import ASGIApp, ASGIInstance, Message, Receive, Scope, Send

STYLES = """
.traceback-container {
    border: 1px solid #038BB8;
}
.traceback-title {
    background-color: #038BB8;
    color: lemonchiffon;
    padding: 12px;
    font-size: 20px;
    margin-top: 0px;
}
.traceback-content {
    padding: 5px 0px 20px 20px;
}
.frame-line {
    font-weight: unset;
    padding: 10px 10px 10px 20px;
    background-color: #E4F4FD;
    margin-left: 10px;
    margin-right: 10px;
    font: #394D54;
    color: #191f21;
    font-size: 17px;
    border: 1px solid #c7dce8;
}
"""

TEMPLATE = """
<html>
    <head>
        <style type='text/css'>
            {styles}
        </style>
        <title>Starlette Debugger</title>
    </head>
    <body>
        <h1>500 Server Error</h1>
        <h2>{error}</h2>
        <div class='traceback-container'>
            <p class='traceback-title'>Traceback</p>
            <div class='traceback-content'>{exc_html}</div>
        </div>
    </body>
</html>
"""

FRAME_TEMPLATE = """
<div>
    File <span class='debug-filename'>`{frame_filename}`</span>,
    line <i>{frame_lineno}</i>,
    in <b>{frame_name}</b>
    <p class='frame-line'>{frame_line}</p>
</div>
"""


class ServerErrorMiddleware:
    """
    Handles returning 500 responses when a server error occurs.

    If 'debug' is set, then traceback responses will be returned,
    otherwise the designated 'handler' will be called.

    This middleware class should generally be used to wrap *everything*
    else up, so that unhandled exceptions anywhere in the stack
    always result in an appropriate 500 response.
    """

    def __init__(
        self, app: ASGIApp, handler: typing.Callable = None, debug: bool = False
    ) -> None:
        self.app = app
        self.handler = handler
        self.debug = debug

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] != "http":
            return self.app(scope)
        return functools.partial(self.asgi, scope=scope)

    async def asgi(self, receive: Receive, send: Send, scope: Scope) -> None:
        response_started = False

        async def _send(message: Message) -> None:
            nonlocal response_started, send

            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            asgi = self.app(scope)
            await asgi(receive, _send)
        except Exception as exc:
            if not response_started:
                request = Request(scope)
                if self.debug:
                    # In debug mode, return traceback responses.
                    response = self.debug_response(request, exc)
                elif self.handler is None:
                    # Use our default 500 error handler.
                    response = self.error_response(request, exc)
                else:
                    # Use an installed 500 error handler.
                    if asyncio.iscoroutinefunction(self.handler):
                        response = await self.handler(request, exc)
                    else:
                        response = await run_in_threadpool(self.handler, request, exc)

                await response(receive, send)

            # We always continue to raise the exception.
            # This allows servers to log the error, or allows test clients
            # to optionally raise the error within the test case.
            raise exc from None

    def genenrate_frame_html(self, frame: traceback.FrameSummary) -> str:
        values = {
            "frame_filename": frame.filename,
            "frame_lineno": frame.lineno,
            "frame_name": frame.name,
            "frame_line": frame.line,
        }
        return FRAME_TEMPLATE.format(**values)

    def generate_html(self, exc: Exception) -> str:
        traceback_obj = traceback.TracebackException.from_exception(
            exc, capture_locals=True
        )
        exc_html = "".join(
            self.genenrate_frame_html(frame) for frame in traceback_obj.stack
        )
        error = f"{traceback_obj.exc_type.__name__}: {traceback_obj}"

        return TEMPLATE.format(styles=STYLES, error=error, exc_html=exc_html)

    def generate_plain_text(self, exc: Exception) -> str:
        return "".join(traceback.format_tb(exc.__traceback__))

    def debug_response(self, request: Request, exc: Exception) -> Response:
        accept = request.headers.get("accept", "")

        if "text/html" in accept:
            content = self.generate_html(exc)
            return HTMLResponse(content, status_code=500)
        content = self.generate_plain_text(exc)
        return PlainTextResponse(content, status_code=500)

    def error_response(self, request: Request, exc: Exception) -> Response:
        return PlainTextResponse("Internal Server Error", status_code=500)
