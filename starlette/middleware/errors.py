from __future__ import annotations

import io
from typing import Any

import tracerite  # type: ignore[import-untyped]
from html5tagger import Document  # type: ignore[import-untyped]
from tracerite.html import html_traceback  # type: ignore[import-untyped]
from tracerite.trace import build_chain_header  # type: ignore[import-untyped]
from tracerite.tty import tty_traceback  # type: ignore[import-untyped]

from starlette._utils import is_async_callable
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.types import ASGIApp, ExceptionHandler, Message, Receive, Scope, Send


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
        self,
        app: ASGIApp,
        handler: ExceptionHandler | None = None,
        debug: bool = False,
        json: bool = False,
    ) -> None:
        self.app = app
        self.handler = handler
        self.debug = debug
        self.json = json

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def _send(message: Message) -> None:
            nonlocal response_started, send

            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, _send)
        except Exception as exc:
            request = Request(scope)
            if self.debug:
                # In debug mode, return traceback responses.
                response = self.debug_response(request, exc)
            elif self.handler is None:
                # Use our default 500 error handler.
                response = self.error_response(request, exc)
            else:
                # Use an installed 500 error handler.
                if is_async_callable(self.handler):
                    response = await self.handler(request, exc)  # type: ignore[assignment, arg-type]
                else:
                    response = await run_in_threadpool(self.handler, request, exc)  # type: ignore[arg-type]

            if not response_started:
                await response(scope, receive, send)

            # We always continue to raise the exception.
            # This allows servers to log the error, or allows test clients
            # to optionally raise the error within the test case.
            raise exc

    def generate_html(
        self,
        exc: Exception,
        limit: int = 7,
        request: Request | None = None,
    ) -> str:
        """
        Render an HTML traceback page for the given exception.

        The ``limit`` parameter is retained for backwards compatibility but is
        no longer honoured; TraceRite renders the full traceback.
        """
        del limit  # TraceRite does not support frame limiting.
        chain = tracerite.extract_chain(exc)
        summary = build_chain_header(chain)
        doc = Document(summary, lang="en")
        font_stack = (
            "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', "
            "Roboto, 'Helvetica Neue', Arial, sans-serif"
        )
        doc.style(
            "body {"
            f"    font-family: {font_stack};"
            "    line-height: 1.4;"
            "    margin: 1.5rem;"
            "}"
        )
        doc.h1("500 Server Error")
        doc.p(
            "This page is shown for your guidance because the application is "
            "running in debug mode and has crashed handling this request."
        )
        doc(html_traceback(exc=exc, chain=chain, include_js_css=True))
        return str(doc)

    def generate_plain_text(self, exc: Exception) -> str:
        """Render a plain-text traceback for the given exception."""
        buffer = io.StringIO()
        tty_traceback(exc, file=buffer)
        return buffer.getvalue()

    def generate_json(self, exc: Exception) -> dict[str, Any]:
        """Render a structured JSON traceback for the given exception."""
        chain = tracerite.extract_chain(exc)
        return {
            "detail": build_chain_header(chain),
            "traceback": chain,
        }

    def debug_response(self, request: Request, exc: Exception) -> Response:
        accept = request.headers.get("accept", "")

        if "text/html" in accept:
            content = self.generate_html(exc, request=request)
            return HTMLResponse(content, status_code=500)
        if self.json and "application/json" in accept:
            return JSONResponse(self.generate_json(exc), status_code=500)
        content = self.generate_plain_text(exc)
        return PlainTextResponse(content, status_code=500)

    def error_response(self, request: Request, exc: Exception) -> Response:
        return PlainTextResponse("Internal Server Error", status_code=500)
