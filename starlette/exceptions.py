from starlette.debug import get_debug_response
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
import asyncio
import http


class HTTPException(Exception):
    def __init__(self, status_code: int, detail: str = None) -> None:
        if detail is None:
            detail = http.HTTPStatus(status_code).phrase
        self.status_code = status_code
        self.detail = detail


class ExceptionMiddleware:
    def __init__(self, app, debug=False):
        self.app = app
        self.debug = debug
        self._exception_handlers = {
            Exception: self.server_error,
            HTTPException: self.http_exception,
        }

    def add_exception_handler(self, exc_class, handler):
        assert issubclass(exc_class, Exception)
        self._exception_handlers[exc_class] = handler

    def _lookup_exception_handler(self, exc):
        for cls in type(exc).__mro__:
            handler = self._exception_handlers.get(cls)
            if handler is not None:
                return handler, cls

    def __call__(self, scope):
        if scope["type"] != "http":
            return self.app(scope)

        async def app(receive, send):
            response_started = False

            async def sender(message):
                nonlocal response_started

                if message["type"] == "http.response.start":
                    response_started = True
                await send(message)

            try:
                try:
                    instance = self.app(scope)
                    await instance(receive, sender)
                except BaseException as exc:
                    # Exception handling is applied to any registed exception
                    # class or subclass that occurs within the application.
                    handler, cls = self._lookup_exception_handler(exc)

                    # Note that we always handle `Exception` in the outermost block.
                    if cls is Exception:
                        raise exc from None

                    if response_started:
                        msg = "Caught handled exception, but response already started."
                        raise RuntimeError(msg) from exc

                    request = Request(scope, receive=receive)
                    if asyncio.iscoroutinefunction(handler):
                        response = await handler(request, exc)
                    else:
                        response = handler(request, exc)
                    await response(receive, sender)

            except Exception as exc:
                # The 'Exception' case always wraps everything else, and
                # provides a last-ditch handler for dealing with server errors.
                request = Request(scope, receive=receive)
                if self.debug:
                    handler = get_debug_response
                else:
                    handler = self._exception_handlers[Exception]
                if asyncio.iscoroutinefunction(handler):
                    response = await handler(request, exc)
                else:
                    response = handler(request, exc)
                if not response_started:
                    await response(receive, send)

                # We always raise the exception up to the server so that it
                # is notified too. Typically this will mean that it'll log
                # the exception.
                raise

        return app

    def http_exception(self, request: Request, exc: type) -> Response:
        if exc.status_code in {204, 304}:
            return Response(b"", status_code=exc.status_code)
        return PlainTextResponse(exc.detail, status_code=exc.status_code)

    def server_error(self, request: Request, exc: type) -> Response:
        return PlainTextResponse("Internal Server Error", status_code=500)
