import typing

import anyio

from starlette.requests import Request
from starlette.responses import Response, StreamingResponse
from starlette.types import ASGIApp, Receive, Scope, Send

RequestResponseEndpoint = typing.Callable[[Request], typing.Awaitable[Response]]
DispatchFunction = typing.Callable[
    [Request, RequestResponseEndpoint], typing.Awaitable[Response]
]


class BaseHTTPMiddleware:
    def __init__(
        self, app: ASGIApp, dispatch: typing.Optional[DispatchFunction] = None
    ) -> None:
        self.app = app
        self.dispatch_func = self.dispatch if dispatch is None else dispatch

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def call_next(request: Request) -> Response:
            app_exc: typing.Optional[Exception] = None
            send_stream, recv_stream = anyio.create_memory_object_stream()

            async def coro() -> None:
                nonlocal app_exc

                async with send_stream:
                    try:
                        await self.app(scope, request.receive, send_stream.send)
                    except Exception as exc:
                        app_exc = exc

            task_group.start_soon(coro)

            try:
                message = await recv_stream.receive()
            except anyio.EndOfStream:
                if app_exc is not None:
                    raise app_exc
                raise RuntimeError("No response returned.")

            assert message["type"] == "http.response.start"

            async def body_stream() -> typing.AsyncGenerator[bytes, None]:
                async with recv_stream:
                    async for message in recv_stream:
                        assert message["type"] == "http.response.body"
                        yield message.get("body", b"")

                if app_exc is not None:
                    raise app_exc

            response = StreamingResponse(
                status_code=message["status"], content=body_stream()
            )
            response.raw_headers = message["headers"]
            return response

        async with anyio.create_task_group() as task_group:
            request = Request(scope, receive=receive)
            response = await self.dispatch_func(request, call_next)
            await response(scope, receive, send)
            task_group.cancel_scope.cancel()

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        raise NotImplementedError()  # pragma: no cover
