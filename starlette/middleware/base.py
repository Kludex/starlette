import asyncio
import functools
import typing

from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.types import ASGIApp, ASGIInstance, Receive, Scope, Send


class BaseHTTPMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] != "http":
            return self.app(scope)
        return functools.partial(self.asgi, scope=scope)

    async def asgi(self, receive: Receive, send: Send, scope: Scope) -> None:
        request = Request(scope, receive=receive)
        response = await self.dispatch(request, self.call_next)
        await response(receive, send)

    async def call_next(self, request: Request) -> ASGIInstance:
        inner = self.app(dict(request))
        loop = asyncio.get_event_loop()
        queue = asyncio.Queue()  # type: asyncio.Queue

        async def coro() -> None:
            try:
                await inner(request.receive, queue.put)
            finally:
                await queue.put(None)

        task = loop.create_task(coro())
        message = await queue.get()
        if message is None:
            task.result()
            raise RuntimeError("No response returned.")
        assert message["type"] == "http.response.start"

        async def body_stream() -> typing.AsyncGenerator[bytes, None]:
            while True:
                message = await queue.get()
                if message is None:
                    break
                assert message["type"] == "http.response.body"
                yield message["body"]
            task.result()

        response = StreamingResponse(
            status_code=message["status"], content=body_stream()
        )
        response.raw_headers = message["headers"]
        return response

    async def dispatch(
        self, request: Request, call_next: typing.Callable
    ) -> ASGIInstance:
        raise NotImplementedError()  # pragma: no cover
