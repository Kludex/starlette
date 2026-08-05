from __future__ import annotations

import zlib
from typing import NoReturn

import anyio

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_EXCLUDED_CONTENT_TYPES = ("text/event-stream",)

_gzip_capacity_limiter: anyio.lowlevel.RunVar[anyio.CapacityLimiter] = anyio.lowlevel.RunVar("_gzip_capacity_limiter")


def _get_gzip_capacity_limiter() -> anyio.CapacityLimiter:
    """Return the capacity limiter used for worker-thread GZip compression."""
    try:
        return _gzip_capacity_limiter.get()
    except LookupError:
        # Keep gzip compression isolated from AnyIO's default worker-thread
        # capacity limiter while matching its default concurrency.
        limiter = anyio.CapacityLimiter(40)
        _gzip_capacity_limiter.set(limiter)
        return limiter


class GZipMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        minimum_size: int = 500,
        compresslevel: int = 9,
        thread_minimum_size: int = 128 * 1024,  # 128 KiB
    ) -> None:
        self.app = app
        self.minimum_size = minimum_size
        self.compresslevel = compresslevel
        self.thread_minimum_size = thread_minimum_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        responder: ASGIApp
        if "gzip" in headers.get("Accept-Encoding", ""):
            responder = GZipResponder(
                self.app,
                self.minimum_size,
                compresslevel=self.compresslevel,
                thread_minimum_size=self.thread_minimum_size,
            )
        else:
            responder = IdentityResponder(self.app, self.minimum_size)

        await responder(scope, receive, send)


class IdentityResponder:
    content_encoding: str

    def __init__(self, app: ASGIApp, minimum_size: int) -> None:
        self.app = app
        self.minimum_size = minimum_size
        self.send: Send = unattached_send
        self.initial_message: Message = {}
        self.started = False
        self.content_encoding_set = False
        self.content_type_is_excluded = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.send = send
        await self.app(scope, receive, self.send_with_compression)

    async def send_with_compression(self, message: Message) -> None:
        message_type = message["type"]
        if message_type == "http.response.start":
            # Don't send the initial message until we've determined how to
            # modify the outgoing headers correctly.
            self.initial_message = message
            headers = Headers(raw=self.initial_message["headers"])
            self.content_encoding_set = "content-encoding" in headers
            self.content_type_is_excluded = headers.get("content-type", "").startswith(DEFAULT_EXCLUDED_CONTENT_TYPES)
        elif message_type == "http.response.body" and (self.content_encoding_set or self.content_type_is_excluded):
            if not self.started:
                self.started = True
                await self.send(self.initial_message)
            await self.send(message)
        elif message_type == "http.response.body" and not self.started:
            self.started = True
            body = message.get("body", b"")
            more_body = message.get("more_body", False)
            if len(body) < self.minimum_size and not more_body:
                # Don't apply compression to small outgoing responses.
                await self.send(self.initial_message)
                await self.send(message)
            elif not more_body:
                # Standard response.
                body = await self.apply_compression(body, more_body=False)

                headers = MutableHeaders(raw=self.initial_message["headers"])
                headers.add_vary_header("Accept-Encoding")
                if body != message["body"]:
                    headers["Content-Encoding"] = self.content_encoding
                    headers["Content-Length"] = str(len(body))
                    message["body"] = body

                await self.send(self.initial_message)
                await self.send(message)
            else:
                # Initial body in streaming response.
                body = await self.apply_compression(body, more_body=True)

                headers = MutableHeaders(raw=self.initial_message["headers"])
                headers.add_vary_header("Accept-Encoding")
                if body != message["body"]:
                    headers["Content-Encoding"] = self.content_encoding
                    del headers["Content-Length"]
                    message["body"] = body

                await self.send(self.initial_message)
                await self.send(message)
        elif message_type == "http.response.body":
            # Remaining body in streaming response.
            body = message.get("body", b"")
            more_body = message.get("more_body", False)

            message["body"] = await self.apply_compression(body, more_body=more_body)

            await self.send(message)
        elif message_type == "http.response.pathsend":  # pragma: no branch
            # Don't apply GZip to pathsend responses
            await self.send(self.initial_message)
            await self.send(message)

    async def apply_compression(self, body: bytes, *, more_body: bool) -> bytes:
        """Apply compression on the response body.

        If more_body is False, the compression stream is finalized. Compression
        resources are only allocated once a body is actually compressed.
        """
        return body


class GZipResponder(IdentityResponder):
    content_encoding = "gzip"

    def __init__(
        self,
        app: ASGIApp,
        minimum_size: int,
        compresslevel: int = 9,
        *,
        thread_minimum_size: int = 128 * 1024,  # 128 KiB
    ) -> None:
        super().__init__(app, minimum_size)

        self.compresslevel = compresslevel
        self.thread_minimum_size = thread_minimum_size
        self._compressor: zlib._Compress | None = None

    @property
    def compressor(self) -> zlib._Compress:
        if self._compressor is None:
            self._compressor = zlib.compressobj(self.compresslevel, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        return self._compressor

    async def apply_compression(self, body: bytes, *, more_body: bool) -> bytes:
        if len(body) >= self.thread_minimum_size:
            # Compressing large chunks inline would block the event loop.
            limiter = _get_gzip_capacity_limiter()
            return await anyio.to_thread.run_sync(self._compress_body, body, more_body, limiter=limiter)
        return self._compress_body(body, more_body)

    def _compress_body(self, body: bytes, more_body: bool) -> bytes:
        if more_body:
            return self.compressor.compress(body)
        return self.compressor.compress(body) + self.compressor.flush()


async def unattached_send(message: Message) -> NoReturn:
    raise RuntimeError("send awaitable not set")  # pragma: no cover
