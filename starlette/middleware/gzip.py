from __future__ import annotations

import functools

import anyio.to_thread

from starlette.datastructures import Headers
from starlette.middleware._compression import GZipCompressor, capacity_limiter
from starlette.middleware._compression_response import CompressionResponder
from starlette.types import ASGIApp, Receive, Scope, Send

# TODO(v2): We should rename `DEFAULT_EXCLUDED_CONTENT_TYPES` to `DEFAULT_EXCLUDE_CONTENT_TYPES`.
DEFAULT_EXCLUDED_CONTENT_TYPES = (
    "application/grpc",
    "application/gzip",
    "application/x-gzip",
    "application/zip",
    "audio/*",
    "font/woff",
    "font/woff2",
    "image/avif",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
    "text/event-stream",
    "video/*",
)


class GZipMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        minimum_size: int = 500,
        compresslevel: int = 9,
        thread_minimum_size: int = 128 * 1024,  # 128 KiB
        *,
        exclude_content_types: tuple[str, ...] = DEFAULT_EXCLUDED_CONTENT_TYPES,
    ) -> None:
        self.app = app
        self.minimum_size = minimum_size
        self.compresslevel = compresslevel
        self.thread_minimum_size = thread_minimum_size
        self.exclude_content_types = _normalize_content_types(exclude_content_types)

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
                exclude_content_types=self.exclude_content_types,
            )
        else:
            responder = CompressionResponder(self.app, self.minimum_size, self.exclude_content_types)

        await responder(scope, receive, send)


class GZipResponder:
    def __init__(
        self,
        app: ASGIApp,
        minimum_size: int,
        compresslevel: int = 9,
        *,
        thread_minimum_size: int = 128 * 1024,  # 128 KiB
        exclude_content_types: tuple[str, ...] = DEFAULT_EXCLUDED_CONTENT_TYPES,
    ) -> None:
        self.app = app
        self.minimum_size = minimum_size
        self.exclude_content_types = _normalize_content_types(exclude_content_types)
        self.compresslevel = compresslevel
        self.thread_minimum_size = thread_minimum_size
        self._compressor: GZipCompressor | None = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def compress(body: bytes, more_body: bool) -> bytes:
            return await self.apply_compression(body, more_body=more_body)

        responder = CompressionResponder(
            self.app,
            self.minimum_size,
            self.exclude_content_types,
            encoding="gzip",
            compress=compress,
        )
        await responder(scope, receive, send)

    async def apply_compression(self, body: bytes, *, more_body: bool) -> bytes:
        if len(body) >= self.thread_minimum_size:
            # Compressing large chunks inline would block the event loop.
            return await anyio.to_thread.run_sync(self._compress_body, body, more_body, limiter=capacity_limiter())
        return self._compress_body(body, more_body)

    def _compress_body(self, body: bytes, more_body: bool) -> bytes:
        if self._compressor is None:
            self._compressor = GZipCompressor(self.compresslevel)
        return self._compressor(body, more_body)


@functools.lru_cache(maxsize=32)
def _normalize_content_types(content_types: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(content_type.partition(";")[0].strip().lower() for content_type in content_types)
