from __future__ import annotations

import re
from typing import NoReturn

import anyio
from brotli import MODE_FONT, MODE_GENERIC, MODE_TEXT, Compressor  # type: ignore[import-untyped]

from starlette.datastructures import Headers, MutableHeaders  # noqa: F401  (re-exported for parity with gzip.py)
from starlette.middleware.gzip import (
    GZipResponder,
    IdentityResponder,
    _get_gzip_capacity_limiter,
)
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_THREAD_MIN_SIZE = 128 * 1024  # 128 KiB; mirrors GZipMiddleware default


class Mode:
    generic = MODE_GENERIC
    text = MODE_TEXT
    font = MODE_FONT


class BrotliMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        quality: int = 4,
        mode: str = "text",
        lgwin: int = 22,
        lgblock: int = 0,
        minimum_size: int = 400,
        gzip_fallback: bool = True,
        excluded_handlers: list[str] | None = None,
        thread_minimum_size: int = DEFAULT_THREAD_MIN_SIZE,
    ) -> None:
        self.app = app
        self.quality = quality
        # mode is a string ("text"|"generic"|"font") on the public API, but
        # brotli.Compressor expects the integer constant. Resolve once here.
        self.mode = getattr(Mode, mode)
        self.lgwin = lgwin
        self.lgblock = lgblock
        self.minimum_size = minimum_size
        self.gzip_fallback = gzip_fallback
        self.thread_minimum_size = thread_minimum_size
        if excluded_handlers:
            self.excluded_handlers: list[re.Pattern[str]] = [re.compile(p) for p in excluded_handlers]
        else:
            self.excluded_handlers = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        if self._is_handler_excluded(scope):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        codings = self._parse_accept_encoding(headers.get("Accept-Encoding", ""))
        br_q = codings.get("br", 0.0)
        gzip_q = codings.get("gzip", 0.0)

        # Honor q-values: q=0 explicitly refuses a coding; on a tie brotli wins
        # (better compression than gzip).
        if br_q > 0 and br_q >= gzip_q:
            responder = BrotliResponder(
                self.app,
                self.minimum_size,
                quality=self.quality,
                mode=self.mode,
                lgwin=self.lgwin,
                lgblock=self.lgblock,
                thread_minimum_size=self.thread_minimum_size,
            )
            await responder(scope, receive, send)
            return

        if self.gzip_fallback and gzip_q > 0:
            # Delegate to Starlette's GZipResponder.
            gzip_responder = GZipResponder(
                self.app,
                self.minimum_size,
                compresslevel=9,
                thread_minimum_size=self.thread_minimum_size,
            )
            await gzip_responder(scope, receive, send)
            return

        # Client accepts neither br nor gzip (or refused both): pass through unchanged.
        await self.app(scope, receive, send)

    def _is_handler_excluded(self, scope: Scope) -> bool:
        path = scope.get("path", "")
        return any(pattern.search(path) for pattern in self.excluded_handlers)

    def _parse_accept_encoding(self, header: str) -> dict[str, float]:
        # Parse Accept-Encoding into {coding: q-value}. Content codings are
        # case-insensitive (RFC 7231 §5.3.4); q defaults to 1.0 and q=0 refuses.
        codings: dict[str, float] = {}
        for part in header.split(","):
            part = part.strip()
            if not part:
                continue
            pieces = part.split(";")
            coding = pieces[0].strip().lower()
            if not coding:
                continue
            q = 1.0
            for param in pieces[1:]:
                param = param.strip()
                if param.startswith("q="):
                    try:
                        q = float(param[2:])
                    except ValueError:
                        q = 1.0
            codings[coding] = q
        return codings


class BrotliResponder(IdentityResponder):
    content_encoding = "br"

    def __init__(
        self,
        app: ASGIApp,
        minimum_size: int,
        *,
        quality: int,
        mode: int,
        lgwin: int,
        lgblock: int,
        thread_minimum_size: int,
    ) -> None:
        super().__init__(app, minimum_size)
        self.quality = quality
        self.mode = mode
        self.lgwin = lgwin
        self.lgblock = lgblock
        self.thread_minimum_size = thread_minimum_size
        # Lazy-init: only allocate a brotli.Compressor when we actually need to
        # compress. This avoids paying the cost for pathsend / small / excluded
        # responses that never reach apply_compression.
        self._compressor: Compressor | None = None

    @property
    def compressor(self) -> Compressor:
        if self._compressor is None:
            self._compressor = Compressor(
                quality=self.quality,
                mode=self.mode,
                lgwin=self.lgwin,
                lgblock=self.lgblock,
            )
        return self._compressor

    async def apply_compression(self, body: bytes, *, more_body: bool) -> bytes:
        # Must call finish() on final empty chunk to write brotli end-of-stream marker.
        # Compressor is lazy-init'd; skipped for small/SSE/pathsend/already-encoded responses.
        if len(body) >= self.thread_minimum_size:
            # Offload large bodies to worker thread via Starlette's gzip capacity limiter.
            limiter = _get_gzip_capacity_limiter()
            return await anyio.to_thread.run_sync(self._compress_body, body, more_body, limiter=limiter)
        return self._compress_body(body, more_body)

    def _compress_body(self, body: bytes, more_body: bool) -> bytes:
        # For streaming chunks call flush() to emit partial output; for final chunk call finish().
        chunk: bytes = self.compressor.process(body)
        tail: bytes = self.compressor.flush() if more_body else self.compressor.finish()
        return chunk + tail


async def unattached_send(message: Message) -> NoReturn:
    raise RuntimeError("send awaitable not set")  # pragma: no cover
