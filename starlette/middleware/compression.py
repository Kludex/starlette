from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping

from starlette.datastructures import Headers
from starlette.middleware._compression import (
    CompressionConfig as CompressionConfig,
    CompressionStream,
    Compressor as Compressor,
    brotli_factory,
    gzip_factory,
    zstd_factory,
)
from starlette.middleware._compression_negotiation import AcceptEncoding, available_dictionary
from starlette.middleware._compression_response import CompressionResponder
from starlette.middleware.gzip import (
    DEFAULT_EXCLUDED_CONTENT_TYPES as DEFAULT_EXCLUDED_CONTENT_TYPES,
)
from starlette.types import ASGIApp, Receive, Scope, Send


class CompressionMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        minimum_size: int = 500,
        compresslevel: int = 3,
        thread_minimum_size: int = 128 * 1024,
        exclude_content_types: tuple[str, ...] = DEFAULT_EXCLUDED_CONTENT_TYPES,
        gzip: bool | CompressionConfig = True,
        zstd: bool | CompressionConfig | None = None,
        brotli: bool | CompressionConfig | None = None,
        extra_compressors: Mapping[str, Callable[[], Compressor]] | None = None,
        dictionaries: Iterable[bytes] = (),
    ) -> None:
        if minimum_size < 0:
            raise ValueError("minimum_size must be non-negative.")
        if thread_minimum_size < 0:
            raise ValueError("thread_minimum_size must be non-negative.")
        self.app = app
        self.minimum_size = minimum_size
        self.thread_minimum_size = thread_minimum_size
        self.exclude_content_types = tuple(value.partition(";")[0].strip().lower() for value in exclude_content_types)
        self.compressors: dict[str, Callable[[], Compressor]] = {}
        for encoding, factory in (extra_compressors or {}).items():
            encoding = encoding.lower()
            if (
                not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", encoding)
                or encoding in {"*", "identity", "gzip", "zstd", "br", "dcz"}
                or encoding in self.compressors
            ):
                raise ValueError(f"Invalid or reserved compression encoding: {encoding!r}.")
            self.compressors[encoding] = factory
        self.dictionaries: dict[bytes, Callable[[], Compressor]] = {}
        dictionaries = tuple(dictionaries)
        level = zstd.get("compresslevel", compresslevel) if isinstance(zstd, dict) else compresslevel
        try:
            if zstd is not False:
                self.compressors["zstd"] = zstd_factory(level)
            for dictionary in dictionaries:
                self.dictionaries[hashlib.sha256(dictionary).digest()] = zstd_factory(level, dictionary)
        except ImportError:
            if zstd is not None or dictionaries:
                raise RuntimeError(
                    "Zstandard compression requires Python 3.14 or 'pip install starlette[zstd]'."
                ) from None
        if brotli is not False:
            level = brotli.get("compresslevel", compresslevel) if isinstance(brotli, dict) else compresslevel
            try:
                self.compressors["br"] = brotli_factory(level)
            except ImportError:
                if brotli is not None:
                    raise RuntimeError("Brotli compression requires 'pip install starlette[brotli]'.") from None
        if gzip is not False:
            level = gzip.get("compresslevel", compresslevel) if isinstance(gzip, dict) else compresslevel
            self.compressors["gzip"] = gzip_factory(level)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not (self.compressors or self.dictionaries):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        accept_encoding = headers.getlist("accept-encoding")
        accepted = AcceptEncoding(",".join(accept_encoding) if accept_encoding else None)
        compressors = self.compressors
        vary: tuple[str, ...] = ("Accept-Encoding",)
        if self.dictionaries:
            vary = ("Accept-Encoding", "Available-Dictionary")
            digest = available_dictionary(headers.get("available-dictionary"))
            if digest in self.dictionaries:
                compressors = {"dcz": self.dictionaries[digest], **compressors}
        encoding = accepted.select(tuple(compressors))
        compress = (
            CompressionStream(compressors[encoding], self.thread_minimum_size)
            if encoding is not None and encoding != "identity"
            else None
        )
        responder = CompressionResponder(
            self.app,
            self.minimum_size,
            self.exclude_content_types,
            encoding=encoding,
            compress=compress,
            accepts=accepted.accepts,
            vary=vary,
        )
        await responder(scope, receive, send)
