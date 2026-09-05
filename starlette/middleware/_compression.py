from __future__ import annotations

import functools
import sys
import zlib
from collections.abc import Callable
from typing import cast

import anyio.lowlevel
import anyio.to_thread

if sys.version_info >= (3, 13):  # pragma: no cover - Depends on the Python version.
    from typing import Protocol, TypedDict
else:  # pragma: no cover - Depends on the Python version.
    from typing_extensions import Protocol, TypedDict


class Compressor(Protocol):
    def __call__(self, body: bytes, more_body: bool, /) -> bytes: ...


class CompressionConfig(TypedDict, total=False):
    compresslevel: int


class CompressionStream:
    def __init__(self, factory: Callable[[], Compressor], thread_minimum_size: int) -> None:
        self.factory = factory
        self.thread_minimum_size = thread_minimum_size
        self.compressor: Compressor | None = None
        self.total_size = 0

    async def __call__(self, body: bytes, more_body: bool) -> bytes:
        self.total_size += len(body)
        if self.total_size >= self.thread_minimum_size:
            try:
                limiter = _capacity_limiter.get()
            except LookupError:
                limiter = anyio.CapacityLimiter(40)
                _capacity_limiter.set(limiter)
            return await anyio.to_thread.run_sync(self.compress, body, more_body, limiter=limiter)
        return self.compress(body, more_body)

    def compress(self, body: bytes, more_body: bool) -> bytes:
        if self.compressor is None:
            self.compressor = self.factory()
        return self.compressor(body, more_body)


class GZipCompressor:
    def __init__(self, compresslevel: int) -> None:
        self.compressor = zlib.compressobj(compresslevel, zlib.DEFLATED, 16 + zlib.MAX_WBITS)

    def __call__(self, body: bytes, more_body: bool, /) -> bytes:
        mode = zlib.Z_SYNC_FLUSH if more_body else zlib.Z_FINISH
        return self.compressor.compress(body) + self.compressor.flush(mode)


def zstd_factory(compresslevel: int) -> Callable[[], Compressor]:
    if sys.version_info >= (3, 14):  # pragma: no cover - Depends on the Python version.
        from compression.zstd import CompressionParameter, ZstdCompressor
    else:  # pragma: no cover - Depends on the Python version.
        from backports.zstd import CompressionParameter, ZstdCompressor

    lower, upper = CompressionParameter.compression_level.bounds()
    if not lower <= compresslevel <= upper:
        raise ValueError(f"Zstandard compresslevel must be between {lower} and {upper}.")

    def create() -> Compressor:
        compressor = ZstdCompressor(
            options={
                CompressionParameter.compression_level: compresslevel,
                # HTTP decoders need not support windows larger than 8 MiB (RFC 9659).
                CompressionParameter.window_log: 23,
            }
        )

        def compress(body: bytes, more_body: bool) -> bytes:
            return compressor.compress(body, ZstdCompressor.FLUSH_BLOCK if more_body else ZstdCompressor.FLUSH_FRAME)

        return compress

    return create


def brotli_factory(compresslevel: int) -> Callable[[], Compressor]:
    import brotli

    if not 0 <= compresslevel <= 11:
        raise ValueError("Brotli compresslevel must be between 0 and 11.")

    def create() -> Compressor:
        compressor = cast(_BrotliCompressor, brotli.Compressor(quality=compresslevel))

        def compress(body: bytes, more_body: bool) -> bytes:
            return compressor.process(body) + (compressor.flush() if more_body else compressor.finish())

        return compress

    return create


def gzip_factory(compresslevel: int) -> Callable[[], Compressor]:
    if not 0 <= compresslevel <= 9:
        raise ValueError("Gzip compresslevel must be between 0 and 9.")
    return functools.partial(GZipCompressor, compresslevel)


class _BrotliCompressor(Protocol):
    def process(self, body: bytes, /) -> bytes: ...
    def flush(self) -> bytes: ...
    def finish(self) -> bytes: ...


_capacity_limiter: anyio.lowlevel.RunVar[anyio.CapacityLimiter] = anyio.lowlevel.RunVar("_compression_capacity_limiter")
