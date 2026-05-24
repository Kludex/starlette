from __future__ import annotations

import functools
import os
import sys
import warnings
from collections.abc import AsyncIterator, Callable, Coroutine, Iterable, Iterator
from types import TracebackType
from typing import IO, Any, Generic, ParamSpec, Protocol, TypeVar, cast

import anyio
import anyio.to_thread

P = ParamSpec("P")
T = TypeVar("T")
FileContent = TypeVar("FileContent", str, bytes)


_NO_THREAD_PLATFORMS = {"emscripten"}


def _threadpool_available() -> bool:
    return sys.platform not in _NO_THREAD_PLATFORMS


class _AsyncFile(Protocol[FileContent]):
    async def __aenter__(self) -> _AsyncFile[FileContent]: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    async def read(self, size: int = -1) -> FileContent: ...

    async def seek(self, offset: int) -> int: ...

    async def aclose(self) -> None: ...


class _ThreadlessAsyncFile(Generic[FileContent]):  # pragma: no cover
    def __init__(self, file: IO[FileContent]) -> None:
        self.file: IO[FileContent] = file

    async def __aenter__(self) -> _ThreadlessAsyncFile[FileContent]:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def read(self, size: int = -1) -> FileContent:
        return self.file.read(size)

    async def seek(self, offset: int) -> int:
        return self.file.seek(offset)

    async def aclose(self) -> None:
        self.file.close()


async def open_file(path: str | os.PathLike[str], mode: str = "r") -> _AsyncFile[Any]:
    """
    Wrapper of `anyio.open_file` that falls back to synchronous file operations
    when the threadpool is not available.
    """
    if _threadpool_available():
        return cast(_AsyncFile[Any], await anyio.open_file(path, mode=cast(Any, mode)))
    return _ThreadlessAsyncFile(open(path, mode))  # pragma: no cover


async def run_until_first_complete(*args: tuple[Callable, dict]) -> None:  # type: ignore[type-arg]
    warnings.warn(
        "run_until_first_complete is deprecated and will be removed in a future version.",
        DeprecationWarning,
    )

    async with anyio.create_task_group() as task_group:

        async def run(func: Callable[[], Coroutine]) -> None:  # type: ignore[type-arg]
            await func()
            task_group.cancel_scope.cancel()

        for func, kwargs in args:
            task_group.start_soon(run, functools.partial(func, **kwargs))


async def run_in_threadpool(func: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    func = functools.partial(func, *args, **kwargs)
    if not _threadpool_available():  # pragma: no cover
        return func()
    return await anyio.to_thread.run_sync(func)


class _StopIteration(Exception):
    pass


def _next(iterator: Iterator[T]) -> T:
    # We can't raise `StopIteration` from within the threadpool iterator
    # and catch it outside that context, so we coerce them into a different
    # exception type.
    try:
        return next(iterator)
    except StopIteration:
        raise _StopIteration


async def iterate_in_threadpool(
    iterator: Iterable[T],
) -> AsyncIterator[T]:
    if not _threadpool_available():  # pragma: no cover
        for item in iterator:
            yield item
        return

    as_iterator = iter(iterator)
    while True:
        try:
            yield await anyio.to_thread.run_sync(_next, as_iterator)
        except _StopIteration:
            break
