from __future__ import annotations

import functools
import re
import sys
from collections.abc import AsyncGenerator, Awaitable, Callable, Generator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from ipaddress import AddressValueError, IPv6Address
from typing import Any, Generic, Protocol, TypeVar, overload

import anyio.abc

from starlette.types import Scope

if sys.version_info >= (3, 13):  # pragma: no cover
    from inspect import iscoroutinefunction
    from typing import TypeIs
else:  # pragma: no cover
    from asyncio import iscoroutinefunction

    from typing_extensions import TypeIs

if sys.version_info < (3, 11):  # pragma: no cover
    try:
        from exceptiongroup import BaseExceptionGroup
    except ImportError:

        class BaseExceptionGroup(BaseException):  # type: ignore[no-redef]
            pass


T = TypeVar("T")
AwaitableCallable = Callable[..., Awaitable[T]]

# Reject characters that could make a Host header change the URL path or authority.
_HOST_RE = re.compile(
    r"^(?P<host>[a-z0-9._~%!$&'()*+,;=-]+|\[(?:(?P<ipv6>[a-f0-9]*:[a-f0-9.:]+)|"
    r"(?-i:v)[a-f0-9]+\.[a-z0-9._~!$&'()*+,;=:-]+)\])(?::(?P<port>[0-9]+))?$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ParsedHost:
    host: str
    port: str | None

    @property
    def authority(self) -> str:
        return self.host if self.port is None else f"{self.host}:{self.port}"

    @property
    def is_valid_port(self) -> bool:
        if self.port is None:
            return True
        port = self.port.lstrip("0")
        return len(port) <= 5 and int(port or "0") <= 65535


@overload
def is_async_callable(obj: AwaitableCallable[T]) -> TypeIs[AwaitableCallable[T]]: ...


@overload
def is_async_callable(obj: Any) -> TypeIs[AwaitableCallable[Any]]: ...


def is_async_callable(obj: Any) -> Any:
    while isinstance(obj, functools.partial):
        obj = obj.func

    return iscoroutinefunction(obj) or (callable(obj) and iscoroutinefunction(obj.__call__))


T_co = TypeVar("T_co", covariant=True)


class AwaitableOrContextManager(
    Awaitable[T_co], AbstractAsyncContextManager[T_co], Protocol[T_co]
): ...  # pragma: no branch


class SupportsAsyncClose(Protocol):
    async def close(self) -> None: ...  # pragma: no cover


SupportsAsyncCloseType = TypeVar("SupportsAsyncCloseType", bound=SupportsAsyncClose, covariant=False)


class AwaitableOrContextManagerWrapper(Generic[SupportsAsyncCloseType]):
    __slots__ = ("aw", "entered")

    def __init__(self, aw: Awaitable[SupportsAsyncCloseType]) -> None:
        self.aw = aw

    def __await__(self) -> Generator[Any, None, SupportsAsyncCloseType]:
        return self.aw.__await__()

    async def __aenter__(self) -> SupportsAsyncCloseType:
        self.entered = await self.aw
        return self.entered

    async def __aexit__(self, *args: Any) -> None | bool:
        await self.entered.close()
        return None


@asynccontextmanager
async def create_collapsing_task_group() -> AsyncGenerator[anyio.abc.TaskGroup, None]:
    try:
        async with anyio.create_task_group() as tg:
            yield tg
    except BaseExceptionGroup as excs:
        if len(excs.exceptions) != 1:
            raise

        exc = excs.exceptions[0]
        context = None if exc.__suppress_context__ else exc.__context__
        raise exc from exc.__cause__ or context


def parse_host_header(host_header: str | None) -> ParsedHost | None:
    """Parse `host_header` into its host and port components.

    The host preserves brackets around IP literals. Invalid headers produce `None`.
    """
    if host_header is None:
        return None

    match = _HOST_RE.fullmatch(host_header)
    if match is None:
        return None

    ipv6 = match["ipv6"]
    if ipv6 is not None:
        try:
            IPv6Address(ipv6)
        except AddressValueError:
            return None

    return ParsedHost(match["host"], match["port"])


def get_route_path(scope: Scope) -> str:
    path: str = scope["path"]
    root_path = scope.get("root_path", "")
    if not root_path:
        return path

    if not path.startswith(root_path):
        return path

    if path == root_path:
        return ""

    if path[len(root_path)] == "/":
        return path[len(root_path) :]

    return path
