import sys
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from contextlib import AbstractAsyncContextManager
from typing import TYPE_CHECKING, Any

if sys.version_info >= (3, 13):  # pragma: no cover
    from typing import TypeVar
else:  # pragma: no cover
    from typing_extensions import TypeVar

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.websockets import WebSocket

AppType = TypeVar("AppType")
_Exception = TypeVar("_Exception", bound=Exception, default=Exception)

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]

Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

StatelessLifespan = Callable[[AppType], AbstractAsyncContextManager[None]]
StatefulLifespan = Callable[[AppType], AbstractAsyncContextManager[Mapping[str, Any]]]
Lifespan = StatelessLifespan[AppType] | StatefulLifespan[AppType]

HTTPExceptionHandler = Callable[["Request", _Exception], "Response | Awaitable[Response]"]
WebSocketExceptionHandler = Callable[["WebSocket", _Exception], Awaitable[None]]
ExceptionHandler = HTTPExceptionHandler[_Exception] | WebSocketExceptionHandler[_Exception]
