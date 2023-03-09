import typing

if typing.TYPE_CHECKING:
    from starlette.applications import Starlette

Scope = typing.MutableMapping[str, typing.Any]
Message = typing.MutableMapping[str, typing.Any]

Receive = typing.Callable[[], typing.Awaitable[Message]]
Send = typing.Callable[[Message], typing.Awaitable[None]]

ASGIApp = typing.Callable[[Scope, Receive, Send], typing.Awaitable[None]]

StatelessLifespan = typing.Callable[["Starlette"], typing.AsyncContextManager[None]]
StatefulLifespan = typing.Callable[
    ["Starlette"], typing.AsyncContextManager[typing.Mapping[str, typing.Any]]
]
Lifespan = typing.Union[StatelessLifespan, StatefulLifespan]
