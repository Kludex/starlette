import typing


Scope = typing.MutableMapping[str, typing.Any]
Message = typing.MutableMapping[str, typing.Any]

Receive = typing.Callable[[], typing.Awaitable[Message]]
Send = typing.Callable[[Message], typing.Awaitable[None]]

ASGIInstance = typing.Callable[[Receive, Send], typing.Awaitable[None]]
ASGIApp = typing.Callable[[Scope], ASGIInstance]
