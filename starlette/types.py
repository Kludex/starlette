import typing


Scope = typing.Mapping[str, typing.Any]
Message = typing.Mapping[str, typing.Any]

Receive = typing.Callable[[], typing.Awaitable[Message]]
Send = typing.Callable[[Message], typing.Awaitable[None]]

ASGIInstance = typing.Callable[[Receive, Send], typing.Awaitable[None]]
ASGIApp = typing.Callable[[Scope], ASGIInstance]
