import asyncio
import typing

from starlette.types import ASGIApp, ASGIInstance, Message, Receive, Scope, Send

STATE_TRANSITION_ERROR = "Got invalid state transition on lifespan protocol."


class LifespanMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        startup_handlers: typing.List[typing.Callable] = None,
        shutdown_handlers: typing.List[typing.Callable] = None,
    ):
        self.app = app
        self.startup_handlers = list(startup_handlers or [])
        self.shutdown_handlers = list(shutdown_handlers or [])

    def add_event_handler(self, event_type: str, func: typing.Callable) -> None:
        assert event_type in ("startup", "shutdown")

        if event_type == "startup":
            self.startup_handlers.append(func)
        else:
            assert event_type == "shutdown"
            self.shutdown_handlers.append(func)

    def on_event(self, event_type: str) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_event_handler(event_type, func)
            return func

        return decorator

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] == "lifespan":
            return LifespanHandler(
                self.app, scope, self.startup_handlers, self.shutdown_handlers
            )
        return self.app(scope)


class LifespanHandler:
    def __init__(
        self,
        app: ASGIApp,
        scope: Scope,
        startup_handlers: typing.List[typing.Callable],
        shutdown_handlers: typing.List[typing.Callable],
    ) -> None:
        self.inner = app(scope)
        self.startup_handlers = startup_handlers
        self.shutdown_handlers = shutdown_handlers

    async def __call__(self, receive: Receive, send: Send) -> None:
        async def receiver() -> Message:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await self.startup()
            elif message["type"] == "lifespan.shutdown":
                await self.shutdown()
            return message

        await self.inner(receiver, send)

    async def startup(self) -> None:
        for handler in self.startup_handlers:
            if asyncio.iscoroutinefunction(handler):
                await handler()
            else:
                handler()

    async def shutdown(self) -> None:
        for handler in self.shutdown_handlers:
            if asyncio.iscoroutinefunction(handler):
                await handler()
            else:
                handler()
