import asyncio
import logging
import traceback
import typing
from types import TracebackType

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
        self.send_buffer = asyncio.Queue()  # type: asyncio.Queue
        self.receive_buffer = asyncio.Queue()  # type: asyncio.Queue

    async def __call__(self, receive: Receive, send: Send) -> None:
        loop = asyncio.get_event_loop()
        inner_task = loop.create_task(self.run_inner())
        try:
            # Handle our own startup.
            message = await receive()
            assert message["type"] == "lifespan.startup"
            await self.startup()

            # Pass the message on to the next in the chain, and wait for the response.
            await self.receive_buffer.put(message)
            message = await self.send_buffer.get()
            if message is None:
                inner_task.result()
            assert message["type"] == "lifespan.startup.complete"
            await send({"type": "lifespan.startup.complete"})

            # Handle our own shutdown.
            message = await receive()
            assert message["type"] == "lifespan.shutdown"
            await self.shutdown()

            # Pass the message on to the next in the chain, and wait for the response.
            await self.receive_buffer.put(message)
            message = await self.send_buffer.get()
            if message is None:
                inner_task.result()
            assert message["type"] == "lifespan.shutdown.complete"
            await send({"type": "lifespan.shutdown.complete"})
        finally:
            await inner_task

    async def run_inner(self) -> None:
        try:
            await self.inner(self.receive_buffer.get, self.send_buffer.put)
        finally:
            await self.send_buffer.put(None)

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
