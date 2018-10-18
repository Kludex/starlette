import asyncio
import logging
import traceback
import typing
from types import TracebackType
from starlette.types import ASGIApp, ASGIInstance, Receive, Message, Send


STATE_TRANSITION_ERROR = "Got invalid state transition on lifespan protocol."


class LifespanHandler:
    def __init__(self) -> None:
        self.startup_handlers = []  # type: typing.List[typing.Callable]
        self.cleanup_handlers = []  # type: typing.List[typing.Callable]

    def on_event(self, event_type: str) -> typing.Callable:
        def decorator(func: typing.Callable) -> typing.Callable:
            self.add_event_handler(event_type, func)
            return func

        return decorator

    def add_event_handler(self, event_type: str, func: typing.Callable) -> None:
        assert event_type in ("startup", "cleanup")

        if event_type == "startup":
            self.startup_handlers.append(func)
        else:
            self.cleanup_handlers.append(func)

    async def run_startup(self) -> None:
        for handler in self.startup_handlers:
            if asyncio.iscoroutinefunction(handler):
                await handler()
            else:
                handler()

    async def run_cleanup(self) -> None:
        for handler in self.cleanup_handlers:
            if asyncio.iscoroutinefunction(handler):
                await handler()
            else:
                handler()

    def __call__(self, scope: Message) -> ASGIInstance:
        assert scope["type"] == "lifespan"
        return self.run_lifespan

    async def run_lifespan(self, receive: Receive, send: Send) -> None:
        message = await receive()
        assert message["type"] == "lifespan.startup"
        await self.run_startup()
        await send({"type": "lifespan.startup.complete"})
        message = await receive()
        assert message["type"] == "lifespan.cleanup"
        await self.run_cleanup()
        await send({"type": "lifespan.cleanup.complete"})


class LifespanContext:
    def __init__(
        self, app: ASGIApp, startup_timeout: int = 10, cleanup_timeout: int = 10
    ) -> None:
        self.startup_timeout = startup_timeout
        self.cleanup_timeout = cleanup_timeout
        self.startup_event = asyncio.Event()
        self.cleanup_event = asyncio.Event()
        self.receive_queue = asyncio.Queue()  # type: asyncio.Queue
        self.asgi = app({"type": "lifespan"})  # type: ASGIInstance

    def __enter__(self) -> None:
        loop = asyncio.get_event_loop()
        loop.create_task(self.run_lifespan())
        loop.run_until_complete(self.wait_startup())

    def __exit__(
        self,
        exc_type: typing.Type[BaseException],
        exc: BaseException,
        tb: TracebackType,
    ) -> None:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.wait_cleanup())

    async def run_lifespan(self) -> None:
        try:
            await self.asgi(self.receive, self.send)
        finally:
            self.startup_event.set()
            self.cleanup_event.set()

    async def send(self, message: Message) -> None:
        if message["type"] == "lifespan.startup.complete":
            assert not self.startup_event.is_set(), STATE_TRANSITION_ERROR
            assert not self.cleanup_event.is_set(), STATE_TRANSITION_ERROR
            self.startup_event.set()
        else:
            assert message["type"] == "lifespan.cleanup.complete"
            assert self.startup_event.is_set(), STATE_TRANSITION_ERROR
            assert not self.cleanup_event.is_set(), STATE_TRANSITION_ERROR
            self.cleanup_event.set()

    async def receive(self) -> Message:
        return await self.receive_queue.get()

    async def wait_startup(self) -> None:
        await self.receive_queue.put({"type": "lifespan.startup"})
        await asyncio.wait_for(self.startup_event.wait(), timeout=self.startup_timeout)

    async def wait_cleanup(self) -> None:
        await self.receive_queue.put({"type": "lifespan.cleanup"})
        await asyncio.wait_for(self.cleanup_event.wait(), timeout=self.cleanup_timeout)
