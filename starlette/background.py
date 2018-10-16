import asyncio
import functools
import typing


class BackgroundTask:
    def __init__(
        self, func: typing.Callable, *args: typing.Any, **kwargs: typing.Any
    ) -> None:
        self.func = func
        self.args = args
        self.kwargs = kwargs

    async def __call__(self) -> None:
        if asyncio.iscoroutinefunction(self.func):
            await asyncio.ensure_future(self.func(*self.args, **self.kwargs))
        else:
            fn = functools.partial(self.func, *self.args, **self.kwargs)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, fn)
