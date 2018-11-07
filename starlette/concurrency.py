import asyncio
import functools
import typing

try:
    import contextvars  # Python 3.7+ only.
except ImportError:  # pragma: no cover
    contextvars = None  # type: ignore


async def run_in_threadpool(
    func: typing.Callable, *args: typing.Any, **kwargs: typing.Any
) -> typing.Any:
    loop = asyncio.get_event_loop()
    if contextvars is not None:  # pragma: no cover
        # Ensure we run in the same context
        child = functools.partial(func, *args, **kwargs)
        context = contextvars.copy_context()
        func = context.run
        args = (child,)
    elif kwargs:  # pragma: no cover
        # loop.run_in_executor doesn't accept 'kwargs', so bind them in here
        func = functools.partial(func, **kwargs)
    return await loop.run_in_executor(None, func, *args)
