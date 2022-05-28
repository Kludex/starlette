import functools

from starlette._utils import is_async_callable


def test_async_func():
    async def async_func():
        ...  # pragma: no cover

    def func():
        ...  # pragma: no cover

    assert is_async_callable(async_func)
    assert not is_async_callable(func)


def test_async_partial():
    async def async_func(a, b):
        ...  # pragma: no cover

    def func(a, b):
        ...  # pragma: no cover

    partial = functools.partial(async_func, 1)
    assert is_async_callable(partial)

    partial = functools.partial(func, 1)
    assert not is_async_callable(partial)


def test_async_method():
    class Async:
        async def method(self):
            ...  # pragma: no cover

    class Sync:
        def method(self):
            ...  # pragma: no cover

    assert is_async_callable(Async().method)
    assert not is_async_callable(Sync().method)


def test_async_object_call():
    class Async:
        async def __call__(self):
            ...  # pragma: no cover

    class Sync:
        def __call__(self):
            ...  # pragma: no cover

    assert is_async_callable(Async())
    assert not is_async_callable(Sync())


def test_async_partial_object_call():
    class Async:
        async def __call__(self, a, b):
            ...  # pragma: no cover

    class Sync:
        def __call__(self, a, b):
            ...  # pragma: no cover

    partial = functools.partial(Async(), 1)
    assert is_async_callable(partial)

    partial = functools.partial(Sync(), 1)
    assert not is_async_callable(partial)


def test_async_nested_partial():
    async def async_func(a, b):
        ...  # pragma: no cover

    partial = functools.partial(async_func, b=2)
    nested_partial = functools.partial(partial, a=1)
    assert is_async_callable(nested_partial)
