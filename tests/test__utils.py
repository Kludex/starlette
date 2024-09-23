import functools
from typing import Any

import pytest

from starlette._utils import get_route_path, is_async_callable
from starlette.types import Scope


def test_async_func() -> None:
    async def async_func() -> None: ...  # pragma: no cover

    def func() -> None: ...  # pragma: no cover

    assert is_async_callable(async_func)
    assert not is_async_callable(func)


def test_async_partial() -> None:
    async def async_func(a: Any, b: Any) -> None: ...  # pragma: no cover

    def func(a: Any, b: Any) -> None: ...  # pragma: no cover

    partial = functools.partial(async_func, 1)
    assert is_async_callable(partial)

    partial = functools.partial(func, 1)  # type: ignore
    assert not is_async_callable(partial)


def test_async_method() -> None:
    class Async:
        async def method(self) -> None: ...  # pragma: no cover

    class Sync:
        def method(self) -> None: ...  # pragma: no cover

    assert is_async_callable(Async().method)
    assert not is_async_callable(Sync().method)


def test_async_object_call() -> None:
    class Async:
        async def __call__(self) -> None: ...  # pragma: no cover

    class Sync:
        def __call__(self) -> None: ...  # pragma: no cover

    assert is_async_callable(Async())
    assert not is_async_callable(Sync())


def test_async_partial_object_call() -> None:
    class Async:
        async def __call__(
            self,
            a: Any,
            b: Any,
        ) -> None: ...  # pragma: no cover

    class Sync:
        def __call__(
            self,
            a: Any,
            b: Any,
        ) -> None: ...  # pragma: no cover

    partial = functools.partial(Async(), 1)
    assert is_async_callable(partial)

    partial = functools.partial(Sync(), 1)  # type: ignore
    assert not is_async_callable(partial)


def test_async_nested_partial() -> None:
    async def async_func(
        a: Any,
        b: Any,
    ) -> None: ...  # pragma: no cover

    partial = functools.partial(async_func, b=2)
    nested_partial = functools.partial(partial, a=1)
    assert is_async_callable(nested_partial)


@pytest.mark.parametrize(
    "scope, expected_result",
    [
        ({"path": "/foo-123/bar", "root_path": "/foo"}, "/foo-123/bar"),
        ({"path": "/foo/bar", "root_path": "/foo"}, "/bar"),
        ({"path": "/foo", "root_path": "/foo"}, ""),
        ({"path": "/foo/bar", "root_path": "/bar"}, "/foo/bar"),
    ],
)
def test_get_route_path(scope: Scope, expected_result: str) -> None:
    assert get_route_path(scope) == expected_result
