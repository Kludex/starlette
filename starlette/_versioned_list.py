from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, SupportsIndex, TypeVar, cast, overload

from typing_extensions import Self

T = TypeVar("T")


class VersionedList(list[T]):
    def __init__(self, values: Iterable[T] = ()) -> None:
        super().__init__(values)
        self.version = 0

    @overload
    def __setitem__(self, index: SupportsIndex, value: T, /) -> None: ...

    @overload
    def __setitem__(self, index: slice, value: Iterable[T], /) -> None: ...

    def __setitem__(self, index: SupportsIndex | slice, value: T | Iterable[T], /) -> None:
        if isinstance(index, slice):
            super().__setitem__(index, cast(Iterable[T], value))
        else:
            super().__setitem__(index, cast(T, value))
        self.version += 1

    def __delitem__(self, index: SupportsIndex | slice, /) -> None:
        super().__delitem__(index)
        self.version += 1

    def __iadd__(self, values: Iterable[T], /) -> Self:  # type: ignore[misc, override]
        result = super().__iadd__(values)
        self.version += 1
        return result

    def __imul__(self, value: SupportsIndex, /) -> Self:
        result = super().__imul__(value)
        self.version += 1
        return result

    def append(self, value: T, /) -> None:
        super().append(value)
        self.version += 1

    def extend(self, values: Iterable[T], /) -> None:
        super().extend(values)
        self.version += 1

    def insert(self, index: SupportsIndex, value: T, /) -> None:
        super().insert(index, value)
        self.version += 1

    def pop(self, index: SupportsIndex = -1, /) -> T:
        value = super().pop(index)
        self.version += 1
        return value

    def remove(self, value: T, /) -> None:
        super().remove(value)
        self.version += 1

    def clear(self) -> None:
        super().clear()
        self.version += 1

    def reverse(self) -> None:
        super().reverse()
        self.version += 1

    def sort(self, *, key: Callable[[T], Any] | None = None, reverse: bool = False) -> None:
        super().sort(key=key, reverse=reverse)
        self.version += 1
