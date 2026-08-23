from __future__ import annotations

import heapq
from collections.abc import Iterable, Sequence


class RouteIndex:
    """Find route candidates in O(N) worst-case time."""

    def __init__(self, routes: Sequence[object] | None = None) -> None:
        self._routes = None if routes is None else list(routes)
        self._exact: dict[str, list[int]] = {}
        self._prefix: dict[str, list[int]] = {}
        self._fallback: list[int] = []

    def is_stale(self, routes: Sequence[object]) -> bool:
        return self._routes != routes

    def add_exact(self, index: int, path: str) -> None:
        self._exact.setdefault(path, []).append(index)

    def add_prefix(self, index: int, path: str) -> None:
        segment = path.lstrip("/").partition("/")[0]
        if not segment or "{" in segment:
            self._fallback.append(index)
        else:
            self._prefix.setdefault(segment, []).append(index)

    def add_fallback(self, index: int) -> None:
        self._fallback.append(index)

    def match(self, path: str) -> Iterable[int]:
        groups: list[list[int]] = []
        exact = self._exact.get(path)
        if exact is not None:
            groups.append(exact)

        segment = path.lstrip("/").partition("/")[0]
        prefix = self._prefix.get(segment)
        if prefix is not None:
            groups.append(prefix)
        if self._fallback:
            groups.append(self._fallback)

        if len(groups) == 1:
            return groups[0]
        return heapq.merge(*groups)
