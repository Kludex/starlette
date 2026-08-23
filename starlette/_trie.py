from __future__ import annotations

import re
from collections.abc import Sequence

from starlette.convertors import (
    Convertor,
    FloatConvertor,
    IntegerConvertor,
    StringConvertor,
    UUIDConvertor,
)

# Match parameters in URL paths, eg. '{param}', and '{param:int}'
PARAM_REGEX = re.compile("{([a-zA-Z_][a-zA-Z0-9_]*)(:[a-zA-Z_][a-zA-Z0-9_]*)?}")

# Built-in convertors whose regex is known to match within a single path segment.
_SEGMENT_CONVERTORS = (StringConvertor, IntegerConvertor, FloatConvertor, UUIDConvertor)


class Node:
    __slots__ = ("static", "param", "tail", "indices")

    def __init__(self) -> None:
        self.static: dict[str, Node] = {}
        self.param: Node | None = None
        # Routes that match any remainder of the path from this node.
        self.tail: list[int] = []
        self.indices: list[int] = []


class RouteTrie:
    """Build in O(N) expected time and match in O(N log N) worst-case time, where N is the input size."""

    def __init__(self, routes: Sequence[object] | None = None) -> None:
        self.root = Node()
        self.indexed = False
        self._routes = None if routes is None else list(routes)

    def is_stale(self, routes: Sequence[object]) -> bool:
        return self._routes != routes

    def add(self, index: int, path: str | None, convertors: dict[str, Convertor[object]]) -> None:
        if not path or not path.startswith("/"):
            self.root.tail.append(index)
            return
        node = self.root
        for seg in path.lstrip("/").split("/"):
            if "{" not in seg:
                child = node.static.get(seg)
                if child is None:
                    child = Node()
                    node.static[seg] = child
                node = child
                continue
            match = PARAM_REGEX.fullmatch(seg)
            convertor = convertors.get(match.group(1)) if match is not None else None
            if type(convertor) in _SEGMENT_CONVERTORS:
                if node.param is None:
                    node.param = Node()
                node = node.param
                continue
            node.tail.append(index)
            if node is not self.root:
                self.indexed = True
            return
        node.indices.append(index)
        self.indexed = True

    def match_all(self, path: str) -> list[int]:
        if not self.indexed:
            # Nothing to narrow with, so skip the walk and the sort: the root tail
            # is already every route, in registration order.
            return self.root.tail
        out: list[int] = []
        segments = path.lstrip("/").split("/")
        last = len(segments) - 1
        stack = [(self.root, 0)]
        while stack:
            node, position = stack.pop()
            seg = segments[position]

            if position == last:
                child = node.static.get(seg)
                if child is not None:
                    out.extend(child.indices)
                if seg and node.param is not None:
                    out.extend(node.param.indices)
            else:
                child = node.static.get(seg)
                if child is not None:
                    stack.append((child, position + 1))
                if seg and node.param is not None:
                    stack.append((node.param, position + 1))

            # A tail registered here matches whatever is left, including the empty
            # string.
            out.extend(node.tail)

        out.sort()
        return out
