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
    """Candidate-narrowing segment trie over Starlette route paths.

    `match_all` returns a superset of the routes whose `path_regex` could match a
    path, in registration order; the caller still runs `Route.matches` on each
    candidate, so the trie never decides a match on its own.

    Segments are read while they are static or a lone parameter using exactly a
    built-in single-segment convertor. The first segment that cannot be read that
    way - a `path` parameter, a compound segment, a custom convertor - makes the
    route a tail on the node reached so far, so it stays a candidate only for
    paths under the literal prefix it does have. A route with no usable path is a
    tail on the root, and so a candidate for every path.
    """

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
        stack = [(self.root, path.lstrip("/"))]
        while stack:
            node, rest = stack.pop()
            seg, slash, tail = rest.partition("/")

            if not slash:
                child = node.static.get(seg)
                if child is not None:
                    out.extend(child.indices)
                if seg and node.param is not None:
                    out.extend(node.param.indices)
            else:
                child = node.static.get(seg)
                if child is not None:
                    stack.append((child, tail))
                if seg and node.param is not None:
                    stack.append((node.param, tail))

            # A tail registered here matches whatever is left, including the empty
            # string.
            out.extend(node.tail)

        out.sort()
        return out
