from __future__ import annotations

import re

from starlette.convertors import (
    Convertor,
    FloatConvertor,
    IntegerConvertor,
    PathConvertor,
    StringConvertor,
    UUIDConvertor,
)

# Match parameters in URL paths, eg. '{param}', and '{param:int}'
PARAM_REGEX = re.compile("{([a-zA-Z_][a-zA-Z0-9_]*)(:[a-zA-Z_][a-zA-Z0-9_]*)?}")

# Built-in convertors whose regex is known to match within a single path segment.
_SEGMENT_CONVERTORS = (StringConvertor, IntegerConvertor, FloatConvertor, UUIDConvertor)


class Node:
    __slots__ = ("static", "param", "path_indices", "indices")

    def __init__(self) -> None:
        self.static: dict[str, Node] = {}
        self.param: Node | None = None
        self.path_indices: list[int] = []
        self.indices: list[int] = []


class RouteTrie:
    """Candidate-narrowing segment trie over Starlette route paths.

    `match_all` returns a superset of the routes whose `path_regex` could match a
    path, in registration order; the caller still runs `Route.matches` on each
    candidate, so the trie never decides a match on its own.

    A route is indexed only when every segment of its path is either static, a
    lone parameter whose convertor is exactly a built-in single-segment one, or a
    `path` parameter. Everything else - compound segments, custom convertors,
    routes without a flat path - is reported as a candidate for every path, so
    dispatch stays correct by construction rather than by regex analysis.
    """

    def __init__(self) -> None:
        self.root = Node()
        self.always: list[int] = []
        # The number of routes this trie was built for. The owner compares it
        # against the live route count to rebuild. Replacing or reordering routes
        # at the same count is not detected: build the route table before
        # serving, as Starlette already expects.
        self.count = 0

    def is_stale(self, count: int) -> bool:
        return self.count != count

    def add(self, index: int, path: str | None, convertors: dict[str, Convertor[object]]) -> None:
        if not path or not path.startswith("/"):
            self.always.append(index)
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
            elif type(convertor) is PathConvertor:
                # Consumes the rest of the path, so the route ends here.
                node.path_indices.append(index)
                return
            else:
                self.always.append(index)
                return
        node.indices.append(index)

    def match_all(self, path: str) -> list[int]:
        out = list(self.always)
        self._walk(self.root, path.lstrip("/"), out)
        out.sort()
        return out

    def _walk(self, node: Node, rest: str, out: list[int]) -> None:
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
                self._walk(child, tail, out)
            if seg and node.param is not None:
                self._walk(node.param, tail, out)

        # A `path` parameter registered here matches whatever is left, including
        # the empty string.
        out.extend(node.path_indices)
