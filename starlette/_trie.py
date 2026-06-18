from __future__ import annotations

import enum
import re
from re import Pattern

from starlette.convertors import Convertor, PathConvertor, StringConvertor

# Match parameters in URL paths, eg. '{param}', and '{param:int}'
PARAM_REGEX = re.compile("{([a-zA-Z_][a-zA-Z0-9_]*)(:[a-zA-Z_][a-zA-Z0-9_]*)?}")


class SegmentKind(enum.Enum):
    STATIC = enum.auto()
    STR_PARAM = enum.auto()
    PATH_PARAM = enum.auto()
    DYNAMIC = enum.auto()


class Node:
    __slots__ = ("static", "param", "dyn", "path_indices", "indices")

    def __init__(self) -> None:
        self.static: dict[str, Node] = {}
        self.param: Node | None = None
        self.dyn: list[tuple[Pattern[str], Node]] = []
        self.path_indices: list[int] = []
        self.indices: list[int] = []


def _classify(seg: str, convertors: dict[str, Convertor[object]]) -> SegmentKind:
    if "{" not in seg:
        return SegmentKind.STATIC
    match = PARAM_REGEX.fullmatch(seg)
    if match is not None:
        name, suffix = match.group(1), match.group(2)
        convertor = convertors.get(name)
        if suffix in (None, ":str") and isinstance(convertor, StringConvertor):
            return SegmentKind.STR_PARAM
        if isinstance(convertor, PathConvertor):
            return SegmentKind.PATH_PARAM
    return SegmentKind.DYNAMIC


def _segment_regex(seg: str, convertors: dict[str, Convertor[object]]) -> Pattern[str]:
    body = ["^"]
    idx = 0
    for match in PARAM_REGEX.finditer(seg):
        name = match.group(1)
        body.append(re.escape(seg[idx : match.start()]))
        convertor = convertors.get(name)
        body.append(convertor.regex if convertor is not None else "[^/]+")
        idx = match.end()
    body.append(re.escape(seg[idx:]))
    body.append("$")
    return re.compile("".join(body))


class RouteTrie:
    """Candidate-narrowing segment trie over Starlette route paths.

    `match_all` returns a superset of the routes whose `path_regex` could match a
    path; the caller still runs `Route.matches` on each candidate, so the trie
    never decides a match on its own. Segment regexes are derived from each
    route's own `param_convertors` (not re-parsed), so custom convertors and the
    exact `uuid` regex match Starlette precisely. Any route the trie can't index
    exactly (`Mount`, `Host`, no flat path) is reported as always-candidate, so
    dispatch stays correct.
    """

    def __init__(self) -> None:
        self.root = Node()
        self.always: list[int] = []
        # The number of routes this trie was built for; the owner sets it after
        # populating and compares it against the live route count to rebuild.
        self.count = 0

    def is_stale(self, count: int) -> bool:
        return self.count != count

    def add(self, index: int, path: str | None, convertors: dict[str, Convertor[object]]) -> None:
        if not path or not path.startswith("/"):
            self.always.append(index)
            return
        node = self.root
        for seg in path.lstrip("/").split("/"):
            kind = _classify(seg, convertors)
            if kind is SegmentKind.PATH_PARAM:
                node.path_indices.append(index)
                return
            if kind is SegmentKind.STR_PARAM:
                if node.param is None:
                    node.param = Node()
                node = node.param
            elif kind is SegmentKind.DYNAMIC:
                regex = _segment_regex(seg, convertors)
                child = next((c for rx, c in node.dyn if rx.pattern == regex.pattern), None)
                if child is None:
                    child = Node()
                    node.dyn.append((regex, child))
                node = child
            else:
                child = node.static.get(seg)
                if child is None:
                    child = Node()
                    node.static[seg] = child
                node = child
        node.indices.append(index)

    def match_all(self, path: str) -> list[int]:
        out = list(self.always)
        self._walk(self.root, path.lstrip("/"), out)
        out.sort()
        return out

    def _walk(self, node: Node, rest: str, out: list[int]) -> None:
        seg, slash, tail = rest.partition("/")
        last = not slash

        if last:
            child = node.static.get(seg)
            if child is not None:
                out.extend(child.indices)
            if seg and node.param is not None:
                out.extend(node.param.indices)
            for regex, child in node.dyn:
                if regex.match(seg):
                    out.extend(child.indices)
        else:
            child = node.static.get(seg)
            if child is not None:
                self._walk(child, tail, out)
            if seg and node.param is not None:
                self._walk(node.param, tail, out)
            for regex, child in node.dyn:
                if regex.match(seg):
                    self._walk(child, tail, out)
        out.extend(node.path_indices)
