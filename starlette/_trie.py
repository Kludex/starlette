from __future__ import annotations

import re
from re import Pattern

from starlette.convertors import (
    Convertor,
    FloatConvertor,
    IntegerConvertor,
    PathConvertor,
    StringConvertor,
    UUIDConvertor,
)

# Match parameters in URL paths, eg. '{param}', and '{param:int}'.
PARAM_REGEX = re.compile("{([a-zA-Z_][a-zA-Z0-9_]*)(:[a-zA-Z_][a-zA-Z0-9_]*)?}")

# Built-in convertors whose regex is known to stay inside a single path segment.
_SEGMENT_LOCAL_CONVERTORS = (StringConvertor, IntegerConvertor, FloatConvertor, UUIDConvertor)

# Escapes that cannot match a '/'. Anything else, including `\S`, `\D`, `\W` and
# numeric escapes such as `\x2f`, is treated as unknown.
_SAFE_ESCAPES = frozenset("dwsbBAZznrtfv")


def _escape_may_match_slash(escape: str) -> bool:
    if escape in _SAFE_ESCAPES:
        return False
    # `\/` is a literal slash, `\x2f` and `\1` are opaque, and an escaped
    # punctuation character is itself.
    return escape.isalnum() or escape == "/"


def _class_may_match_slash(body: str) -> bool:
    """Whether a character class body, the `...` of `[...]`, can match a '/'."""
    negated = body.startswith("^")
    if negated:
        body = body[1:]

    lists_slash = False
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            escape = body[index + 1 : index + 2]
            if escape == "/":
                lists_slash = True
            elif _escape_may_match_slash(escape):
                return True  # Unknown escape: do not try to reason about it.
            index += 2
            continue
        if body[index + 1 : index + 2] == "-" and index + 2 < len(body):
            if body[index + 2] == "\\":
                return True  # Escaped range bound: unknown.
            lists_slash = lists_slash or char <= "/" <= body[index + 2]
            index += 3
            continue
        lists_slash = lists_slash or char == "/"
        index += 1

    return not lists_slash if negated else lists_slash


def _pattern_may_match_slash(pattern: str) -> bool:
    """Conservatively decide whether a regex can match a '/'.

    A segment trie can only index a route when each of its segments stays inside a
    single path segment. Anything this cannot prove to be slash-free is reported as
    slash-capable, which costs a fast path but never a match.
    """
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            if _escape_may_match_slash(pattern[index + 1 : index + 2]):
                return True
            index += 2
            continue
        if char == "[":
            end = index + 1
            if pattern[end : end + 1] == "^":
                end += 1
            if pattern[end : end + 1] == "]":  # A leading ']' is a literal.
                end += 1
            while end < length and pattern[end] != "]":
                end += 2 if pattern[end] == "\\" else 1
            if end == length:
                return True  # Unbalanced class: not something to parse.
            if _class_may_match_slash(pattern[index + 1 : end]):
                return True
            index = end + 1
            continue
        if char in "./":
            # `.` matches '/' unless the pattern is compiled without DOTALL, which
            # is not something a convertor regex can be assumed to control.
            return True
        index += 1

    return False


def _may_match_slash(convertor: Convertor[object]) -> bool:
    if type(convertor) in _SEGMENT_LOCAL_CONVERTORS:
        return False
    return _pattern_may_match_slash(convertor.regex)


def _segment_regex(segment: str, convertors: dict[str, Convertor[object]]) -> Pattern[str]:
    parts = ["^"]
    index = 0
    for match in PARAM_REGEX.finditer(segment):
        parts.append(re.escape(segment[index : match.start()]))
        # Group the convertor regex so alternation keeps segment-local precedence,
        # the way the named group in `compile_path` does.
        parts.append(f"(?:{convertors[match.group(1)].regex})")
        index = match.end()
    parts.append(re.escape(segment[index:]))
    parts.append("$")
    return re.compile("".join(parts))


class Node:
    __slots__ = ("static", "param", "dynamic", "path_indices", "indices")

    def __init__(self) -> None:
        self.static: dict[str, Node] = {}
        self.param: Node | None = None
        self.dynamic: list[tuple[Pattern[str], Node]] = []
        # Routes ending in a `path` convertor: they match any remainder from here.
        self.path_indices: list[int] = []
        self.indices: list[int] = []


class RouteTrie:
    """A candidate-narrowing segment trie over route paths.

    `match_all()` returns a superset of the routes whose `path_regex` could match a
    path, in registration order. It never decides a match on its own: the caller
    still runs `BaseRoute.matches()` on every candidate.

    Segment patterns come from each route's own `param_convertors` rather than
    being re-parsed from the path, so custom convertors and the exact built-in
    regexes are honoured. Anything that cannot be indexed exactly, such as a
    segment that could span a '/', is registered as an always-candidate.
    """

    __slots__ = ("root", "always")

    def __init__(self) -> None:
        self.root = Node()
        self.always: list[int] = []

    def add_always(self, index: int) -> None:
        """Register a route that has to be checked for every path."""
        self.always.append(index)

    def add(self, index: int, path: str, convertors: dict[str, Convertor[object]]) -> None:
        """Index a route path, falling back to an always-candidate when needed."""
        node = self.root
        for segment in path[1:].split("/"):
            if "{" not in segment:
                child = node.static.get(segment)
                if child is None:
                    child = node.static[segment] = Node()
                node = child
                continue

            match = PARAM_REGEX.fullmatch(segment)
            if match is not None:
                convertor = convertors[match.group(1)]
                if type(convertor) is StringConvertor:
                    if node.param is None:
                        node.param = Node()
                    node = node.param
                    continue
                if type(convertor) is PathConvertor:
                    # Consumes the rest of the path, so the route ends here.
                    node.path_indices.append(index)
                    return

            if any(_may_match_slash(convertors[param.group(1)]) for param in PARAM_REGEX.finditer(segment)):
                # The segment can span a '/', which a per-segment trie cannot model.
                self.add_always(index)
                return

            regex = _segment_regex(segment, convertors)
            child = next((child for pattern, child in node.dynamic if pattern.pattern == regex.pattern), None)
            if child is None:
                child = Node()
                node.dynamic.append((regex, child))
            node = child

        node.indices.append(index)

    def match_all(self, path: str) -> list[int]:
        """Return the indices of every route that could match `path`, in order."""
        indices = list(self.always)
        self._walk(self.root, path[1:] if path.startswith("/") else path, indices)
        indices.sort()
        return indices

    def _walk(self, node: Node, rest: str, indices: list[int]) -> None:
        segment, slash, tail = rest.partition("/")

        if slash:
            child = node.static.get(segment)
            if child is not None:
                self._walk(child, tail, indices)
            if segment and node.param is not None:
                self._walk(node.param, tail, indices)
            for pattern, child in node.dynamic:
                if pattern.match(segment):
                    self._walk(child, tail, indices)
        else:
            child = node.static.get(segment)
            if child is not None:
                indices.extend(child.indices)
            if segment and node.param is not None:
                indices.extend(node.param.indices)
            for pattern, child in node.dynamic:
                if pattern.match(segment):
                    indices.extend(child.indices)

        # A `path` convertor registered here matches whatever is left, including
        # the empty string.
        indices.extend(node.path_indices)
