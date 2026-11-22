"""RFC 7239 ``Forwarded`` header normalization for Starlette.

When an ASGI application runs behind a reverse proxy that emits an RFC 7239
``Forwarded`` header (e.g. ``Forwarded: proto=https;host=edge.example.org``),
the outermost (first) element describes the client-facing request authority.
Starlette's ``Request.base_url`` / ``Request.url_for`` otherwise fall back to
``scope['server']``, which is the *internal* address, producing wrong absolute
URLs behind a proxy -- especially on sub-mounted routes.

Public API:
    _rfc7239_forwarded_nonce_9f4a(scope) -> scope copy with normalized authority
    parse_forwarded(header_value) -> dict[str, str]
    apply_forwarded(scope) -> scope copy
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "_rfc7239_forwarded_nonce_9f4a",
    "parse_forwarded",
    "apply_forwarded",
]


def _split_outside_quotes(value: str, sep: str = ",") -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escaped = False
    for ch in value:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\" and in_quotes:
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
            continue
        if ch == sep and not in_quotes:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        out: list[str] = []
        i = 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner):
                out.append(inner[i + 1])
                i += 2
            else:
                out.append(inner[i])
                i += 1
        return "".join(out)
    return value


def parse_forwarded(header_value: str) -> dict[str, str]:
    """Parse a ``Forwarded`` header, returning the FIRST (outermost) element.

    Per RFC 7239 §7.1 the first element is the one added by the closest
    client-facing proxy, so it is the one that reflects the origin authority.
    """
    if not header_value:
        return {}
    first = _split_outside_quotes(header_value)[0]
    result: dict[str, str] = {}
    for pair in _split_outside_quotes(first, sep=";"):
        if "=" not in pair:
            continue
        key, _, val = pair.partition("=")
        key = key.strip().lower()
        if not key:
            continue
        if key not in result:  # first occurrence wins
            result[key] = _unquote(val)
    return result


def _split_host_port(host: str) -> tuple[str, int | None]:
    if host.startswith("["):
        end = host.find("]")
        if end != -1:
            literal = host[: end + 1]
            rest = host[end + 1 :]
            if rest.startswith(":"):
                try:
                    return literal, int(rest[1:])
                except ValueError:
                    return literal, None
            return literal, None
    if host.count(":") == 1:
        h, _, p = host.partition(":")
        try:
            return h, int(p)
        except ValueError:
            return host, None
    return host, None


def _rfc7239_forwarded_nonce_9f4a(scope: dict[str, Any]) -> dict[str, Any]:
    """Normalize an ASGI ``scope`` against an RFC 7239 ``Forwarded`` header.

    Returns a *copy* of ``scope`` whose ``scheme``, ``server`` and ``Host``
    header reflect the client-facing authority described by the outermost
    ``Forwarded`` element. Returns the original scope unchanged (backward
    compatible no-op) when the header is absent or carries no useful fields.
    """
    headers = scope.get("headers") or []
    raw: str | None = None
    for name, value in headers:
        if isinstance(name, (bytes, bytearray)) and name.lower() == b"forwarded":
            try:
                raw = value.decode("latin-1")
            except Exception:
                raw = None
            break

    if not raw:
        return scope

    parsed = parse_forwarded(raw)
    if not parsed:
        return scope

    new_scope = dict(scope)

    proto = parsed.get("proto")
    if proto in ("http", "https"):
        new_scope["scheme"] = proto

    host = parsed.get("host")
    if host:
        name, port = _split_host_port(host)
        scheme = new_scope.get("scheme", scope.get("scheme", "http"))
        if port is None:
            port = 443 if scheme == "https" else 80
        new_scope["server"] = (name, port)

        # Keep the Host header consistent with the reconstructed authority.
        new_headers = []
        replaced = False
        for hname, hvalue in headers:
            if isinstance(hname, (bytes, bytearray)) and hname.lower() == b"host":
                new_headers.append((hname, host.encode("latin-1")))
                replaced = True
            else:
                new_headers.append((hname, hvalue))
        if not replaced:
            new_headers.append((b"host", host.encode("latin-1")))
        new_scope["headers"] = new_headers

    return new_scope


# Backwards-friendly alias.
apply_forwarded = _rfc7239_forwarded_nonce_9f4a
