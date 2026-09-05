from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Literal

try:
    from opentelemetry import propagate, trace
    from opentelemetry.trace import SpanKind, Status, StatusCode
except ImportError:  # pragma: no cover
    raise ImportError("The `opentelemetry-api` package is required to use `OpenTelemetryMiddleware`.") from None

from starlette import __version__
from starlette.datastructures import URL
from starlette.routing import Mount
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class OpenTelemetryMiddleware:
    """Create OpenTelemetry server spans for incoming HTTP requests."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        excluded_urls: str | Sequence[str] = (),
        capture_headers: bool | str | Sequence[str] = False,
        sanitize_headers: str | Sequence[str] = (),
    ) -> None:
        self.app = app
        if isinstance(excluded_urls, str):
            excluded_urls = [pattern.strip() for pattern in excluded_urls.split(",")] if excluded_urls else ()
        patterns = tuple(re.compile(pattern) for pattern in excluded_urls)
        header_capture = _HeaderCapture(capture_headers, sanitize_headers)
        self._responder = OpenTelemetryResponder(app, patterns, header_capture)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("starlette.opentelemetry"):
            return await self.app(scope, receive, send)

        scope["starlette.opentelemetry"] = True
        try:
            await self._responder(scope, receive, send)
        finally:
            del scope["starlette.opentelemetry"]


class OpenTelemetryResponder:
    def __init__(
        self,
        app: ASGIApp,
        excluded_urls: tuple[re.Pattern[str], ...],
        header_capture: _HeaderCapture | None = None,
    ) -> None:
        self.app = app
        self._excluded_urls = excluded_urls
        self._header_capture = _HeaderCapture(False, ()) if header_capture is None else header_capture

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        tracer_provider = trace.get_tracer_provider()
        if isinstance(tracer_provider, (trace.NoOpTracerProvider, trace.ProxyTracerProvider)):
            return await self.app(scope, receive, send)

        url = URL(scope=scope)
        if any(pattern.search(str(url)) for pattern in self._excluded_urls):
            return await self.app(scope, receive, send)

        original_method = scope.get("method", "")
        method = original_method.upper()

        headers = _decode_headers(scope.get("headers", []))

        attributes: dict[str, str | int | list[str]] = {
            "http.request.method": method,
            "url.path": scope.get("path", ""),
            "url.scheme": scope.get("scheme", "http"),
        }
        attributes.update(self._header_capture.attributes(headers, "request"))
        if original_method != method:
            attributes["http.request.method_original"] = original_method
        if url.query:
            attributes["url.query"] = url.query
        if url.hostname is not None:
            attributes["server.address"] = url.hostname
            server = scope.get("server")
            server_port = url.port if url.port is not None else server[1] if server is not None else None
            if server_port is not None:
                attributes["server.port"] = server_port
        if scope.get("http_version"):
            attributes["network.protocol.version"] = scope["http_version"]
        if scope.get("client") is not None:
            attributes["client.address"] = scope["client"][0]
        if headers.get("user-agent"):
            attributes["user_agent.original"] = headers["user-agent"][0]

        with tracer_provider.get_tracer("starlette", __version__).start_as_current_span(
            method,
            context=propagate.extract(headers),
            kind=SpanKind.SERVER,
            attributes=attributes,
        ) as span:

            async def send_with_telemetry(message: Message) -> None:
                if message["type"] == "http.response.start":
                    status_code = message["status"]
                    span.set_attribute("http.response.status_code", status_code)
                    if self._header_capture:
                        response_headers = _decode_headers(message.get("headers", []))
                        span.set_attributes(self._header_capture.attributes(response_headers, "response"))
                    if status_code >= 500:
                        span.set_attribute("error.type", str(status_code))
                        span.set_status(Status(StatusCode.ERROR))
                await send(message)

            try:
                await self.app(scope, receive, send_with_telemetry)
            except Exception as exc:
                span.set_attribute("error.type", type(exc).__qualname__)
                raise
            finally:
                route = scope.get("route")
                if isinstance(route, Mount):
                    route_path = scope.get("root_path") or "/"
                else:
                    path_format = getattr(route, "path_format", None)
                    route_path = (
                        scope.get("root_path", "").rstrip("/") + path_format or "/"
                        if isinstance(path_format, str)
                        else None
                    )
                if route_path is not None:
                    span.update_name(f"{method} {route_path}")
                    span.set_attribute("http.route", route_path)


class _HeaderCapture:
    def __init__(
        self,
        capture_headers: bool | str | Sequence[str],
        sanitize_headers: str | Sequence[str],
    ) -> None:
        self._capture_patterns = self._compile_patterns(capture_headers)
        self._sanitize_patterns = self._compile_patterns(sanitize_headers)

    def __bool__(self) -> bool:
        return bool(self._capture_patterns)

    def attributes(
        self,
        headers: dict[str, list[str]],
        direction: Literal["request", "response"],
    ) -> dict[str, list[str]]:
        return {
            f"http.{direction}.header.{name}": (
                ["[REDACTED]"] * len(values)
                if any(pattern.search(name) for pattern in self._sanitize_patterns)
                else values
            )
            for name, values in headers.items()
            if any(pattern.fullmatch(name) for pattern in self._capture_patterns)
        }

    @staticmethod
    def _compile_patterns(patterns: bool | str | Sequence[str]) -> tuple[re.Pattern[str], ...]:
        if patterns is True:
            patterns = (".*",)
        elif patterns is False:
            patterns = ()
        elif isinstance(patterns, str):
            patterns = (patterns,)
        return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


def _decode_headers(raw_headers: Iterable[tuple[bytes, bytes]]) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    for name, value in raw_headers:
        decoded_name = name.decode("latin-1").lower()
        headers.setdefault(decoded_name, []).append(value.decode("latin-1"))
    return headers
