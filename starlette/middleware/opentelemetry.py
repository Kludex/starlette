from __future__ import annotations

from contextvars import ContextVar

from opentelemetry import propagate, trace
from opentelemetry.propagators.textmap import Getter
from opentelemetry.trace import Span, SpanKind, Status, StatusCode

from starlette import __version__
from starlette.datastructures import URL
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_KNOWN_HTTP_METHODS = {"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}
_tracing_request: ContextVar[bool] = ContextVar("starlette_tracing_request", default=False)


class _ScopeGetter(Getter[Scope]):
    def get(self, carrier: Scope, key: str) -> list[str] | None:
        key = key.lower()
        values = [
            value.decode("latin-1")
            for name, value in carrier.get("headers", [])
            if name.decode("latin-1").lower() == key
        ]
        return values or None

    def keys(self, carrier: Scope) -> list[str]:
        return [name.decode("latin-1") for name, _ in carrier.get("headers", [])]


_scope_getter = _ScopeGetter()


def _get_method(scope: Scope) -> tuple[str, str]:
    original = scope.get("method", "")
    method = original.upper()
    if method in _KNOWN_HTTP_METHODS:
        return method, method
    return "HTTP", "_OTHER"


def _get_attributes(scope: Scope, method: str) -> dict[str, str | int]:
    url = URL(scope=scope)
    attributes: dict[str, str | int] = {
        "http.request.method": method,
        "url.path": scope.get("path", ""),
        "url.scheme": scope.get("scheme", "http"),
    }

    original_method = scope.get("method", "")
    if method == "_OTHER" or original_method != method:
        attributes["http.request.method_original"] = original_method
    if url.query:
        attributes["url.query"] = url.query
    if url.hostname is not None:
        attributes["server.address"] = url.hostname
    if url.port is not None:
        attributes["server.port"] = url.port

    http_version = scope.get("http_version")
    if http_version:
        attributes["network.protocol.version"] = http_version
    client = scope.get("client")
    if client is not None:
        attributes["client.address"] = client[0]
    return attributes


def _set_response_status(span: Span, status_code: int) -> None:
    span.set_attribute("http.response.status_code", status_code)
    if status_code >= 500:
        span.set_attribute("error.type", str(status_code))
        span.set_status(Status(StatusCode.ERROR))


def _set_route(span: Span, scope: Scope, method: str) -> None:
    route_path = scope.get("starlette.route_path")
    if isinstance(route_path, str):
        span.update_name(f"{method} {route_path}")
        span.set_attribute("http.route", route_path)


class _OpenTelemetryMiddleware:
    """Create OpenTelemetry server spans for incoming HTTP requests."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or _tracing_request.get():
            await self.app(scope, receive, send)
            return

        tracer_provider = trace.get_tracer_provider()
        if isinstance(tracer_provider, (trace.NoOpTracerProvider, trace.ProxyTracerProvider)):
            await self.app(scope, receive, send)
            return

        tracer = tracer_provider.get_tracer("starlette", __version__)
        span_method, attribute_method = _get_method(scope)
        attributes = _get_attributes(scope, attribute_method)
        parent_context = propagate.extract(scope, getter=_scope_getter)
        token = _tracing_request.set(True)

        try:
            with tracer.start_as_current_span(
                span_method,
                context=parent_context,
                kind=SpanKind.SERVER,
                attributes=attributes,
            ) as span:

                async def send_with_telemetry(message: Message) -> None:
                    if message["type"] == "http.response.start":
                        _set_route(span, scope, span_method)
                        _set_response_status(span, message["status"])
                    await send(message)

                try:
                    await self.app(scope, receive, send_with_telemetry)
                except Exception as exc:
                    _set_route(span, scope, span_method)
                    span.set_attribute("error.type", type(exc).__qualname__)
                    raise
                finally:
                    _set_route(span, scope, span_method)
        finally:
            _tracing_request.reset(token)
