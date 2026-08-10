from __future__ import annotations

from opentelemetry import propagate, trace
from opentelemetry.trace import SpanKind, Status, StatusCode

from starlette import __version__
from starlette.datastructures import URL
from starlette.routing import Mount
from starlette.types import ASGIApp, Message, Receive, Scope, Send

_KNOWN_HTTP_METHODS = {"CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"}


class OpenTelemetryMiddleware:
    """Create OpenTelemetry server spans for incoming HTTP requests."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("starlette.opentelemetry"):
            return await self.app(scope, receive, send)

        tracer_provider = trace.get_tracer_provider()
        if isinstance(tracer_provider, (trace.NoOpTracerProvider, trace.ProxyTracerProvider)):
            return await self.app(scope, receive, send)

        original_method = scope.get("method", "")
        method = original_method.upper()
        if method in _KNOWN_HTTP_METHODS:
            span_method = attribute_method = method
        else:
            span_method, attribute_method = "HTTP", "_OTHER"

        url = URL(scope=scope)
        attributes: dict[str, str | int] = {
            "http.request.method": attribute_method,
            "url.path": scope.get("path", ""),
            "url.scheme": scope.get("scheme", "http"),
        }
        if attribute_method == "_OTHER" or original_method != attribute_method:
            attributes["http.request.method_original"] = original_method
        if url.query:
            attributes["url.query"] = url.query
        if url.hostname is not None:
            attributes["server.address"] = url.hostname
        if url.port is not None:
            attributes["server.port"] = url.port
        if scope.get("http_version"):
            attributes["network.protocol.version"] = scope["http_version"]
        if scope.get("client") is not None:
            attributes["client.address"] = scope["client"][0]

        headers: dict[str, list[str]] = {}
        for name, value in scope.get("headers", []):
            headers.setdefault(name.decode("latin-1").lower(), []).append(value.decode("latin-1"))

        scope["starlette.opentelemetry"] = True

        try:
            with tracer_provider.get_tracer("starlette", __version__).start_as_current_span(
                span_method,
                context=propagate.extract(headers),
                kind=SpanKind.SERVER,
                attributes=attributes,
            ) as span:

                async def send_with_telemetry(message: Message) -> None:
                    if message["type"] == "http.response.start":
                        status_code = message["status"]
                        span.set_attribute("http.response.status_code", status_code)
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
                        span.update_name(f"{span_method} {route_path}")
                        span.set_attribute("http.route", route_path)
        finally:
            del scope["starlette.opentelemetry"]
