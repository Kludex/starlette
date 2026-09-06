from __future__ import annotations

import re
from collections.abc import Sequence

try:
    from opentelemetry import metrics, propagate, trace
    from opentelemetry.trace import SpanKind, Status, StatusCode
except ImportError:  # pragma: no cover
    raise ImportError("The `opentelemetry-api` package is required to use `OpenTelemetryMiddleware`.") from None

from starlette import __version__
from starlette.datastructures import URL
from starlette.middleware._opentelemetry import HTTPMetricsResponder, get_route_template
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class OpenTelemetryMiddleware:
    """Create OpenTelemetry server spans and metrics for incoming HTTP requests.

    Extract distributed trace context from request headers and name server spans
    using the matched route template. Record `http.server.request.duration` in
    seconds, including the application's background tasks. Tracing and metrics
    work independently; a no-op provider disables only its own signal.

    Body sizes count bytes in complete ASGI bodies without buffering or draining
    unread requests. Metric methods use `_OTHER` for unknown methods. Set
    `OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS` to override the known method list.

    Skip non-HTTP scopes and excluded URLs. Multiple native middleware instances
    on the same request emit telemetry once. Your application configures exporters
    and owns provider shutdown. Global providers can be configured after the app.

    Args:
        app: The ASGI application to wrap.
        excluded_urls: Regular expressions matched against the full request URL.
            Pass a comma-separated string or a sequence. By default, exclude no URLs.
        tracer_provider: Optional tracer provider. If omitted, use the global tracer provider.
        meter_provider: Optional meter provider. If omitted, use the global meter provider.
        record_active_requests: Enable `http.server.active_requests`. Defaults to False.
        record_body_sizes: Enable `http.server.request.body.size` and
            `http.server.response.body.size` in bytes. Defaults to False.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        excluded_urls: str | Sequence[str] = (),
        tracer_provider: trace.TracerProvider | None = None,
        meter_provider: metrics.MeterProvider | None = None,
        record_active_requests: bool = False,
        record_body_sizes: bool = False,
    ) -> None:
        self.app = app
        if isinstance(excluded_urls, str):
            excluded_urls = [pattern.strip() for pattern in excluded_urls.split(",")] if excluded_urls else ()
        patterns = tuple(re.compile(pattern) for pattern in excluded_urls)
        metrics_app = HTTPMetricsResponder(app, meter_provider, record_active_requests, record_body_sizes)
        self._responder = OpenTelemetryResponder(app, patterns, tracer_provider, metrics_app)

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
        tracer_provider: trace.TracerProvider | None,
        metrics_app: ASGIApp,
    ) -> None:
        self.app = app
        self._excluded_urls = excluded_urls
        self._tracer_provider = tracer_provider or trace.get_tracer_provider()
        self._metrics_app = metrics_app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        tracer_provider = self._tracer_provider
        url = URL(scope=scope)
        if any(pattern.search(str(url)) for pattern in self._excluded_urls):
            return await self.app(scope, receive, send)

        original_method = scope.get("method", "")
        method = original_method.upper()

        headers: dict[str, list[str]] = {}
        for name, value in scope.get("headers", []):
            headers.setdefault(name.decode("latin-1").lower(), []).append(value.decode("latin-1"))

        attributes: dict[str, str | int] = {
            "http.request.method": method,
            "url.path": scope.get("path", ""),
            "url.scheme": scope.get("scheme", "http"),
        }
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
                    if status_code >= 500:
                        span.set_attribute("error.type", str(status_code))
                        span.set_status(Status(StatusCode.ERROR))
                await send(message)

            try:
                await self._metrics_app(scope, receive, send_with_telemetry)
            except Exception as exc:
                span.set_attribute("error.type", type(exc).__qualname__)
                raise
            finally:
                route_path = get_route_template(scope)
                if route_path is not None:
                    span.update_name(f"{method} {route_path}")
                    span.set_attribute("http.route", route_path)
