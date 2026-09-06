from __future__ import annotations

import os
import re
from collections.abc import Sequence
from time import perf_counter

import anyio

try:
    from opentelemetry import metrics, propagate, trace
    from opentelemetry.trace import SpanKind, Status, StatusCode
except ImportError:  # pragma: no cover
    raise ImportError("The `opentelemetry-api` package is required to use `OpenTelemetryMiddleware`.") from None

from starlette import __version__
from starlette.datastructures import URL
from starlette.routing import Mount
from starlette.types import ASGIApp, Message, Receive, Scope, Send

HTTP_DURATION_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10)


class OpenTelemetryMiddleware:
    """Create OpenTelemetry server spans and metrics for incoming HTTP requests.

    Extract trace context from request headers and name spans using route templates.
    Record `http.server.request.duration` in seconds, including background tasks.
    Tracing and metrics work independently. Body sizes count complete ASGI bodies
    without buffering or draining requests. Unknown metric methods use `_OTHER`.
    Skip non-HTTP scopes and excluded URLs; nested instances emit telemetry once.

    Resolve None options once at construction from the listed environment variables
    in order, then the default. Explicit False, "", and [] override the environment.
    Boolean environment values accept true, false, 1, and 0, ignoring case.

    Args:
        app: The ASGI application to wrap.
        excluded_urls: Regular expressions matched against the full request URL.
            Pass a comma-separated string or a sequence. Resolve None from
            `OTEL_PYTHON_STARLETTE_EXCLUDED_URLS`, then `OTEL_PYTHON_EXCLUDED_URLS`.
            By default, exclude no URLs.
        tracer_provider: Optional tracer provider. If omitted, use the global tracer provider.
        meter_provider: Optional meter provider. If omitted, use the global meter provider.
        record_active_requests: Enable `http.server.active_requests`. Resolve None
            from `OTEL_PYTHON_STARLETTE_RECORD_ACTIVE_REQUESTS`. Defaults to False.
        record_body_sizes: Enable `http.server.request.body.size` and
            `http.server.response.body.size` in bytes. Resolve None from
            `OTEL_PYTHON_STARLETTE_RECORD_BODY_SIZES`. Defaults to False.
        known_methods: Known HTTP methods for metric labels, as a comma-separated
            string or sequence. Resolve None from `OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS`.
            Defaults to CONNECT, DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT, QUERY, TRACE.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        excluded_urls: str | Sequence[str] | None = None,
        tracer_provider: trace.TracerProvider | None = None,
        meter_provider: metrics.MeterProvider | None = None,
        record_active_requests: bool | None = None,
        record_body_sizes: bool | None = None,
        known_methods: str | Sequence[str] | None = None,
    ) -> None:
        self.app = app
        if excluded_urls is None:
            excluded_urls = os.environ.get(
                "OTEL_PYTHON_STARLETTE_EXCLUDED_URLS", os.environ.get("OTEL_PYTHON_EXCLUDED_URLS", "")
            )
        if isinstance(excluded_urls, str):
            excluded_urls = [pattern.strip() for pattern in excluded_urls.split(",")] if excluded_urls else ()
        self._excluded_urls = tuple(re.compile(pattern) for pattern in excluded_urls)
        if record_active_requests is None:
            value = os.environ.get("OTEL_PYTHON_STARLETTE_RECORD_ACTIVE_REQUESTS", "false").lower()
            if value not in ("true", "false", "1", "0"):
                raise ValueError("OTEL_PYTHON_STARLETTE_RECORD_ACTIVE_REQUESTS must be true, false, 1, or 0.")
            record_active_requests = value in ("true", "1")
        if record_body_sizes is None:
            value = os.environ.get("OTEL_PYTHON_STARLETTE_RECORD_BODY_SIZES", "false").lower()
            if value not in ("true", "false", "1", "0"):
                raise ValueError("OTEL_PYTHON_STARLETTE_RECORD_BODY_SIZES must be true, false, 1, or 0.")
            record_body_sizes = value in ("true", "1")
        if known_methods is None:
            known_methods = os.environ.get(
                "OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS", "CONNECT,DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT,QUERY,TRACE"
            )
        if isinstance(known_methods, str):
            known_methods = [method.strip() for method in known_methods.split(",")] if known_methods else ()
        self._known_methods = set(known_methods)
        self._tracer_provider = tracer_provider if tracer_provider is not None else trace.get_tracer_provider()
        provider = meter_provider if meter_provider is not None else metrics.get_meter_provider()
        meter = provider.get_meter("starlette", __version__)
        self._duration = meter.create_histogram(
            "http.server.request.duration",
            unit="s",
            description="Duration of HTTP server requests.",
            explicit_bucket_boundaries_advisory=HTTP_DURATION_BUCKETS,
        )
        self._active_requests = (
            meter.create_up_down_counter(
                "http.server.active_requests", unit="{request}", description="Number of active HTTP server requests."
            )
            if record_active_requests
            else None
        )
        self._request_body_size = (
            meter.create_histogram(
                "http.server.request.body.size", unit="By", description="Size of HTTP request bodies."
            )
            if record_body_sizes
            else None
        )
        self._response_body_size = (
            meter.create_histogram(
                "http.server.response.body.size", unit="By", description="Size of HTTP response bodies."
            )
            if record_body_sizes
            else None
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("starlette.opentelemetry"):
            return await self.app(scope, receive, send)

        scope["starlette.opentelemetry"] = True
        try:
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

            active_attributes: dict[str, str | int] = {
                "http.request.method": method if method in self._known_methods else "_OTHER",
                "url.scheme": attributes["url.scheme"],
            }
            metric_attributes = active_attributes.copy()
            if "network.protocol.version" in attributes:
                metric_attributes["network.protocol.version"] = attributes["network.protocol.version"]
            request_size = response_size = 0
            request_complete = response_complete = False

            with self._tracer_provider.get_tracer("starlette", __version__).start_as_current_span(
                method,
                context=propagate.extract(headers),
                kind=SpanKind.SERVER,
                attributes=attributes,
            ) as span:

                async def receive_with_telemetry() -> Message:
                    nonlocal request_size, request_complete
                    message = await receive()
                    if message["type"] == "http.request":
                        request_size += len(message.get("body", b""))
                        request_complete = not message.get("more_body", False)
                    return message

                async def send_with_telemetry(message: Message) -> None:
                    nonlocal response_size, response_complete
                    if message["type"] == "http.response.start":
                        status_code = message["status"]
                        span.set_attribute("http.response.status_code", status_code)
                        if status_code >= 500:
                            span.set_attribute("error.type", str(status_code))
                            span.set_status(Status(StatusCode.ERROR))
                    await send(message)
                    if message["type"] == "http.response.start":
                        metric_attributes["http.response.status_code"] = message["status"]
                        if message["status"] >= 500:
                            metric_attributes["error.type"] = str(message["status"])
                    elif message["type"] == "http.response.body":
                        response_size += 0 if method == "HEAD" else len(message.get("body", b""))
                        response_complete = not message.get("more_body", False)

                start_time = perf_counter()
                if self._active_requests is not None:
                    self._active_requests.add(1, active_attributes)
                try:
                    await self.app(
                        scope,
                        receive_with_telemetry if self._request_body_size is not None else receive,
                        send_with_telemetry,
                    )
                except (Exception, anyio.get_cancelled_exc_class()) as exc:
                    metric_attributes["error.type"] = type(exc).__qualname__
                    if isinstance(exc, Exception):
                        span.set_attribute("error.type", type(exc).__qualname__)
                    raise
                finally:
                    duration = perf_counter() - start_time
                    if self._active_requests is not None:
                        self._active_requests.add(-1, active_attributes)
                    route = scope.get("route")
                    root_path = scope.get("root_path_template", scope.get("root_path", ""))
                    route_path = None
                    if isinstance(route, Mount):
                        route_path = root_path or "/"
                    else:
                        path_format = getattr(route, "path_format", None)
                        if isinstance(path_format, str):
                            route_path = root_path.rstrip("/") + path_format or "/"
                    if route_path is not None:
                        span.update_name(f"{method} {route_path}")
                        span.set_attribute("http.route", route_path)
                        metric_attributes["http.route"] = route_path
                    self._duration.record(duration, metric_attributes)
                    if self._request_body_size is not None and request_complete:
                        self._request_body_size.record(request_size, metric_attributes)
                    if self._response_body_size is not None and response_complete:
                        self._response_body_size.record(response_size, metric_attributes)
        finally:
            del scope["starlette.opentelemetry"]
