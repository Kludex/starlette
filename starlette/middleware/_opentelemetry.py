from __future__ import annotations

import os
from time import perf_counter

import anyio
from opentelemetry import metrics

from starlette import __version__
from starlette.routing import Mount
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class HTTPMetricsResponder:
    def __init__(
        self,
        app: ASGIApp,
        meter_provider: metrics.MeterProvider | None,
        record_active_requests: bool,
        record_body_sizes: bool,
    ) -> None:
        self.app = app
        provider = meter_provider if meter_provider is not None else metrics.get_meter_provider()
        meter = provider.get_meter("starlette", __version__)
        self.duration = meter.create_histogram(
            "http.server.request.duration",
            unit="s",
            description="Duration of HTTP server requests.",
            explicit_bucket_boundaries_advisory=(
                0.005,
                0.01,
                0.025,
                0.05,
                0.075,
                0.1,
                0.25,
                0.5,
                0.75,
                1,
                2.5,
                5,
                7.5,
                10,
            ),
        )
        self.active_requests = (
            meter.create_up_down_counter(
                "http.server.active_requests", unit="{request}", description="Number of active HTTP server requests."
            )
            if record_active_requests
            else None
        )
        self.request_body_size = (
            meter.create_histogram(
                "http.server.request.body.size", unit="By", description="Size of HTTP request bodies."
            )
            if record_body_sizes
            else None
        )
        self.response_body_size = (
            meter.create_histogram(
                "http.server.response.body.size", unit="By", description="Size of HTTP response bodies."
            )
            if record_body_sizes
            else None
        )
        self.known_methods = {
            method.strip()
            for method in os.environ.get(
                "OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS", "CONNECT,DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT,QUERY,TRACE"
            ).split(",")
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        method = scope.get("method", "").upper()
        active_attributes: dict[str, str | int] = {
            "http.request.method": method if method in self.known_methods else "_OTHER",
            "url.scheme": scope.get("scheme", "http"),
        }
        attributes = active_attributes.copy()
        if scope.get("http_version"):
            attributes["network.protocol.version"] = scope["http_version"]
        request_size = response_size = 0
        request_complete = response_complete = False

        async def receive_with_metrics() -> Message:
            nonlocal request_size, request_complete
            message = await receive()
            if message["type"] == "http.request":
                request_size += len(message.get("body", b""))
                request_complete = not message.get("more_body", False)
            return message

        async def send_with_metrics(message: Message) -> None:
            nonlocal response_size, response_complete
            await send(message)
            if message["type"] == "http.response.start":
                status_code = message["status"]
                attributes["http.response.status_code"] = status_code
                if status_code >= 500:
                    attributes["error.type"] = str(status_code)
            elif message["type"] == "http.response.body":
                response_size += 0 if method == "HEAD" else len(message.get("body", b""))
                response_complete = not message.get("more_body", False)

        start_time = perf_counter()
        if self.active_requests is not None:
            self.active_requests.add(1, active_attributes)
        try:
            await self.app(
                scope, receive_with_metrics if self.request_body_size is not None else receive, send_with_metrics
            )
        except (Exception, anyio.get_cancelled_exc_class()) as exc:
            attributes["error.type"] = type(exc).__qualname__
            raise
        finally:
            duration = perf_counter() - start_time
            if self.active_requests is not None:
                self.active_requests.add(-1, active_attributes)
            route_path = get_route_template(scope)
            if route_path is not None:
                attributes["http.route"] = route_path
            self.duration.record(duration, attributes)
            if self.request_body_size is not None and request_complete:
                self.request_body_size.record(request_size, attributes)
            if self.response_body_size is not None and response_complete:
                self.response_body_size.record(response_size, attributes)


def get_route_template(scope: Scope) -> str | None:
    route = scope.get("route")
    root_path = scope.get("root_path_template", scope.get("root_path", ""))
    if isinstance(route, Mount):
        return root_path or "/"
    path_format = getattr(route, "path_format", None)
    if isinstance(path_format, str):
        return root_path.rstrip("/") + path_format or "/"
    return None
