from __future__ import annotations

import importlib.util
from collections.abc import Generator

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from starlette.applications import Starlette, _wrap_with_opentelemetry
from starlette.middleware import Middleware, opentelemetry as opentelemetry_middleware
from starlette.middleware.opentelemetry import _get_attributes, _OpenTelemetryMiddleware, _scope_getter
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import BaseRoute, Host, Match, Mount, Route, Router, WebSocketRoute
from starlette.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocket
from tests.types import TestClientFactory


@pytest.fixture
def tracer_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[TracerProvider, InMemorySpanExporter], None, None]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: provider)
    yield provider, exporter
    provider.shutdown()


def get_span(exporter: InMemorySpanExporter) -> ReadableSpan:
    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    return spans[0]


def homepage(request: Request) -> PlainTextResponse:
    return PlainTextResponse("Hello, world!")


def test_missing_opentelemetry_dependency_does_not_wrap_app(monkeypatch: pytest.MonkeyPatch) -> None:
    app = PlainTextResponse("Hello")
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)

    assert _wrap_with_opentelemetry(app) is app


def test_noop_provider_skips_instrumentation(
    monkeypatch: pytest.MonkeyPatch,
    test_client_factory: TestClientFactory,
) -> None:
    monkeypatch.setattr(trace, "get_tracer_provider", trace.NoOpTracerProvider)
    monkeypatch.setattr(
        opentelemetry_middleware,
        "_set_route",
        lambda span, scope, method: pytest.fail("Route instrumentation should be skipped without a tracer provider"),
    )

    assert test_client_factory(Starlette(routes=[Route("/", homepage)])).get("/").status_code == 200


def test_provider_configured_after_middleware_stack_is_built(
    monkeypatch: pytest.MonkeyPatch,
    test_client_factory: TestClientFactory,
) -> None:
    app = Starlette(routes=[Route("/", homepage)])
    app.middleware_stack = app.build_middleware_stack()
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: provider)

    try:
        assert test_client_factory(app).get("/").status_code == 200
        assert get_span(exporter).name == "GET /"
    finally:
        provider.shutdown()


def test_http_span_uses_route_and_semantic_attributes(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    app = Starlette(routes=[Route("/users/{username}", homepage)])

    response = test_client_factory(app).get("/users/marcelo?format=json")

    assert response.status_code == 200
    span = get_span(exporter)
    assert span.name == "GET /users/{username}"
    assert span.kind == SpanKind.SERVER
    assert span.attributes is not None
    assert span.attributes["http.request.method"] == "GET"
    assert span.attributes["http.response.status_code"] == 200
    assert span.attributes["http.route"] == "/users/{username}"
    assert span.attributes["url.path"] == "/users/marcelo"
    assert span.attributes["url.query"] == "format=json"
    assert span.attributes["url.scheme"] == "http"
    assert span.attributes["server.address"] == "testserver"
    assert span.attributes["network.protocol.version"] == "1.1"
    assert span.status.status_code == StatusCode.UNSET


def test_http_span_uses_nested_route(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    routes = [Mount("/api", app=Router([Route("/users/{username}", homepage)]))]
    app = Starlette(routes=routes)

    assert test_client_factory(app).get("/api/users/marcelo").status_code == 200

    span = get_span(exporter)
    assert span.name == "GET /api/users/{username}"
    assert span.attributes is not None
    assert span.attributes["http.route"] == "/api/users/{username}"


def test_mounted_starlette_app_does_not_create_duplicate_span(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    mounted_app = Starlette(routes=[Route("/users/{username}", homepage)])
    app = Starlette(routes=[Mount("/api", app=mounted_app)])

    assert test_client_factory(app).get("/api/users/marcelo").status_code == 200

    span = get_span(exporter)
    assert span.name == "GET /api/users/{username}"


def test_instrumentation_uses_actual_route_match_once(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider

    class CountingRoute(Route):
        match_count = 0

        def matches(self, scope: Scope) -> tuple[Match, Scope]:
            self.match_count += 1
            return super().matches(scope)

    route = CountingRoute("/users/{username}", homepage)
    app = Starlette(routes=[route])

    assert test_client_factory(app).get("/users/marcelo").status_code == 200

    assert route.match_count == 1
    assert get_span(exporter).name == "GET /users/{username}"


def test_route_is_resolved_after_path_rewriting_middleware(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider

    class RewritePathMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            scope["path"] = "/target"
            await self.app(scope, receive, send)

    app = Starlette(
        routes=[Route("/target", homepage)],
        middleware=[Middleware(RewritePathMiddleware)],
    )

    assert test_client_factory(app).get("/source").status_code == 200

    span = get_span(exporter)
    assert span.name == "GET /target"
    assert span.attributes is not None
    assert span.attributes["http.route"] == "/target"


def test_http_span_uses_mount_path_when_child_does_not_resolve(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    routes = [Mount("/api", app=Router([Route("/users/{username}", homepage)]))]
    app = Starlette(routes=routes)

    assert test_client_factory(app).get("/api/missing").status_code == 404

    span = get_span(exporter)
    assert span.name == "GET /api"
    assert span.attributes is not None
    assert span.attributes["http.route"] == "/api"


def test_http_span_uses_mount_path_for_raw_asgi_app(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    routes = [Mount("/api", app=PlainTextResponse("mounted"))]
    app = Starlette(routes=routes)

    assert test_client_factory(app).get("/api/example").text == "mounted"

    span = get_span(exporter)
    assert span.name == "GET /api"
    assert span.attributes is not None
    assert span.attributes["http.route"] == "/api"


def test_http_span_resolves_host_route(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    routes = [Host("testserver", app=Router([Route("/users/{username}", homepage)]))]
    app = Starlette(routes=routes)

    assert test_client_factory(app).get("/users/marcelo").status_code == 200

    span = get_span(exporter)
    assert span.name == "GET /users/{username}"
    assert span.attributes is not None
    assert span.attributes["http.route"] == "/users/{username}"


def test_http_span_omits_route_for_hosted_raw_asgi_app(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    routes = [Host("testserver", app=PlainTextResponse("hosted"))]
    app = Starlette(routes=routes)

    assert test_client_factory(app).get("/").text == "hosted"

    span = get_span(exporter)
    assert span.name == "GET"
    assert span.attributes is not None
    assert "http.route" not in span.attributes


def test_http_span_omits_route_for_custom_route(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider

    class CustomRoute(BaseRoute):
        def matches(self, scope: Scope) -> tuple[Match, Scope]:
            return Match.FULL, {}

        async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
            await PlainTextResponse("custom")(scope, receive, send)

    app = Starlette(routes=[CustomRoute()])

    assert test_client_factory(app).get("/anything").text == "custom"

    span = get_span(exporter)
    assert span.name == "GET"
    assert span.attributes is not None
    assert "http.route" not in span.attributes


def test_http_span_extracts_remote_parent(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    app = Starlette(routes=[Route("/", homepage)])
    trace_id = "0af7651916cd43dd8448eb211c80319c"
    parent_span_id = "b7ad6b7169203331"

    response = test_client_factory(app).get("/", headers={"traceparent": f"00-{trace_id}-{parent_span_id}-01"})

    assert response.status_code == 200
    span = get_span(exporter)
    assert span.context is not None
    assert span.parent is not None
    assert span.context.trace_id == int(trace_id, 16)
    assert span.parent.span_id == int(parent_span_id, 16)
    assert span.parent.is_remote


def test_http_span_records_server_error(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider

    def error(request: Request) -> PlainTextResponse:
        raise RuntimeError("Oh no")

    app = Starlette(routes=[Route("/error", error)])

    response = test_client_factory(app, raise_server_exceptions=False).get("/error")

    assert response.status_code == 500
    span = get_span(exporter)
    assert span.attributes is not None
    assert span.attributes["error.type"] == "RuntimeError"
    assert span.status.status_code == StatusCode.ERROR
    assert [event.name for event in span.events] == ["exception"]


def test_http_span_records_error_response(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    app = Starlette(routes=[Route("/", PlainTextResponse("Unavailable", status_code=503))])

    assert test_client_factory(app).get("/").status_code == 503

    span = get_span(exporter)
    assert span.attributes is not None
    assert span.attributes["error.type"] == "503"
    assert span.status.status_code == StatusCode.ERROR


def test_http_span_sanitizes_unknown_method(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    app = Starlette(routes=[Route("/", PlainTextResponse("OK"))])

    assert test_client_factory(app).request("CUSTOM", "/").status_code == 200

    span = get_span(exporter)
    assert span.name == "HTTP /"
    assert span.attributes is not None
    assert span.attributes["http.request.method"] == "_OTHER"
    assert span.attributes["http.request.method_original"] == "CUSTOM"


def test_http_span_without_starlette_app(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    app = _OpenTelemetryMiddleware(PlainTextResponse("raw"))

    assert test_client_factory(app).get("/raw").text == "raw"

    span = get_span(exporter)
    assert span.name == "GET"
    assert span.attributes is not None
    assert "http.route" not in span.attributes


def test_scope_helpers_cover_optional_values() -> None:
    scope: Scope = {
        "type": "http",
        "method": "get",
        "path": "/",
        "query_string": b"",
        "headers": [(b"x-example", b"one"), (b"X-Example", b"two")],
        "server": ("example.com", 8000),
    }

    assert _scope_getter.get(scope, "X-EXAMPLE") == ["one", "two"]
    assert _scope_getter.get(scope, "missing") is None
    assert _scope_getter.keys(scope) == ["x-example", "X-Example"]
    assert _get_attributes(scope, "GET") == {
        "http.request.method": "GET",
        "http.request.method_original": "get",
        "url.path": "/",
        "url.scheme": "http",
        "server.address": "example.com",
        "server.port": 8000,
    }

    scope["server"] = None
    assert "server.address" not in _get_attributes(scope, "GET")


def test_non_http_scopes_are_not_traced(
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider

    async def websocket_endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.close()

    app = Starlette(routes=[WebSocketRoute("/", websocket_endpoint)])

    with TestClient(app) as client:
        with client.websocket_connect("/"):
            pass

    assert exporter.get_finished_spans() == ()
