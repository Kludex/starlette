from __future__ import annotations

from collections.abc import Generator
from unittest.mock import AsyncMock

import httpx
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.opentelemetry import OpenTelemetryMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import BaseRoute, Host, Match, Mount, Route, Router, WebSocketRoute
from starlette.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send
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


def test_noop_provider_skips_instrumentation(
    monkeypatch: pytest.MonkeyPatch,
    test_client_factory: TestClientFactory,
) -> None:
    monkeypatch.setattr(trace, "get_tracer_provider", trace.NoOpTracerProvider)
    app = Starlette(routes=[Route("/", homepage)], middleware=[Middleware(OpenTelemetryMiddleware)])

    assert test_client_factory(app).get("/").status_code == 200


@pytest.mark.parametrize(
    ("excluded_urls", "excluded_paths"),
    [
        ([r"^http://testserver/health(?:\?.*)?$"], ("/health?full=true",)),
        (r"/health(?:\?.*)?$", ("/health?full=true",)),
        (r"/health$, /metrics$", ("/health", "/metrics")),
        ("", ()),
    ],
)
def test_excluded_urls(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
    excluded_urls: str | list[str],
    excluded_paths: tuple[str, ...],
) -> None:
    _, exporter = tracer_provider
    app = Starlette(
        routes=[Route("/", homepage), Route("/health", homepage), Route("/metrics", homepage)],
        middleware=[Middleware(OpenTelemetryMiddleware, excluded_urls=excluded_urls)],
    )
    client = test_client_factory(app)

    for path in excluded_paths:
        assert client.get(path).status_code == 200
    assert exporter.get_finished_spans() == ()
    assert client.get("/").status_code == 200
    assert get_span(exporter).name == "GET /"


def test_multiple_native_middlewares_do_not_create_duplicate_span(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    app = Starlette(
        routes=[Route("/", homepage)],
        middleware=[Middleware(OpenTelemetryMiddleware), Middleware(OpenTelemetryMiddleware)],
    )

    assert test_client_factory(app).get("/").status_code == 200
    assert get_span(exporter).name == "GET /"


def test_exclusion_propagates_to_nested_native_middleware(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    mounted_app = Starlette(
        routes=[Route("/health", homepage)],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )
    app = Starlette(
        routes=[Mount("/api", app=mounted_app)],
        middleware=[Middleware(OpenTelemetryMiddleware, excluded_urls=[r"/api/health$"])],
    )

    assert test_client_factory(app).get("/api/health").status_code == 200
    assert exporter.get_finished_spans() == ()


def test_provider_configured_after_middleware_stack_is_built(
    monkeypatch: pytest.MonkeyPatch,
    test_client_factory: TestClientFactory,
) -> None:
    app = Starlette(routes=[Route("/", homepage)], middleware=[Middleware(OpenTelemetryMiddleware)])
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
    app = Starlette(
        routes=[Route("/users/{username}", homepage)],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )

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
    assert span.attributes["server.port"] == 80
    assert span.attributes["network.protocol.version"] == "1.1"
    assert span.attributes["user_agent.original"] == "testclient"
    assert span.status.status_code == StatusCode.UNSET


def test_http_span_uses_nested_route(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    routes = [Mount("/api", app=Router([Route("/users/{username}", homepage)]))]
    app = Starlette(routes=routes, middleware=[Middleware(OpenTelemetryMiddleware)])

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
    mounted_app = Starlette(
        routes=[Route("/users/{username}", homepage)],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )
    app = Starlette(
        routes=[Mount("/api", app=mounted_app)],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )

    assert test_client_factory(app).get("/api/users/marcelo").status_code == 200

    span = get_span(exporter)
    assert span.name == "GET /api/users/{username}"


def test_nested_in_process_request_creates_its_own_span(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    inner_app = Starlette(
        routes=[Route("/inner", homepage)],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )

    async def call_inner(request: Request) -> PlainTextResponse:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=inner_app),
            base_url="http://inner",
        ) as client:
            response = await client.get("/inner")
        return PlainTextResponse(response.text)

    app = Starlette(
        routes=[Route("/outer", call_inner)],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )

    assert test_client_factory(app).get("/outer").status_code == 200
    spans = exporter.get_finished_spans()
    assert len(spans) == 2
    assert {span.name for span in spans} == {"GET /inner", "GET /outer"}


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
    app = Starlette(routes=[route], middleware=[Middleware(OpenTelemetryMiddleware)])

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
        middleware=[Middleware(OpenTelemetryMiddleware), Middleware(RewritePathMiddleware)],
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
    app = Starlette(routes=routes, middleware=[Middleware(OpenTelemetryMiddleware)])

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
    app = Starlette(routes=routes, middleware=[Middleware(OpenTelemetryMiddleware)])

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
    app = Starlette(routes=routes, middleware=[Middleware(OpenTelemetryMiddleware)])

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
    app = Starlette(routes=routes, middleware=[Middleware(OpenTelemetryMiddleware)])

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

    app = Starlette(routes=[CustomRoute()], middleware=[Middleware(OpenTelemetryMiddleware)])

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
    app = Starlette(routes=[Route("/", homepage)], middleware=[Middleware(OpenTelemetryMiddleware)])
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

    app = Starlette(routes=[Route("/error", error)], middleware=[Middleware(OpenTelemetryMiddleware)])

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
    app = Starlette(
        routes=[Route("/", PlainTextResponse("Unavailable", status_code=503))],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )

    assert test_client_factory(app).get("/").status_code == 503

    span = get_span(exporter)
    assert span.attributes is not None
    assert span.attributes["error.type"] == "503"
    assert span.status.status_code == StatusCode.ERROR


def test_http_span_without_starlette_app(
    test_client_factory: TestClientFactory,
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    app = OpenTelemetryMiddleware(PlainTextResponse("raw"))

    assert test_client_factory(app).get("/raw").text == "raw"

    span = get_span(exporter)
    assert span.name == "GET"
    assert span.attributes is not None
    assert "http.route" not in span.attributes


@pytest.mark.anyio
async def test_http_span_handles_optional_scope_values(
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider
    scope: Scope = {
        "type": "http",
        "method": "get",
        "path": "/",
        "query_string": b"",
        "headers": [(b"x-example", b"one"), (b"X-Example", b"two")],
        "server": ("example.com", 8000),
    }

    messages: list[Message] = []

    async def send(message: Message) -> None:
        messages.append(message)

    app = OpenTelemetryMiddleware(PlainTextResponse("raw"))
    await app(scope, AsyncMock(), send)

    span = get_span(exporter)
    assert span.attributes is not None
    assert span.attributes["http.request.method"] == "GET"
    assert span.attributes["http.request.method_original"] == "get"
    assert span.attributes["server.address"] == "example.com"
    assert span.attributes["server.port"] == 8000
    assert "network.protocol.version" not in span.attributes
    assert "client.address" not in span.attributes

    exporter.clear()
    scope["server"] = None
    await app(scope, AsyncMock(), send)
    span = get_span(exporter)
    assert span.attributes is not None
    assert "server.address" not in span.attributes


def test_non_http_scopes_are_not_traced(
    tracer_provider: tuple[TracerProvider, InMemorySpanExporter],
) -> None:
    _, exporter = tracer_provider

    async def websocket_endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.close()

    app = Starlette(
        routes=[WebSocketRoute("/", websocket_endpoint)],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )

    with TestClient(app) as client:
        with client.websocket_connect("/"):
            pass

    assert exporter.get_finished_spans() == ()
