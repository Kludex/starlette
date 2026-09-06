from __future__ import annotations

from collections.abc import AsyncIterator, Generator, Sequence

import anyio
import httpx
import pytest
from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import Histogram, InMemoryMetricReader, Metric, Sum
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.opentelemetry import OpenTelemetryMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.types import Message, Receive, Scope, Send


@pytest.fixture
def meter_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[tuple[MeterProvider, InMemoryMetricReader], None, None]:
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    monkeypatch.setattr(metrics, "get_meter_provider", lambda: provider)
    yield provider, reader
    provider.shutdown()


def get_metrics(reader: InMemoryMetricReader) -> dict[str, Metric]:
    data = reader.get_metrics_data()
    if data is None:
        return {}
    return {
        metric.name: metric
        for resource_metrics in data.resource_metrics
        for scope_metrics in resource_metrics.scope_metrics
        for metric in scope_metrics.metrics
    }


@pytest.mark.anyio
@pytest.mark.parametrize("explicit_provider", [False, True])
async def test_duration_with_noop_tracing(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    explicit_provider: bool,
) -> None:
    provider, reader = meter_provider
    app = Starlette(
        routes=[Route("/users/{user}", PlainTextResponse("ok"))],
        middleware=[
            Middleware(
                OpenTelemetryMiddleware,
                tracer_provider=trace.NoOpTracerProvider(),
                meter_provider=provider if explicit_provider else None,
            )
        ],
    )

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://testserver") as client:
        assert (await client.get("/users/alice?secret=one", headers={"x-private": "secret"})).status_code == 200
        assert (await client.get("/users/bob?secret=two")).status_code == 200

    recorded = get_metrics(reader)
    assert set(recorded) == {"http.server.request.duration"}
    metric = recorded["http.server.request.duration"]
    assert metric.unit == "s"
    assert isinstance(metric.data, Histogram)
    assert len(metric.data.data_points) == 1
    point = metric.data.data_points[0]
    assert point.count == 2
    assert point.sum > 0
    assert point.explicit_bounds == (0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10)
    assert point.attributes == {
        "http.request.method": "GET",
        "url.scheme": "https",
        "network.protocol.version": "1.1",
        "http.response.status_code": 200,
        "http.route": "/users/{user}",
    }


@pytest.mark.anyio
async def test_explicit_meter_provider_overrides_global(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
) -> None:
    _, global_reader = meter_provider
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])
    app = OpenTelemetryMiddleware(PlainTextResponse("ok"), meter_provider=provider)
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            assert (await client.get("/")).status_code == 200
        assert set(get_metrics(reader)) == {"http.server.request.duration"}
        assert get_metrics(global_reader) == {}
    finally:
        provider.shutdown()


@pytest.mark.anyio
@pytest.mark.parametrize("noop_metrics", [False, True])
async def test_metrics_and_tracing_are_independent(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    noop_metrics: bool,
) -> None:
    _, reader = meter_provider
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    app = OpenTelemetryMiddleware(
        PlainTextResponse("ok"),
        tracer_provider=provider,
        meter_provider=metrics.NoOpMeterProvider() if noop_metrics else None,
    )
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            assert (await client.get("/")).status_code == 200
        spans = exporter.get_finished_spans()
        assert len(spans) == 1
        if noop_metrics:
            assert get_metrics(reader) == {}
        else:
            duration = get_metrics(reader)["http.server.request.duration"]
            assert isinstance(duration.data, Histogram)
            exemplars = duration.data.data_points[0].exemplars
            assert len(exemplars) == 1
            assert spans[0].context is not None
            assert exemplars[0].trace_id == spans[0].context.trace_id
            assert exemplars[0].span_id == spans[0].context.span_id
    finally:
        provider.shutdown()


@pytest.mark.anyio
async def test_exclusions_and_nested_middleware(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
) -> None:
    _, reader = meter_provider
    app = OpenTelemetryMiddleware(
        OpenTelemetryMiddleware(PlainTextResponse("ok")),
        excluded_urls="/health$",
        tracer_provider=trace.NoOpTracerProvider(),
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/health")).status_code == 200
        assert get_metrics(reader) == {}
        assert (await client.get("/")).status_code == 200
    metric = get_metrics(reader)["http.server.request.duration"]
    assert isinstance(metric.data, Histogram)
    assert metric.data.data_points[0].count == 1
    assert metric.data.data_points[0].attributes is not None
    assert "http.route" not in metric.data.data_points[0].attributes


@pytest.mark.anyio
@pytest.mark.parametrize("status_code", [200, 404, 503])
async def test_response_status(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    status_code: int,
) -> None:
    _, reader = meter_provider
    app = OpenTelemetryMiddleware(PlainTextResponse("ok", status_code=status_code))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/")).status_code == status_code
    metric = get_metrics(reader)["http.server.request.duration"]
    assert isinstance(metric.data, Histogram)
    attributes = metric.data.data_points[0].attributes
    assert attributes is not None
    assert attributes["http.response.status_code"] == status_code
    if status_code == 503:
        assert attributes["error.type"] == "503"
    else:
        assert "error.type" not in attributes


@pytest.mark.anyio
async def test_concurrent_active_requests(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
) -> None:
    _, reader = meter_provider
    started = anyio.Event()
    release = anyio.Event()
    count = 0

    async def endpoint(request: Request) -> PlainTextResponse:
        nonlocal count
        count += 1
        if count == 2:
            started.set()
        await release.wait()
        return PlainTextResponse("ok")

    app = Starlette(
        routes=[Route("/users/{user}", endpoint)],
        middleware=[Middleware(OpenTelemetryMiddleware, record_active_requests=True)],
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        async with anyio.create_task_group() as group:
            group.start_soon(client.get, "/users/alice")
            group.start_soon(client.get, "/users/bob")
            await started.wait()
            active = get_metrics(reader)["http.server.active_requests"]
            assert active.unit == "{request}"
            assert isinstance(active.data, Sum)
            assert active.data.data_points[0].value == 2
            assert active.data.data_points[0].attributes == {"http.request.method": "GET", "url.scheme": "http"}
            release.set()
    active = get_metrics(reader)["http.server.active_requests"]
    assert isinstance(active.data, Sum)
    assert active.data.data_points[0].value == 0


@pytest.mark.anyio
@pytest.mark.parametrize("cancel", [False, True])
async def test_failed_requests_release_active_count(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    cancel: bool,
) -> None:
    _, reader = meter_provider

    async def endpoint(request: Request) -> PlainTextResponse:
        if cancel:
            await anyio.sleep_forever()
        raise RuntimeError("request failed")

    app = Starlette(
        routes=[Route("/", endpoint)],
        middleware=[Middleware(OpenTelemetryMiddleware, record_active_requests=True)],
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        if cancel:
            with anyio.CancelScope() as scope:
                scope.cancel()
                await client.get("/")
        else:
            with pytest.raises(RuntimeError, match="request failed"):
                await client.get("/")
    recorded = get_metrics(reader)
    active = recorded["http.server.active_requests"]
    assert isinstance(active.data, Sum)
    assert active.data.data_points[0].value == 0
    duration = recorded["http.server.request.duration"]
    assert isinstance(duration.data, Histogram)
    assert duration.data.data_points[0].attributes is not None
    assert duration.data.data_points[0].attributes["error.type"] == (
        anyio.get_cancelled_exc_class().__qualname__ if cancel else "RuntimeError"
    )
    assert "http.response.status_code" not in duration.data.data_points[0].attributes


@pytest.mark.anyio
@pytest.mark.parametrize("method", ["POST", "HEAD"])
async def test_streaming_body_sizes(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    method: str,
) -> None:
    _, reader = meter_provider

    async def application(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        body = await request.body()
        await send({"type": "http.response.start", "status": 200})
        await send({"type": "http.response.body", "body": body[:2], "more_body": True})
        await send({"type": "http.response.body", "body": body[2:]})

    async def body() -> AsyncIterator[bytes]:
        yield b"hello"
        yield b"world"

    app = OpenTelemetryMiddleware(application, record_body_sizes=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.request(method, "/", content=body())
        assert response.content == (b"" if method == "HEAD" else b"helloworld")
    recorded = get_metrics(reader)
    for name in ("http.server.request.body.size", "http.server.response.body.size"):
        metric = recorded[name]
        assert metric.unit == "By"
        assert isinstance(metric.data, Histogram)
        assert metric.data.data_points[0].count == 1
        assert metric.data.data_points[0].sum == (0 if method == "HEAD" and name.endswith("response.body.size") else 10)


@pytest.mark.anyio
async def test_parameterized_mounts_use_route_templates(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
) -> None:
    _, reader = meter_provider
    app = Starlette(
        routes=[
            Mount("/tenants/{tenant}", routes=[Mount("/v1", routes=[Route("/users/{user}", PlainTextResponse("ok"))])])
        ],
        middleware=[Middleware(OpenTelemetryMiddleware)],
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/tenants/acme/v1/users/alice")).status_code == 200
        assert (await client.get("/tenants/example/v1/users/bob")).status_code == 200
    duration = get_metrics(reader)["http.server.request.duration"]
    assert isinstance(duration.data, Histogram)
    assert len(duration.data.data_points) == 1
    assert duration.data.data_points[0].count == 2
    assert duration.data.data_points[0].attributes is not None
    assert duration.data.data_points[0].attributes["http.route"] == "/tenants/{tenant}/v1/users/{user}"


@pytest.mark.anyio
@pytest.mark.parametrize("complete_request", [False, True])
async def test_disconnect_and_response_trailers(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    complete_request: bool,
) -> None:
    _, reader = meter_provider
    messages: list[Message] = []
    incoming_messages: list[Message] = [
        {"type": "http.request", "body": b"hello", "more_body": not complete_request},
        {"type": "http.disconnect"},
    ]
    incoming = iter(incoming_messages)

    async def receive() -> Message:
        return next(incoming)

    async def send(message: Message) -> None:
        messages.append(message)

    async def application(scope: Scope, receive: Receive, send: Send) -> None:
        assert (await receive())["body"] == b"hello"
        assert (await receive())["type"] == "http.disconnect"
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send({"type": "http.response.body"})
        await send({"type": "http.response.trailers", "headers": []})

    app = OpenTelemetryMiddleware(application, record_body_sizes=True)
    await app({"type": "http", "method": "POST", "path": "/", "headers": []}, receive, send)
    assert len(messages) == 3
    recorded = get_metrics(reader)
    assert ("http.server.request.body.size" in recorded) == complete_request
    response_size = recorded["http.server.response.body.size"]
    assert isinstance(response_size.data, Histogram)
    assert response_size.data.data_points[0].sum == 0


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("environment", "known_methods", "method", "expected"),
    [
        (None, None, "GET", "GET"),
        (None, None, "BREW", "_OTHER"),
        ("BREW", None, "BREW", "BREW"),
        ("BREW", None, "GET", "_OTHER"),
        ("", None, "GET", "_OTHER"),
        ("GET", "", "GET", "_OTHER"),
        ("GET", [], "GET", "_OTHER"),
        ("GET", ["BREW"], "BREW", "BREW"),
        ("GET", " BREW, POST ", "BREW", "BREW"),
    ],
)
async def test_known_http_methods(
    monkeypatch: pytest.MonkeyPatch,
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    environment: str | None,
    known_methods: str | Sequence[str] | None,
    method: str,
    expected: str,
) -> None:
    _, reader = meter_provider
    if environment is None:
        monkeypatch.delenv("OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS", raising=False)
    else:
        monkeypatch.setenv("OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS", environment)
    app = OpenTelemetryMiddleware(PlainTextResponse("ok"), known_methods=known_methods)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.request(method, "/")).status_code == 200
    duration = get_metrics(reader)["http.server.request.duration"]
    assert isinstance(duration.data, Histogram)
    assert duration.data.data_points[0].attributes is not None
    assert duration.data.data_points[0].attributes["http.request.method"] == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("excluded_urls", "starlette_environment", "general_environment", "excluded"),
    [
        (None, None, None, False),
        (None, None, "/excluded", True),
        (None, "/excluded", "[", True),
        (None, "/other", "/excluded", False),
        (None, "", "/excluded", False),
        ("", "/excluded", "[", False),
        ([], "/excluded", "[", False),
        (["/excluded"], "[", "[", True),
        ("/excluded", "[", "[", True),
    ],
)
async def test_excluded_urls_precedence(
    monkeypatch: pytest.MonkeyPatch,
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    excluded_urls: str | Sequence[str] | None,
    starlette_environment: str | None,
    general_environment: str | None,
    excluded: bool,
) -> None:
    _, reader = meter_provider
    for name, value in (
        ("OTEL_PYTHON_STARLETTE_EXCLUDED_URLS", starlette_environment),
        ("OTEL_PYTHON_EXCLUDED_URLS", general_environment),
    ):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    app = OpenTelemetryMiddleware(PlainTextResponse("ok"), excluded_urls=excluded_urls)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/excluded")).status_code == 200
    assert ("http.server.request.duration" not in get_metrics(reader)) == excluded


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("active_environment", "body_environment", "explicit", "active_enabled", "body_enabled"),
    [
        ("true", "false", None, True, False),
        ("0", "1", None, False, True),
        ("FALSE", "TRUE", None, False, True),
        ("true", "1", False, False, False),
        ("false", "0", True, True, True),
        ("invalid", "invalid", False, False, False),
        ("invalid", "invalid", True, True, True),
    ],
)
async def test_metric_flags_precedence(
    monkeypatch: pytest.MonkeyPatch,
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    active_environment: str,
    body_environment: str,
    explicit: bool | None,
    active_enabled: bool,
    body_enabled: bool,
) -> None:
    _, reader = meter_provider
    monkeypatch.setenv("OTEL_PYTHON_STARLETTE_RECORD_ACTIVE_REQUESTS", active_environment)
    monkeypatch.setenv("OTEL_PYTHON_STARLETTE_RECORD_BODY_SIZES", body_environment)

    async def echo(request: Request) -> PlainTextResponse:
        return PlainTextResponse(await request.body())

    app = OpenTelemetryMiddleware(
        Starlette(routes=[Route("/", echo, methods=["POST"])]),
        record_active_requests=explicit,
        record_body_sizes=explicit,
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.post("/", content=b"hello")).text == "hello"
    recorded = get_metrics(reader)
    assert "http.server.request.duration" in recorded
    assert ("http.server.active_requests" in recorded) == active_enabled
    assert ("http.server.request.body.size" in recorded) == body_enabled
    assert ("http.server.response.body.size" in recorded) == body_enabled


@pytest.mark.parametrize(
    "name", ["OTEL_PYTHON_STARLETTE_RECORD_ACTIVE_REQUESTS", "OTEL_PYTHON_STARLETTE_RECORD_BODY_SIZES"]
)
@pytest.mark.parametrize("value", ["invalid", ""])
def test_invalid_metric_flag_environment(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match=f"Config '{name}'.*Not a valid bool"):
        OpenTelemetryMiddleware(PlainTextResponse("ok"))


@pytest.mark.anyio
async def test_environment_resolved_at_construction(
    monkeypatch: pytest.MonkeyPatch,
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
) -> None:
    _, reader = meter_provider
    monkeypatch.setenv("OTEL_PYTHON_STARLETTE_EXCLUDED_URLS", "/excluded")
    monkeypatch.setenv("OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS", "GET")
    monkeypatch.setenv("OTEL_PYTHON_STARLETTE_RECORD_ACTIVE_REQUESTS", "true")
    monkeypatch.setenv("OTEL_PYTHON_STARLETTE_RECORD_BODY_SIZES", "true")
    app = OpenTelemetryMiddleware(PlainTextResponse("ok"))
    monkeypatch.setenv("OTEL_PYTHON_STARLETTE_EXCLUDED_URLS", "/included")
    monkeypatch.setenv("OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS", "POST")
    monkeypatch.setenv("OTEL_PYTHON_STARLETTE_RECORD_ACTIVE_REQUESTS", "false")
    monkeypatch.setenv("OTEL_PYTHON_STARLETTE_RECORD_BODY_SIZES", "false")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.get("/excluded")).status_code == 200
        assert (await client.get("/included")).status_code == 200
    recorded = get_metrics(reader)
    assert "http.server.active_requests" in recorded
    assert "http.server.response.body.size" in recorded
    duration = recorded["http.server.request.duration"]
    assert isinstance(duration.data, Histogram)
    assert len(duration.data.data_points) == 1
    point = duration.data.data_points[0]
    assert point.count == 1
    assert point.attributes is not None
    assert point.attributes["http.request.method"] == "GET"
