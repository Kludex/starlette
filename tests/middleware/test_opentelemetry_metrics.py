from __future__ import annotations

from collections.abc import AsyncIterator, Generator

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
@pytest.mark.parametrize(("method", "expected"), [("GET", "GET"), ("QUERY", "QUERY"), ("PROPFIND", "_OTHER")])
async def test_known_http_methods(
    meter_provider: tuple[MeterProvider, InMemoryMetricReader],
    method: str,
    expected: str,
) -> None:
    _, reader = meter_provider
    app = OpenTelemetryMiddleware(PlainTextResponse("ok"))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        assert (await client.request(method, "/")).status_code == 200
    duration = get_metrics(reader)["http.server.request.duration"]
    assert isinstance(duration.data, Histogram)
    assert duration.data.data_points[0].attributes is not None
    assert duration.data.data_points[0].attributes["http.request.method"] == expected
