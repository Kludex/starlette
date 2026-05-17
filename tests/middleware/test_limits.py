from __future__ import annotations

from contextlib import AsyncExitStack
from typing import AsyncGenerator, AsyncIterable, Callable

import anyio
import httpx
import pytest

from starlette.applications import Starlette
from starlette.middleware.limits import (
    RequestSizeLimitMiddleware,
    RequestTimeoutMiddleware,
)
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route
from starlette.testclient import TestClient
from starlette.types import ASGIApp, Message, Receive, Scope, Send


async def echo_endpoint(request: Request) -> Response:
    return Response(content=await request.body())


async def streaming_echo_endpoint(request: Request) -> Response:
    async def generator() -> AsyncIterable[bytes]:
        async for chunk in request.stream():
            if chunk:
                yield chunk

    return SimpleStreamingResponse(content=generator())


class SimpleStreamingResponse(Response):
    def __init__(self, content: AsyncIterable[bytes], status_code: int = 200):
        super().__init__(status_code=status_code)
        self.content = content

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        initial = True
        async for chunk in self.content:
            if initial:
                await send({"type": "http.response.start", "status": self.status_code})
                initial = False
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})


app = Starlette(
    routes=[
        Route("/echo", echo_endpoint, methods=["POST"]),
        Route("/streaming_echo", streaming_echo_endpoint, methods=["POST"]),
    ],
)


TestClientFactory = Callable[[ASGIApp], TestClient]


async def create_async_content_it(
    data: list[bytes], error_if_consumed: bool = True
) -> AsyncIterable[bytes]:
    for chunk in data:
        yield chunk
    if error_if_consumed:  # pragma: no cover
        raise AssertionError("create_async_content_it was consumed!")
    else:
        return


@pytest.mark.parametrize(
    "include_limits_in_error_responses,expected_content",
    [
        (True, b"Request body is too large. Max allowed size is 10 bytes."),
        (False, b"Request body is too large."),
    ],
)
def test_request_size_too_large(
    test_client_factory: TestClientFactory,
    include_limits_in_error_responses: bool,
    expected_content: bytes,
) -> None:
    wrapped_app = RequestSizeLimitMiddleware(
        app,
        max_request_size=10,
        include_limits_in_error_responses=include_limits_in_error_responses,
    )
    client = test_client_factory(wrapped_app)

    response = client.post("/echo", content=b"a" * 9)
    assert response.status_code == 200

    response = client.post("/echo", content=b"a" * 11)
    assert response.status_code == 413
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.content == expected_content


@pytest.mark.parametrize(
    "include_limits_in_error_responses,expected_content",
    [
        (True, b"Chunk size is too large. Max allowed size is 10 bytes."),
        (False, b"Chunk size is too large."),
    ],
)
@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.anyio
async def test_request_chunk_size_too_large(
    include_limits_in_error_responses: bool,
    expected_content: bytes,
) -> None:
    wrapped_app = RequestSizeLimitMiddleware(
        app,
        max_chunk_size=10,
        include_limits_in_error_responses=include_limits_in_error_responses,
    )
    client = httpx.AsyncClient(base_url="https://example.com", app=wrapped_app)

    response = await client.post(
        "/echo",
        content=create_async_content_it(
            [b"a", b"a" * 9, b"a"], error_if_consumed=False
        ),
    )
    assert response.status_code == 200

    response = await client.post(
        "/echo", content=create_async_content_it([b"a", b"a" * 11, b"a"])
    )
    assert response.status_code == 413
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.content == expected_content


@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.anyio
async def test_request_chunk_size_too_large_response_started() -> None:
    wrapped_app = RequestSizeLimitMiddleware(
        app,
        max_chunk_size=10,
    )
    client = httpx.AsyncClient(base_url="https://example.com", app=wrapped_app)

    response = await client.post(
        "/streaming_echo",
        content=create_async_content_it(
            [b"a", b"a" * 9, b"a"], error_if_consumed=False
        ),
    )
    assert response.status_code == 200

    # this is raised by ExceptionMiddleware
    with pytest.raises(RuntimeError, match="response already started"):
        await client.post(
            "/streaming_echo", content=create_async_content_it([b"a", b"a" * 11, b"a"])
        )


async def create_slow_content_generator(sleeps: list[float]) -> AsyncIterable[bytes]:
    for sleep in sleeps:
        await anyio.sleep(sleep)
        yield b"a"


@pytest.mark.parametrize(
    "include_limits_in_error_responses,expected_content",
    [
        (True, b"Request exceeded the timeout of 0.1 seconds."),
        (False, b"Request exceeded the timeout."),
    ],
)
@pytest.mark.anyio
async def test_request_too_slow(
    include_limits_in_error_responses: bool,
    expected_content: bytes,
) -> None:
    wrapped_app = RequestTimeoutMiddleware(
        app,
        request_timeout_seconds=0.1,
        include_limits_in_error_responses=include_limits_in_error_responses,
    )
    client = httpx.AsyncClient(base_url="https://example.com", app=wrapped_app)

    response = await client.post(
        "/echo",
        content=create_slow_content_generator([0.01] * 4),
    )
    assert response.status_code == 200

    response = await client.post(
        "/echo",
        content=create_slow_content_generator([0.01] * 10),
    )
    assert response.status_code == 408
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.content == expected_content


@pytest.mark.parametrize(
    "include_limits_in_error_responses,expected_content",
    [
        (True, b"Client was too slow sending data. Max allowed time is 0.1 seconds."),
        (False, b"Client was too slow sending data."),
    ],
)
@pytest.mark.anyio
async def test_client_slow_sending_data(
    include_limits_in_error_responses: bool,
    expected_content: bytes,
) -> None:
    wrapped_app = RequestTimeoutMiddleware(
        app,
        receive_timeout_seconds=0.1,
        include_limits_in_error_responses=include_limits_in_error_responses,
    )
    client = httpx.AsyncClient(base_url="https://example.com", app=wrapped_app)

    delays = [0.01] * 5

    response = await client.post(
        "/echo",
        content=create_slow_content_generator(delays),
    )
    assert response.status_code == 200

    response = await client.post(
        "/echo",
        content=create_slow_content_generator(delays + [0.5]),
    )
    assert response.status_code == 408
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.content == expected_content


@pytest.mark.anyio
async def test_client_slow_sending_data_response_already_started() -> None:
    wrapped_app = RequestTimeoutMiddleware(
        app,
        receive_timeout_seconds=0.1,
    )
    client = httpx.AsyncClient(base_url="https://example.com", app=wrapped_app)

    delays = [0.01] * 5

    response = await client.post(
        "/streaming_echo",
        content=create_slow_content_generator(delays),
    )
    assert response.status_code == 200

    # this is raised by ExceptionMiddleware
    with pytest.raises(RuntimeError, match="response already started"):
        response = await client.post(
            "/streaming_echo",
            content=create_slow_content_generator(delays + [0.5]),
        )


@pytest.mark.parametrize(
    "include_limits_in_error_responses",
    [True, False],
)
@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.anyio
async def test_client_slow_receiving_data(
    include_limits_in_error_responses: bool,
) -> None:
    wrapped_app = RequestTimeoutMiddleware(
        app,
        send_timeout_seconds=0.1,
        include_limits_in_error_responses=include_limits_in_error_responses,
    )

    responses: list[Message] = []

    async def rcv(chunks: list[bytes]) -> AsyncGenerator[Message, None]:
        for chunk in chunks:
            yield {"type": "http.request", "body": chunk, "more_body": True}
        yield {"type": "http.request", "body": b"", "more_body": False}

    async def snd(delay: float) -> AsyncGenerator[None, Message | None]:
        while True:
            await anyio.sleep(delay)
            message = yield
            assert message is not None
            responses.append(message)

    scope = {
        "type": "http",
        "version": "3",
        "method": "POST",
        "path": "/echo",
    }

    async with AsyncExitStack() as stack:
        send_gen = snd(0.01)
        await send_gen.asend(None)
        stack.push_async_callback(send_gen.aclose)

        rcv_gen = rcv([b"a"])
        stack.push_async_callback(rcv_gen.aclose)

        await wrapped_app(scope, rcv_gen.__anext__, send_gen.asend)
        assert responses == [
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", b"1")],
            },
            {"type": "http.response.body", "body": b"a"},
        ]

        responses.clear()
        send_gen = snd(0.5)
        await send_gen.asend(None)
        stack.push_async_callback(send_gen.aclose)

        rcv_gen = rcv([b"a"])
        stack.push_async_callback(rcv_gen.aclose)

        with pytest.raises(RuntimeError, match="response already started"):
            await wrapped_app(scope, rcv_gen.__anext__, send_gen.asend)
        assert responses == [
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", b"1")],
            }
        ]


@pytest.mark.parametrize(
    "include_limits_in_error_responses",
    [True, False],
)
@pytest.mark.filterwarnings("ignore::ResourceWarning")
@pytest.mark.anyio
async def test_client_slow_receiving_data_streaming(
    include_limits_in_error_responses: bool,
) -> None:
    wrapped_app = RequestTimeoutMiddleware(
        app,
        send_timeout_seconds=0.1,
        include_limits_in_error_responses=include_limits_in_error_responses,
    )

    responses: list[Message] = []

    async def rcv(chunks: list[bytes]) -> AsyncGenerator[Message, None]:
        for chunk in chunks:
            yield {"type": "http.request", "body": chunk, "more_body": True}
        yield {"type": "http.request", "body": b"", "more_body": False}

    async def snd(delay: float) -> AsyncGenerator[None, Message | None]:
        while True:
            await anyio.sleep(delay)
            message = yield
            assert message is not None
            responses.append(message)

    scope = {
        "type": "http",
        "version": "3",
        "method": "POST",
        "path": "/streaming_echo",
    }

    async with AsyncExitStack() as stack:
        send_gen = snd(0.01)
        await send_gen.asend(None)
        stack.push_async_callback(send_gen.aclose)

        rcv_gen = rcv([b"a"])
        stack.push_async_callback(rcv_gen.aclose)

        await wrapped_app(scope, rcv_gen.__anext__, send_gen.asend)
        assert responses == [
            {"type": "http.response.start", "status": 200},
            {"type": "http.response.body", "body": b"a", "more_body": True},
            {"type": "http.response.body", "body": b"", "more_body": False},
        ]

        responses.clear()
        send_gen = snd(0.5)
        await send_gen.asend(None)
        stack.push_async_callback(send_gen.aclose)

        rcv_gen = rcv([b"a"])
        stack.push_async_callback(rcv_gen.aclose)

        with pytest.raises(RuntimeError, match="response already started"):
            await wrapped_app(scope, rcv_gen.__anext__, send_gen.asend)
        assert responses == [{"type": "http.response.start", "status": 200}]


def test_request_size_limit_not_http(test_client_factory: TestClientFactory) -> None:
    wrapped_app = RequestSizeLimitMiddleware(app, max_request_size=10)

    with test_client_factory(wrapped_app):
        pass


def test_timeout_not_http(test_client_factory: TestClientFactory) -> None:
    wrapped_app = RequestTimeoutMiddleware(app)

    with test_client_factory(wrapped_app):
        pass
