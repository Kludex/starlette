from __future__ import annotations

from typing import cast

import anyio
import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response, StreamingResponse
from starlette.routing import Mount
from starlette.types import Message, Receive, Scope, Send
from tests.types import TestClientFactory


@pytest.mark.parametrize("depth", [0, 1, 2])
@pytest.mark.parametrize("streaming", [True, False])
def test_mounted_trailers_through_http_middleware(
    test_client_factory: TestClientFactory, depth: int, streaming: bool
) -> None:
    events: list[str] = []
    payload = b"hello" * 200

    async def rpc(scope: Scope, receive: Receive, send: Send) -> None:
        assert "http.response.trailers" in scope["extensions"]
        await send({"type": "http.response.start", "status": 200, "headers": [], "trailers": True})
        await send({"type": "http.response.body", "body": payload, "more_body": streaming})
        if streaming:
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        await anyio.lowlevel.checkpoint()
        events.append("trailers")
        await send({"type": "http.response.trailers", "headers": [(b"x-item", b"one")], "more_trailers": True})
        await send({"type": "http.response.trailers", "headers": [(b"x-item", b"two"), (b"grpc-status", b"0")]})
        events.append("background")

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["x-middleware"] = "present"
        return response

    app = Starlette(
        routes=[Mount("/rpc", app=rpc)],
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=dispatch) for _ in range(depth)]
        + [Middleware(CORSMiddleware, allow_origins=["*"])],
    )
    response = test_client_factory(app).post("/rpc/method", headers={"origin": "https://example.org", "te": "trailers"})
    assert response.content == payload
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.extensions["http.response.trailers"] == [
        (b"x-item", b"one"),
        (b"x-item", b"two"),
        (b"grpc-status", b"0"),
    ]
    assert "grpc-status" not in response.headers
    assert events == ["trailers", "background"]


@pytest.mark.parametrize("consume", [True, False])
def test_replace_trailer_response(test_client_factory: TestClientFactory, consume: bool) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [], "trailers": True})
        await send({"type": "http.response.body", "body": b"original"})
        await send({"type": "http.response.trailers", "headers": [(b"grpc-status", b"0")]})

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if consume:
            async for _ in cast(StreamingResponse, response).body_iterator:
                pass
        return PlainTextResponse("replacement")

    response = test_client_factory(BaseHTTPMiddleware(app, dispatch=dispatch)).get("/")
    assert response.text == "replacement"
    assert "http.response.trailers" not in response.extensions


@pytest.mark.anyio
async def test_middleware_does_not_disconnect_before_trailers() -> None:
    received_body = anyio.Event()
    received_trailers = anyio.Event()

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await receive()
        await send({"type": "http.response.start", "status": 200, "headers": [], "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        await received_body.wait()
        await send({"type": "http.response.trailers", "headers": [], "more_trailers": True})
        await send({"type": "http.response.trailers", "headers": []})
        assert received_trailers.is_set()
        assert await receive() == {"type": "http.disconnect"}

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        return await call_next(request)

    async def receive() -> Message:
        return {"type": "http.request", "body": b""}

    async def send(message: Message) -> None:
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            received_body.set()
        if message["type"] == "http.response.trailers" and not message.get("more_trailers", False):
            received_trailers.set()

    with anyio.fail_after(2):
        await BaseHTTPMiddleware(app, dispatch=dispatch)({"type": "http"}, receive, send)


@pytest.mark.parametrize("raises", [True, False])
def test_missing_trailers_through_middleware(test_client_factory: TestClientFactory, raises: bool) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": [], "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        if raises:
            raise ValueError("trailer production failed")

    async def dispatch(request: Request, call_next: RequestResponseEndpoint) -> Response:
        return await call_next(request)

    with pytest.raises(ValueError if raises else AssertionError, match="failed|without completing trailers"):
        test_client_factory(BaseHTTPMiddleware(app, dispatch=dispatch)).get("/")
