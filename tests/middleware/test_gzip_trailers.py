from __future__ import annotations

import anyio
import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount
from starlette.types import Receive, Scope, Send
from tests.types import TestClientFactory


@pytest.mark.parametrize("depth", [0, 1, 2])
@pytest.mark.parametrize("encoding", ["gzip", "identity"])
@pytest.mark.parametrize("streaming", [True, False])
def test_mounted_trailers(test_client_factory: TestClientFactory, depth: int, encoding: str, streaming: bool) -> None:
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
        + [Middleware(GZipMiddleware), Middleware(CORSMiddleware, allow_origins=["*"])],
    )
    response = test_client_factory(app).post(
        "/rpc/method", headers={"accept-encoding": encoding, "origin": "https://example.org", "te": "trailers"}
    )
    assert response.content == payload
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.extensions["http.response.trailers"] == [
        (b"x-item", b"one"),
        (b"x-item", b"two"),
        (b"grpc-status", b"0"),
    ]
    assert "grpc-status" not in response.headers
    if encoding == "gzip":
        assert response.headers["content-encoding"] == "gzip"
        assert "content-length" not in response.headers
    assert events == ["trailers", "background"]


@pytest.mark.parametrize("media_type", ["application/grpc", "application/grpc+proto", "text/event-stream"])
@pytest.mark.parametrize("encoding", ["gzip", "identity"])
def test_excluded_content_preserves_trailers(
    test_client_factory: TestClientFactory, media_type: str, encoding: str
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", media_type.encode())],
                "trailers": True,
            }
        )
        await send({"type": "http.response.body", "body": b"hello"})
        await send({"type": "http.response.trailers", "headers": [(b"grpc-status", b"0")]})

    result = test_client_factory(GZipMiddleware(app, minimum_size=0)).get("/", headers={"accept-encoding": encoding})
    assert result.content == b"hello"
    assert "content-encoding" not in result.headers
    assert result.extensions["http.response.trailers"] == [(b"grpc-status", b"0")]
