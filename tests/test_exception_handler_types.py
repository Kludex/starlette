from __future__ import annotations

import httpx
import pytest

from starlette.applications import Starlette
from starlette.exceptions import HTTPException, WebSocketException
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, WebSocketRoute
from starlette.types import Message, Scope
from starlette.websockets import WebSocket


@pytest.mark.anyio
async def test_http_exception_handler_types() -> None:
    async def endpoint(request: Request) -> Response:
        raise HTTPException(status_code=418)

    def handle_http_error(request: Request, exc: HTTPException) -> Response:
        return Response(status_code=exc.status_code)

    async def handle_http_error_async(request: Request, exc: HTTPException) -> Response:
        return Response(status_code=exc.status_code)

    def handle_error(request: Request, exc: Exception) -> Response:
        return Response(status_code=418)

    for handler in (handle_http_error, handle_http_error_async, handle_error):
        app = Starlette(routes=[Route("/", endpoint)])
        app.add_exception_handler(HTTPException, handler)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver") as client:
            response = await client.get("/")
        assert response.status_code == 418

    app.add_exception_handler(Exception, handle_http_error)  # type: ignore[arg-type]
    app.add_exception_handler(ValueError, handle_http_error)  # type: ignore[arg-type]
    app.add_exception_handler(500, handle_http_error)  # type: ignore[arg-type]
    app.add_exception_handler(500, handle_http_error_async)  # type: ignore[arg-type]
    Starlette(exception_handlers={HTTPException: handle_error})
    Starlette(exception_handlers={HTTPException: handle_http_error})  # type: ignore[dict-item]


@pytest.mark.anyio
@pytest.mark.parametrize("key", [500, Exception])
async def test_server_error_handler_types(key: int | type[Exception]) -> None:
    async def endpoint(request: Request) -> Response:
        raise ValueError("Server error")

    def handle_error(request: Request, exc: Exception) -> Response:
        return Response(str(exc), status_code=500)

    async def handle_error_async(request: Request, exc: Exception) -> Response:
        return Response(str(exc), status_code=500)

    for handler in (handle_error, handle_error_async):
        app = Starlette(routes=[Route("/", endpoint)])
        app.add_exception_handler(key, handler)
        transport = httpx.ASGITransport(app, raise_app_exceptions=False)

        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/")
        assert response.status_code == 500
        assert response.text == "Server error"


@pytest.mark.anyio
async def test_websocket_exception_handler_types() -> None:
    async def endpoint(websocket: WebSocket) -> None:
        await websocket.accept()
        raise WebSocketException(code=1008)

    async def handle_websocket_error(websocket: WebSocket, exc: WebSocketException) -> None:
        await websocket.close(code=exc.code)

    async def handle_error(websocket: WebSocket, exc: Exception) -> None:
        await websocket.close(code=1008)

    async def receive() -> Message:
        return {"type": "websocket.connect"}

    async def send(message: Message) -> None:
        messages.append(message)

    for handler in (handle_websocket_error, handle_error):
        app = Starlette(routes=[WebSocketRoute("/", endpoint)])
        app.add_exception_handler(WebSocketException, handler)
        messages: list[Message] = []
        scope: Scope = {"type": "websocket", "path": "/", "headers": [], "query_string": b""}

        await app(scope, receive, send)
        assert messages == [
            {"type": "websocket.accept", "subprotocol": None, "headers": []},
            {"type": "websocket.close", "code": 1008, "reason": ""},
        ]

    app.add_exception_handler(403, handle_error)
    app.add_exception_handler(Exception, handle_websocket_error)  # type: ignore[arg-type]
    app.add_exception_handler(ValueError, handle_websocket_error)  # type: ignore[arg-type]
    Starlette(exception_handlers={WebSocketException: handle_error})
    Starlette(exception_handlers={WebSocketException: handle_websocket_error})  # type: ignore[dict-item]
