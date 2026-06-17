import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import WebSocketDenialResponse
from starlette.types import Scope, Receive, Send
from starlette.websockets import WebSocket, WebSocketDisconnect
from tests.types import TestClientFactory


def test_trusted_host_middleware(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=["testserver", "*.testserver"])],
    )

    client = test_client_factory(app)
    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(app, base_url="http://subdomain.testserver")
    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(app, base_url="http://invalidhost")
    response = client.get("/")
    assert response.status_code == 400


def test_default_allowed_hosts() -> None:
    app = Starlette()
    middleware = TrustedHostMiddleware(app)
    assert middleware.allowed_hosts == ["*"]


def test_www_redirect(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=["www.example.com"])],
    )

    client = test_client_factory(app, base_url="https://example.com")
    response = client.get("/")
    assert response.status_code == 200
    assert response.url == "https://www.example.com/"


def test_trusted_host_middleware_websocket(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive, send)
        await websocket.accept()
        await websocket.send_text("OK")
        await websocket.close()

    app = TrustedHostMiddleware(app, allowed_hosts=["testserver"])
    client = test_client_factory(app)

    # 1. Valid host
    with client.websocket_connect("/") as websocket:
        assert websocket.receive_text() == "OK"

    # 2. Invalid host, raises WebSocketDenialResponse because test client supports websocket.http.response extension
    with pytest.raises(WebSocketDenialResponse) as exc_info:
        with client.websocket_connect("ws://invalidhost/"):
            pass
    assert exc_info.value.status_code == 400
    assert exc_info.value.content == b"Invalid host header"


def test_trusted_host_middleware_websocket_without_denial_extension(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive, send)
        await websocket.accept()
        await websocket.send_text("OK")
        await websocket.close()

    app = TrustedHostMiddleware(app, allowed_hosts=["testserver"])

    async def mock_asgi_app(scope: Scope, receive: Receive, send: Send) -> None:
        if "extensions" in scope:
            scope["extensions"].pop("websocket.http.response", None)
        await app(scope, receive, send)

    client = test_client_factory(mock_asgi_app)
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("ws://invalidhost/"):
            pass
    assert exc_info.value.code == 1008
