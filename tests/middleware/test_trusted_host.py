import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import Message, Receive, Scope, Send
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


def test_ipv6_trusted_host(test_client_factory: TestClientFactory) -> None:
    server_scope = None

    def homepage(request: Request) -> PlainTextResponse:
        nonlocal server_scope
        server_scope = request.scope["server"]
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=["[::1]"])],
    )

    client = test_client_factory(app, base_url="http://[::1]:8000")
    response = client.get("/")
    assert response.status_code == 200
    assert server_scope == ["::1", 8000]

    client = test_client_factory(app, base_url="http://[::2]:8000")
    response = client.get("/")
    assert response.status_code == 400


def test_ipv6_invalid_host_header(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=["[::1]", "*.example.com"])],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"host": "[::1]evil.com"})
    assert response.status_code == 400

    response = client.get("/", headers={"host": "[unclosed"})
    assert response.status_code == 400

    response = client.get("/", headers={"host": "[::1].example.com"})
    assert response.status_code == 400


@pytest.mark.anyio
async def test_ipv6_non_ascii_port_rejected() -> None:
    sent_status = None

    async def dummy_app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})

    middleware = TrustedHostMiddleware(dummy_app, allowed_hosts=["[::1]"])
    scope: Scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"host", "[::1]:\u0661".encode("utf-8"))],
    }

    async def send(message: Message) -> None:
        nonlocal sent_status
        if message["type"] == "http.response.start":
            sent_status = message["status"]

    async def receive() -> Message:
        return {"type": "http.request"}

    await middleware(scope, receive, send)
    assert sent_status == 400
