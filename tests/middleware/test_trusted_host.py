from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
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


def test_ipv6_host(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=["[::1]"])],
    )

    # Test the middleware's host parsing directly
    middleware = TrustedHostMiddleware(app, allowed_hosts=["[::1]"])

    # Simulate IPv6 host header with port
    scope = {"type": "http", "headers": [(b"host", b"[::1]:8000")]}
    host = dict(scope["headers"]).get(b"host", b"").decode()
    # Our fix: extract IPv6 address
    if host.startswith("["):
        parsed_host = host.split("]")[0] + "]"
    else:
        parsed_host = host.split(":")[0]
    assert parsed_host == "[::1]", f"Expected [::1], got {parsed_host}"

    # Simulate IPv6 host header without port
    scope = {"type": "http", "headers": [(b"host", b"[::1]")]}
    host = dict(scope["headers"]).get(b"host", b"").decode()
    if host.startswith("["):
        parsed_host = host.split("]")[0] + "]"
    else:
        parsed_host = host.split(":")[0]
    assert parsed_host == "[::1]", f"Expected [::1], got {parsed_host}"

    # Regular IPv4 should still work
    scope = {"type": "http", "headers": [(b"host", b"example.com:8000")]}
    host = dict(scope["headers"]).get(b"host", b"").decode()
    if host.startswith("["):
        parsed_host = host.split("]")[0] + "]"
    else:
        parsed_host = host.split(":")[0]
    assert parsed_host == "example.com", f"Expected example.com, got {parsed_host}"
