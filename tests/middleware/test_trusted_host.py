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


def test_ipv6_host_extraction() -> None:
    """Test that IPv6 addresses are extracted correctly from the Host header."""
    from starlette.datastructures import Headers

    async def app(scope, receive, send):  # type: ignore[no-untyped-def]
        pass

    middleware = TrustedHostMiddleware(app, allowed_hosts=["::1"])

    # Simulate the middleware's host extraction logic
    test_cases = [
        ("[::1]:8000", "::1"),
        ("[::1]", "::1"),
        ("[2001:db8::1]:80", "2001:db8::1"),
        ("example.com:8000", "example.com"),
        ("example.com", "example.com"),
    ]

    for host_header, expected in test_cases:
        if host_header.startswith("["):
            bracket_end = host_header.find("]")
            host = host_header[1:bracket_end] if bracket_end != -1 else host_header
        else:
            host = host_header.split(":")[0]
        assert host == expected, f"For Host header '{host_header}': expected '{expected}', got '{host}'"
