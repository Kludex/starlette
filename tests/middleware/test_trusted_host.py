from __future__ import annotations

import pytest

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


@pytest.mark.parametrize(
    ("host", "status_code"),
    [
        ("[::1]", 200),
        ("[::1]:8000", 200),
        ("[v1.foo]", 200),
        ("[:::]", 400),
        ("[::ffff:999.999.999.999]", 400),
        ("[2001:db8::1]", 400),
        ("[::1", 400),
        ("[::1]evil.example.com", 400),
        ("[::1]@attacker", 400),
        ("[::1].", 400),
        ("[::1]:evil", 400),
        ("[::1]:", 400),
        ("api_service", 200),
        ("api_service:000080", 200),
        ("api_service:65535", 200),
        ("api_service:65536", 200),
        ("api_service:100000", 200),
        ("api_service:8000", 200),
        ("api_service/evil", 400),
        ("api_service?evil", 400),
        ("api_service#evil", 400),
        ("api_service@attacker", 400),
        ("api service", 400),
    ],
)
def test_trusted_host_middleware_ipv6(test_client_factory: TestClientFactory, host: str, status_code: int) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK")

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(TrustedHostMiddleware, allowed_hosts=["[::1]", "[v1.foo]", "api_service", "*.example.com"])
        ],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"host": host})
    assert response.status_code == status_code


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


@pytest.mark.parametrize(
    ("allowed_host", "host"),
    [
        ("example.com", "EXAMPLE.com"),
        ("example.com", "Example.Com"),
        ("example.com", "EXAMPLE.COM"),
        ("example.com", "EXAMPLE.COM:8000"),
        ("Example.Com", "example.com"),
        ("*.example.com", "SUB.EXAMPLE.com"),
        ("*.Example.Com", "sub.example.com"),
    ],
)
def test_trusted_host_middleware_is_case_insensitive(
    test_client_factory: TestClientFactory, allowed_host: str, host: str
) -> None:
    """Host names are case-insensitive. See RFC 9110, section 4.2.3."""

    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK")

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=[allowed_host])],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"host": host})
    assert response.status_code == 200


def test_www_redirect_is_case_insensitive(test_client_factory: TestClientFactory) -> None:
    """The www redirect compares the host case-insensitively too."""

    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=["www.example.com"])],
    )

    client = test_client_factory(app)
    response = client.get("/", headers={"host": "EXAMPLE.com"}, follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "http://www.EXAMPLE.com/"

    response = client.get("/", headers={"host": "WWW.EXAMPLE.com"})
    assert response.status_code == 200
    assert response.text == "OK"
