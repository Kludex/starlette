from __future__ import annotations

import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import Receive, Scope, Send
from tests.types import TestClientFactory


def test_https_redirect_middleware(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("OK", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(HTTPSRedirectMiddleware)],
    )

    client = test_client_factory(app, base_url="https://testserver")
    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(app)
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    client = test_client_factory(app, base_url="http://testserver:80")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    client = test_client_factory(app, base_url="http://testserver:443")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    client = test_client_factory(app, base_url="http://testserver:123")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver:123/"

    client = test_client_factory(app)
    response = client.get("/", headers={"host": "testserver:000080"}, follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    response = client.get("/", headers={"host": "testserver:65536"}, follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    response = client.get("/", headers={"host": "[:::]"}, follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://testserver/"

    client = test_client_factory(app, base_url="http://[::1]")
    response = client.get("/", headers={"host": "[:::]"}, follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["location"] == "https://[::1]/"


@pytest.mark.parametrize("host", ["testserver:65536", "[:::]"])
def test_https_redirect_middleware_without_server(test_client_factory: TestClientFactory, host: str) -> None:
    middleware = HTTPSRedirectMiddleware(PlainTextResponse("OK"))

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        scope.pop("server", None)
        await middleware(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/", headers={"host": host}, follow_redirects=False)
    assert response.status_code == 400
    assert response.text == "Invalid host header"
