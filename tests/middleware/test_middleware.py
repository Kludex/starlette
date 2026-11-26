from collections.abc import Callable

import pytest

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.middleware.gzip import GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send
from tests.types import TestClientFactory


class CustomMiddleware:  # pragma: no cover
    def __init__(self, app: ASGIApp, foo: str, *, bar: int) -> None:
        self.app = app
        self.foo = foo
        self.bar = bar

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.app(scope, receive, send)


def test_middleware_repr() -> None:
    middleware = Middleware(CustomMiddleware, "foo", bar=123)
    assert repr(middleware) == "Middleware(CustomMiddleware, 'foo', bar=123)"


def test_middleware_iter() -> None:
    cls, args, kwargs = Middleware(CustomMiddleware, "foo", bar=123)
    assert (cls, args, kwargs) == (CustomMiddleware, ("foo",), {"bar": 123})


async def passthrough(request: Request, call_next: RequestResponseEndpoint) -> Response:
    return await call_next(request)


@pytest.mark.parametrize(
    "wrap",
    [
        lambda app: SessionMiddleware(app, secret_key="secret"),
        lambda app: GZipMiddleware(app, minimum_size=1),
        lambda app: BaseHTTPMiddleware(app, dispatch=passthrough),
    ],
    ids=["session", "gzip", "base"],
)
def test_response_start_without_headers(
    test_client_factory: TestClientFactory, wrap: Callable[[ASGIApp], ASGIApp]
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200})
        await send({"type": "http.response.body", "body": b"Hello, world!"})

    response = test_client_factory(wrap(app)).get("/")
    assert response.status_code == 200
    assert response.text == "Hello, world!"
