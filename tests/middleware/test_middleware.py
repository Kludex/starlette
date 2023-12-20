from starlette.middleware import Middleware
from starlette.types import ASGIApp, Receive, Scope, Send


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
