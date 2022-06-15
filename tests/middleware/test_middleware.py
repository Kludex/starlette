from starlette.middleware import Middleware


class CustomMiddleware:
    pass


def test_middleware_repr():
    middleware = Middleware(CustomMiddleware)
    assert repr(middleware) == "Middleware(CustomMiddleware)"
