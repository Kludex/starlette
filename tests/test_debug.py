from starlette import Request, Response, TestClient
from starlette.debug import DebugMiddleware
import pytest


def test_debug_text():
    def app(scope):
        async def asgi(receive, send):
            raise RuntimeError("Something went wrong")

        return asgi

    client = TestClient(DebugMiddleware(app))
    response = client.get("/")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/plain")
    assert "RuntimeError" in response.text


def test_debug_html():
    def app(scope):
        async def asgi(receive, send):
            raise RuntimeError("Something went wrong")

        return asgi

    client = TestClient(DebugMiddleware(app))
    response = client.get("/", headers={"Accept": "text/html, */*"})
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/html")
    assert "RuntimeError" in response.text


def test_debug_after_response_sent():
    def app(scope):
        async def asgi(receive, send):
            response = Response(b"", status_code=204)
            await response(receive, send)
            raise RuntimeError("Something went wrong")

        return asgi

    client = TestClient(DebugMiddleware(app))
    with pytest.raises(RuntimeError):
        response = client.get("/")


def test_debug_error_during_scope():
    def app(scope):
        raise RuntimeError("Something went wrong")

    app = DebugMiddleware(app)
    client = TestClient(DebugMiddleware(app))
    response = client.get("/", headers={"Accept": "text/html, */*"})
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/html")
    assert "RuntimeError" in response.text


def test_debug_not_http():
    def app(scope):
        raise RuntimeError("Something went wrong")

    app = DebugMiddleware(app)

    with pytest.raises(RuntimeError):
        app({"type": "websocket"})
