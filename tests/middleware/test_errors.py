import pytest

from starlette.middleware.errors import ServerErrorMiddleware
from starlette.responses import JSONResponse, Response
from starlette.testclient import TestClient


def test_handler():
    async def app(scope, receive, send):
        raise RuntimeError("Something went wrong")

    def error_500(request, exc):
        return JSONResponse({"detail": "Server Error"}, status_code=500)

    app = ServerErrorMiddleware(app, handler=error_500)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 500
    assert response.json() == {"detail": "Server Error"}


def test_debug_text():
    async def app(scope, receive, send):
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/plain")
    assert "RuntimeError: Something went wrong" in response.text


def test_debug_html():
    async def app(scope, receive, send):
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/", headers={"Accept": "text/html, */*"})
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/html")
    assert "RuntimeError" in response.text


def test_debug_after_response_sent():
    async def app(scope, receive, send):
        response = Response(b"", status_code=204)
        await response(scope, receive, send)
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = TestClient(app)
    with pytest.raises(RuntimeError):
        client.get("/")


def test_debug_not_http():
    """
    DebugMiddleware should just pass through any non-http messages as-is.
    """

    async def app(scope, receive, send):
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app)

    with pytest.raises(RuntimeError):
        client = TestClient(app)
        with client.websocket_connect("/"):
            pass  # pragma: nocover
