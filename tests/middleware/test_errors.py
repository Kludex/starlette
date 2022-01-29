import pytest

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware.errors import ServerErrorMiddleware
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


def test_handler(test_client_factory):
    async def app(scope, receive, send):
        raise RuntimeError("Something went wrong")

    def error_500(request, exc):
        return JSONResponse({"detail": "Server Error"}, status_code=500)

    app = ServerErrorMiddleware(app, handler=error_500)
    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 500
    assert response.json() == {"detail": "Server Error"}


def test_debug_text(test_client_factory):
    async def app(scope, receive, send):
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/plain")
    assert "RuntimeError: Something went wrong" in response.text


def test_debug_html(test_client_factory):
    async def app(scope, receive, send):
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.get("/", headers={"Accept": "text/html, */*"})
    assert response.status_code == 500
    assert response.headers["content-type"].startswith("text/html")
    assert "RuntimeError" in response.text


def test_debug_after_response_sent(test_client_factory):
    async def app(scope, receive, send):
        response = Response(b"", status_code=204)
        await response(scope, receive, send)
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app, debug=True)
    client = test_client_factory(app)
    with pytest.raises(RuntimeError):
        client.get("/")


def test_debug_not_http(test_client_factory):
    """
    DebugMiddleware should just pass through any non-http messages as-is.
    """

    async def app(scope, receive, send):
        raise RuntimeError("Something went wrong")

    app = ServerErrorMiddleware(app)

    with pytest.raises(RuntimeError):
        client = test_client_factory(app)
        with client.websocket_connect("/"):
            pass  # pragma: nocover


def test_background_task(test_client_factory):
    accessed_error_handler = False

    def error_handler(request, exc):
        nonlocal accessed_error_handler
        accessed_error_handler = True

    def raise_exception():
        raise Exception("Something went wrong")

    async def endpoint(request):
        task = BackgroundTask(raise_exception)
        return Response(status_code=204, background=task)

    app = Starlette(
        routes=[Route("/", endpoint=endpoint)],
        exception_handlers={Exception: error_handler},
    )

    client = test_client_factory(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 204
    assert accessed_error_handler
