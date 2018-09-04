from starlette.exceptions import ExceptionMiddleware, HTTPException
from starlette.response import PlainTextResponse
from starlette.routing import Router, Path
from starlette.testclient import TestClient
import pytest


def raise_runtime_error(scope):
    async def asgi(receive, send):
        raise RuntimeError("Yikes")

    return asgi


def not_acceptable(scope):
    async def asgi(receive, send):
        raise HTTPException(status_code=406)

    return asgi


def not_modified(scope):
    async def asgi(receive, send):
        raise HTTPException(status_code=304)

    return asgi


def handled_exc_after_response(scope):
    async def asgi(receive, send):
        response = PlainTextResponse("OK", status_code=200)
        await response(receive, send)
        raise HTTPException(status_code=406)

    return asgi


router = Router(
    routes=[
        Path("/runtime_error", app=raise_runtime_error),
        Path("/not_acceptable", app=not_acceptable),
        Path("/not_modified", app=not_modified),
        Path("/handled_exc_after_response", app=handled_exc_after_response),
    ]
)


app = ExceptionMiddleware(router)
client = TestClient(app)


def test_server_error():
    with pytest.raises(RuntimeError):
        response = client.get("/runtime_error")

    allow_500_client = TestClient(app, raise_server_exceptions=False)
    response = allow_500_client.get("/runtime_error")
    assert response.status_code == 500
    assert response.text == "Internal Server Error"


def test_debug_enabled():
    app = ExceptionMiddleware(router)
    app.debug = True
    allow_500_client = TestClient(app, raise_server_exceptions=False)
    response = allow_500_client.get("/runtime_error")
    assert response.status_code == 500
    assert "RuntimeError" in response.text


def test_not_acceptable():
    response = client.get("/not_acceptable")
    assert response.status_code == 406
    assert response.text == "Not Acceptable"


def test_not_modified():
    response = client.get("/not_modified")
    assert response.status_code == 304
    assert response.text == ""


def test_websockets_should_raise():
    with pytest.raises(RuntimeError):
        client.websocket_connect("/runtime_error")


def test_handled_exc_after_response():
    # A 406 HttpException is raised *after* the response has already been sent.
    # The exception middleware should raise a RuntimeError.
    with pytest.raises(RuntimeError):
        client.get("/handled_exc_after_response")

    # If `raise_server_exceptions=False` then the test client will still allow
    # us to see the response as it will have been seen by the client.
    allow_200_client = TestClient(app, raise_server_exceptions=False)
    response = allow_200_client.get("/handled_exc_after_response")
    assert response.status_code == 200
    assert response.text == "OK"


def test_force_500_response():
    def app(scope):
        raise RuntimeError()

    force_500_client = TestClient(app, raise_server_exceptions=False)
    response = force_500_client.get("/")
    assert response.status_code == 500
    assert response.text == ""
