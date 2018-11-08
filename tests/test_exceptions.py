import pytest

from starlette.exceptions import ExceptionMiddleware, HTTPException
from starlette.responses import PlainTextResponse
from starlette.routing import Route, Router, WebSocketRoute
from starlette.testclient import TestClient


def raise_runtime_error(request):
    raise RuntimeError("Yikes")


def not_acceptable(request):
    raise HTTPException(status_code=406)


def not_modified(request):
    raise HTTPException(status_code=304)


class HandledExcAfterResponse:
    def __init__(self, scope):
        pass

    async def __call__(self, receive, send):
        response = PlainTextResponse("OK", status_code=200)
        await response(receive, send)
        raise HTTPException(status_code=406)


router = Router(
    routes=[
        Route("/runtime_error", endpoint=raise_runtime_error),
        Route("/not_acceptable", endpoint=not_acceptable),
        Route("/not_modified", endpoint=not_modified),
        Route("/handled_exc_after_response", endpoint=HandledExcAfterResponse),
        WebSocketRoute("/runtime_error", endpoint=raise_runtime_error),
    ]
)


app = ExceptionMiddleware(router)
client = TestClient(app)


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
