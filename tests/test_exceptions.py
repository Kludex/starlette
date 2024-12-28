from collections.abc import Generator

import pytest

from starlette.exceptions import HTTPException, WebSocketException
from starlette.middleware.exceptions import ExceptionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route, Router, WebSocketRoute
from starlette.testclient import TestClient
from starlette.types import Receive, Scope, Send
from tests.types import TestClientFactory


def raise_runtime_error(request: Request) -> None:
    raise RuntimeError("Yikes")


def not_acceptable(request: Request) -> None:
    raise HTTPException(status_code=406)


def no_content(request: Request) -> None:
    raise HTTPException(status_code=204)


def not_modified(request: Request) -> None:
    raise HTTPException(status_code=304)


def with_headers(request: Request) -> None:
    raise HTTPException(status_code=200, headers={"x-potato": "always"})


class BadBodyException(HTTPException):
    pass


async def read_body_and_raise_exc(request: Request) -> None:
    await request.body()
    raise BadBodyException(422)


async def handler_that_reads_body(request: Request, exc: BadBodyException) -> JSONResponse:
    body = await request.body()
    return JSONResponse(status_code=422, content={"body": body.decode()})


class HandledExcAfterResponse:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = PlainTextResponse("OK", status_code=200)
        await response(scope, receive, send)
        raise HTTPException(status_code=406)


router = Router(
    routes=[
        Route("/runtime_error", endpoint=raise_runtime_error),
        Route("/not_acceptable", endpoint=not_acceptable),
        Route("/no_content", endpoint=no_content),
        Route("/not_modified", endpoint=not_modified),
        Route("/with_headers", endpoint=with_headers),
        Route("/handled_exc_after_response", endpoint=HandledExcAfterResponse()),
        WebSocketRoute("/runtime_error", endpoint=raise_runtime_error),
        Route("/consume_body_in_endpoint_and_handler", endpoint=read_body_and_raise_exc, methods=["POST"]),
    ]
)


app = ExceptionMiddleware(
    router,
    handlers={BadBodyException: handler_that_reads_body},  # type: ignore[dict-item]
)


@pytest.fixture
def client(test_client_factory: TestClientFactory) -> Generator[TestClient, None, None]:
    with test_client_factory(app) as client:
        yield client


def test_not_acceptable(client: TestClient) -> None:
    response = client.get("/not_acceptable")
    assert response.status_code == 406
    assert response.text == "Not Acceptable"


def test_no_content(client: TestClient) -> None:
    response = client.get("/no_content")
    assert response.status_code == 204
    assert "content-length" not in response.headers


def test_not_modified(client: TestClient) -> None:
    response = client.get("/not_modified")
    assert response.status_code == 304
    assert response.text == ""


def test_with_headers(client: TestClient) -> None:
    response = client.get("/with_headers")
    assert response.status_code == 200
    assert response.headers["x-potato"] == "always"


def test_websockets_should_raise(client: TestClient) -> None:
    with pytest.raises(RuntimeError):
        with client.websocket_connect("/runtime_error"):
            pass  # pragma: no cover


def test_handled_exc_after_response(test_client_factory: TestClientFactory, client: TestClient) -> None:
    # A 406 HttpException is raised *after* the response has already been sent.
    # The exception middleware should raise a RuntimeError.
    with pytest.raises(RuntimeError, match="Caught handled exception, but response already started."):
        client.get("/handled_exc_after_response")

    # If `raise_server_exceptions=False` then the test client will still allow
    # us to see the response as it will have been seen by the client.
    allow_200_client = test_client_factory(app, raise_server_exceptions=False)
    response = allow_200_client.get("/handled_exc_after_response")
    assert response.status_code == 200
    assert response.text == "OK"


def test_force_500_response(test_client_factory: TestClientFactory) -> None:
    # use a sentinel variable to make sure we actually
    # make it into the endpoint and don't get a 500
    # from an incorrect ASGI app signature or something
    called = False

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal called
        called = True
        raise RuntimeError()

    force_500_client = test_client_factory(app, raise_server_exceptions=False)
    response = force_500_client.get("/")
    assert called
    assert response.status_code == 500
    assert response.text == ""


def test_http_str() -> None:
    assert str(HTTPException(status_code=404)) == "404: Not Found"
    assert str(HTTPException(404, "Not Found: foo")) == "404: Not Found: foo"
    assert str(HTTPException(404, headers={"key": "value"})) == "404: Not Found"


def test_http_repr() -> None:
    assert repr(HTTPException(404)) == ("HTTPException(status_code=404, detail='Not Found')")
    assert repr(HTTPException(404, detail="Not Found: foo")) == (
        "HTTPException(status_code=404, detail='Not Found: foo')"
    )

    class CustomHTTPException(HTTPException):
        pass

    assert repr(CustomHTTPException(500, detail="Something custom")) == (
        "CustomHTTPException(status_code=500, detail='Something custom')"
    )


def test_websocket_str() -> None:
    assert str(WebSocketException(1008)) == "1008: "
    assert str(WebSocketException(1008, "Policy Violation")) == "1008: Policy Violation"


def test_websocket_repr() -> None:
    assert repr(WebSocketException(1008, reason="Policy Violation")) == (
        "WebSocketException(code=1008, reason='Policy Violation')"
    )

    class CustomWebSocketException(WebSocketException):
        pass

    assert (
        repr(CustomWebSocketException(1013, reason="Something custom"))
        == "CustomWebSocketException(code=1013, reason='Something custom')"
    )


def test_request_in_app_and_handler_is_the_same_object(client: TestClient) -> None:
    response = client.post("/consume_body_in_endpoint_and_handler", content=b"Hello!")
    assert response.status_code == 422
    assert response.json() == {"body": "Hello!"}
