import pytest
from starlette.responses import PlainTextResponse
from starlette.routing import Router, Path
from starlette.testclient import TestClient
from starlette.endpoints import HTTPEndpoint


class Homepage(HTTPEndpoint):
    async def get(self, request, username=None):
        if username is None:
            return PlainTextResponse("Hello, world!")
        return PlainTextResponse(f"Hello, {username}!")


app = Router(routes=[Path("/", Homepage), Path("/{username}", Homepage)])

client = TestClient(app)


def test_route():
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_route_kwargs():
    response = client.get("/tomchristie")
    assert response.status_code == 200
    assert response.text == "Hello, tomchristie!"


def test_route_method():
    response = client.post("/")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"
