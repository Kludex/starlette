import pytest
from starlette import App
from starlette.views import View
from starlette.response import PlainTextResponse
from starlette.testclient import TestClient


app = App()


@app.route("/")
@app.route("/{username}")
class Homepage(View):
    async def get(self, request, username=None):
        if username is None:
            return PlainTextResponse("Hello, world!")
        return PlainTextResponse(f"Hello, {username}!")


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
    assert response.status_code == 406
    assert response.text == "Method not allowed"
