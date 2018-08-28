from starlette import App
from starlette.response import PlainTextResponse
from starlette.staticfiles import StaticFiles
from starlette.testclient import TestClient
import os


app = App()


@app.route("/func")
def func_homepage(request):
    return PlainTextResponse("Hello, world!")


@app.route("/async")
async def async_homepage(request):
    return PlainTextResponse("Hello, world!")


@app.route("/user/{username}")
def user_page(request, username):
    return PlainTextResponse("Hello, %s!" % username)


@app.websocket_route("/ws")
async def websocket_endpoint(session):
    await session.accept()
    await session.send_text("Hello, world!")
    await session.close()


client = TestClient(app)


def test_func_route():
    response = client.get("/func")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_async_route():
    response = client.get("/async")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_route_kwargs():
    response = client.get("/user/tomchristie")
    assert response.status_code == 200
    assert response.text == "Hello, tomchristie!"


def test_websocket_route():
    with client.wsconnect("/ws") as session:
        text = session.receive_text()
        assert text == "Hello, world!"


def test_400():
    response = client.get("/404")
    assert response.status_code == 404


def test_app_mount(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = App()
    app.mount("/static", StaticFiles(directory=tmpdir))
    client = TestClient(app)
    response = client.get("/static/example.txt")
    assert response.status_code == 200
    assert response.text == "<file content>"
