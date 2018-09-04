from starlette import App
from starlette.exceptions import HTTPException
from starlette.response import JSONResponse, PlainTextResponse
from starlette.staticfiles import StaticFiles
from starlette.testclient import TestClient
from starlette.views import View
import os


app = App()


@app.exception_handler(Exception)
async def error_500(request, exc):
    return JSONResponse({"detail": "Server Error"}, status_code=500)


@app.exception_handler(HTTPException)
async def handler(request, exc):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.route("/func")
def func_homepage(request):
    return PlainTextResponse("Hello, world!")


@app.route("/async")
async def async_homepage(request):
    return PlainTextResponse("Hello, world!")


@app.route("/class")
class Homepage(View):
    def get(self, request):
        return PlainTextResponse("Hello, world!")


@app.route("/user/{username}")
def user_page(request, username):
    return PlainTextResponse("Hello, %s!" % username)


@app.route("/500")
def func_homepage(request):
    raise RuntimeError()


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


def test_class_route():
    response = client.get("/class")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_route_kwargs():
    response = client.get("/user/tomchristie")
    assert response.status_code == 200
    assert response.text == "Hello, tomchristie!"


def test_websocket_route():
    with client.websocket_connect("/ws") as session:
        text = session.receive_text()
        assert text == "Hello, world!"


def test_400():
    response = client.get("/404")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_405():
    response = client.post("/func")
    assert response.status_code == 405
    assert response.json() == {"detail": "Method Not Allowed"}

    response = client.post("/class")
    assert response.status_code == 405
    assert response.json() == {"detail": "Method Not Allowed"}


def test_500():
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/500")
    assert response.status_code == 500
    assert response.json() == {"detail": "Server Error"}


def test_app_mount(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = App()
    app.mount("/static", StaticFiles(directory=tmpdir), methods=["GET", "HEAD"])
    client = TestClient(app)

    response = client.get("/static/example.txt")
    assert response.status_code == 200
    assert response.text == "<file content>"

    response = client.post("/static/example.txt")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"


def test_app_debug():
    app = App()
    app.debug = True

    @app.route("/")
    async def homepage(request):
        raise RuntimeError()

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 500
    assert "RuntimeError" in response.text
    assert app.debug
