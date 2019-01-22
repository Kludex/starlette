import os

from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.endpoints import HTTPEndpoint
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route, Router, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.testclient import TestClient


class TrustedHostMiddleware:
    def __init__(self, app, hostname):
        self.app = app
        self.hostname = hostname

    def __call__(self, scope):
        headers = Headers(scope=scope)
        if headers.get("host") != self.hostname:
            return PlainTextResponse("Invalid host header", status_code=400)
        return self.app(scope)


app = Starlette()


app.add_middleware(TrustedHostMiddleware, hostname="testserver")


@app.exception_handler(500)
async def error_500(request, exc):
    return JSONResponse({"detail": "Server Error"}, status_code=500)


@app.exception_handler(405)
async def method_not_allowed(request, exc):
    return JSONResponse({"detail": "Custom message"}, status_code=405)


@app.exception_handler(HTTPException)
async def http_exception(request, exc):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.route("/func")
def func_homepage(request):
    return PlainTextResponse("Hello, world!")


@app.route("/async")
async def async_homepage(request):
    return PlainTextResponse("Hello, world!")


@app.route("/class")
class Homepage(HTTPEndpoint):
    def get(self, request):
        return PlainTextResponse("Hello, world!")


users = Router()


@users.route("/")
def all_users_page(request):
    return PlainTextResponse("Hello, everyone!")


@users.route("/{username}")
def user_page(request):
    username = request.path_params["username"]
    return PlainTextResponse(f"Hello, {username}!")


app.mount("/users", users)


@app.route("/500")
def runtime_error(request):
    raise RuntimeError()


@app.websocket_route("/ws")
async def websocket_endpoint(session):
    await session.accept()
    await session.send_text("Hello, world!")
    await session.close()


client = TestClient(app)


def test_url_path_for():
    assert app.url_path_for("func_homepage") == "/func"


def test_func_route():
    response = client.get("/func")
    assert response.status_code == 200
    assert response.text == "Hello, world!"

    response = client.head("/func")
    assert response.status_code == 200
    assert response.text == ""


def test_async_route():
    response = client.get("/async")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_class_route():
    response = client.get("/class")
    assert response.status_code == 200
    assert response.text == "Hello, world!"


def test_mounted_route():
    response = client.get("/users/")
    assert response.status_code == 200
    assert response.text == "Hello, everyone!"


def test_mounted_route_path_params():
    response = client.get("/users/tomchristie")
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
    assert response.json() == {"detail": "Custom message"}

    response = client.post("/class")
    assert response.status_code == 405
    assert response.json() == {"detail": "Custom message"}


def test_500():
    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/500")
    assert response.status_code == 500
    assert response.json() == {"detail": "Server Error"}


def test_middleware():
    client = TestClient(app, base_url="http://incorrecthost")
    response = client.get("/func")
    assert response.status_code == 400
    assert response.text == "Invalid host header"


def test_routes():
    assert app.routes == [
        Route("/func", endpoint=func_homepage, methods=["GET"]),
        Route("/async", endpoint=async_homepage, methods=["GET"]),
        Route("/class", endpoint=Homepage),
        Mount(
            "/users",
            app=Router(
                routes=[
                    Route("/", endpoint=all_users_page),
                    Route("/{username}", endpoint=user_page),
                ]
            ),
        ),
        Route("/500", endpoint=runtime_error, methods=["GET"]),
        WebSocketRoute("/ws", endpoint=websocket_endpoint),
    ]


def test_app_mount(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = Starlette()
    app.mount("/static", StaticFiles(directory=tmpdir))

    client = TestClient(app)

    response = client.get("/static/example.txt")
    assert response.status_code == 200
    assert response.text == "<file content>"

    response = client.post("/static/example.txt")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"


def test_app_debug():
    app = Starlette()
    app.debug = True

    @app.route("/")
    async def homepage(request):
        raise RuntimeError()

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/")
    assert response.status_code == 500
    assert "RuntimeError" in response.text
    assert app.debug


def test_app_add_route():
    app = Starlette()

    async def homepage(request):
        return PlainTextResponse("Hello, World!")

    app.add_route("/", homepage)
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, World!"


def test_app_add_websocket_route():
    app = Starlette()

    async def websocket_endpoint(session):
        await session.accept()
        await session.send_text("Hello, world!")
        await session.close()

    app.add_websocket_route("/ws", websocket_endpoint)
    client = TestClient(app)

    with client.websocket_connect("/ws") as session:
        text = session.receive_text()
        assert text == "Hello, world!"


def test_app_add_event_handler():
    startup_complete = False
    cleanup_complete = False
    app = Starlette()

    def run_startup():
        nonlocal startup_complete
        startup_complete = True

    def run_cleanup():
        nonlocal cleanup_complete
        cleanup_complete = True

    app.add_event_handler("startup", run_startup)
    app.add_event_handler("shutdown", run_cleanup)

    assert not startup_complete
    assert not cleanup_complete
    with TestClient(app):
        assert startup_complete
        assert not cleanup_complete
    assert startup_complete
    assert cleanup_complete
