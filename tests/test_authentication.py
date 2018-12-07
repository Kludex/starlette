import base64
import binascii

from starlette.applications import Starlette
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
    UnauthenticatedUser,
    requires,
)
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import JSONResponse
from starlette.testclient import TestClient


class BasicAuth(AuthenticationBackend):
    async def authenticate(self, request):
        if "Authorization" not in request.headers:
            return None

        auth = request.headers["Authorization"]
        try:
            scheme, credentials = auth.split()
            decoded = base64.b64decode(credentials).decode("ascii")
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            raise AuthenticationError("Invalid basic auth credentials")

        username, _, password = decoded.partition(":")
        return AuthCredentials(["authenticated"]), SimpleUser(username)


app = Starlette()
app.add_middleware(AuthenticationMiddleware, backend=BasicAuth())


@app.route("/")
def homepage(request):
    return JSONResponse(
        {
            "authenticated": request.user.is_authenticated,
            "user": request.user.display_name,
        }
    )


@app.route("/dashboard")
@requires("authenticated")
async def dashboard(request):
    return JSONResponse(
        {
            "authenticated": request.user.is_authenticated,
            "user": request.user.display_name,
        }
    )


@app.route("/admin")
@requires("authenticated", redirect="homepage")
async def admin(request):
    return JSONResponse(
        {
            "authenticated": request.user.is_authenticated,
            "user": request.user.display_name,
        }
    )


@app.route("/dashboard/sync")
@requires("authenticated")
def dashboard(request):
    return JSONResponse(
        {
            "authenticated": request.user.is_authenticated,
            "user": request.user.display_name,
        }
    )


@app.route("/admin/sync")
@requires("authenticated", redirect="homepage")
def admin(request):
    return JSONResponse(
        {
            "authenticated": request.user.is_authenticated,
            "user": request.user.display_name,
        }
    )


def test_user_interface():
    with TestClient(app) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert response.json() == {"authenticated": False, "user": ""}

        response = client.get("/", auth=("tomchristie", "example"))
        assert response.status_code == 200
        assert response.json() == {"authenticated": True, "user": "tomchristie"}


def test_authentication_required():
    with TestClient(app) as client:
        response = client.get("/dashboard")
        assert response.status_code == 403

        response = client.get("/dashboard", auth=("tomchristie", "example"))
        assert response.status_code == 200
        assert response.json() == {"authenticated": True, "user": "tomchristie"}

        response = client.get("/dashboard/sync")
        assert response.status_code == 403

        response = client.get("/dashboard/sync", auth=("tomchristie", "example"))
        assert response.status_code == 200
        assert response.json() == {"authenticated": True, "user": "tomchristie"}

        response = client.get("/dashboard", headers={"Authorization": "basic foobar"})
        assert response.status_code == 400
        assert response.text == "Invalid basic auth credentials"


def test_authentication_redirect():
    with TestClient(app) as client:
        response = client.get("/admin")
        assert response.status_code == 200
        assert response.url == "http://testserver/"

        response = client.get("/admin", auth=("tomchristie", "example"))
        assert response.status_code == 200
        assert response.json() == {"authenticated": True, "user": "tomchristie"}

        response = client.get("/admin/sync")
        assert response.status_code == 200
        assert response.url == "http://testserver/"

        response = client.get("/admin/sync", auth=("tomchristie", "example"))
        assert response.status_code == 200
        assert response.json() == {"authenticated": True, "user": "tomchristie"}
