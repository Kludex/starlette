from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.responses import PlainTextResponse
from starlette.testclient import TestClient


def test_trusted_host_middleware():
    app = Starlette()

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["testserver"])

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("OK", status_code=200)

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200

    client = TestClient(app, base_url="http://invalidhost")
    response = client.get("/")
    assert response.status_code == 400


def test_https_redirect_middleware():
    app = Starlette()

    app.add_middleware(HTTPSRedirectMiddleware)

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("OK", status_code=200)

    client = TestClient(app, base_url="https://testserver")
    response = client.get("/")
    assert response.status_code == 200

    client = TestClient(app)
    response = client.get("/", allow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == "https://testserver/"
