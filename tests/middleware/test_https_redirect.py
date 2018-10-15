from starlette.applications import Starlette
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.responses import PlainTextResponse
from starlette.testclient import TestClient


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
