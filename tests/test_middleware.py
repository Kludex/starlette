from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
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


def test_cors_allow_all():
    app = Starlette()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_headers=["*"],
        allow_methods=["*"],
        expose_headers=["X-Status"],
        allow_credentials=True,
    )

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("Homepage", status_code=200)

    client = TestClient(app)

    # Test pre-flight response
    headers = {
        "Origin": "https://example.org",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Example",
    }
    response = client.options("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "OK"
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.headers["access-control-allow-headers"] == "X-Example"

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.headers["access-control-expose-headers"] == "X-Status"

    # Test non-CORS response
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers


def test_cors_allow_specific_origin():
    app = Starlette()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://example.org"],
        allow_headers=["X-Example"],
    )

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("Homepage", status_code=200)

    client = TestClient(app)

    # Test pre-flight response
    headers = {
        "Origin": "https://example.org",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Example",
    }
    response = client.options("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "OK"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-allow-headers"] == "X-Example"

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"

    # Test non-CORS response
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers


def test_cors_disallowed_preflight():
    app = Starlette()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://example.org"],
        allow_headers=["X-Example"],
    )

    @app.route("/")
    def homepage(request):
        pass  # pragma: no cover

    client = TestClient(app)

    # Test pre-flight response
    headers = {
        "Origin": "https://another.org",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Nope",
    }
    response = client.options("/", headers=headers)
    assert response.status_code == 400
    assert response.text == "Disallowed CORS origin, method, headers"
