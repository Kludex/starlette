from starlette.applications import Starlette
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import PlainTextResponse


def test_trusted_host_middleware(test_client_factory):
    app = Starlette()

    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["testserver", "*.testserver"]
    )

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("OK", status_code=200)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(app, base_url="http://subdomain.testserver")
    response = client.get("/")
    assert response.status_code == 200

    client = test_client_factory(app, base_url="http://invalidhost")
    response = client.get("/")
    assert response.status_code == 400


def test_default_allowed_hosts():
    app = Starlette()
    middleware = TrustedHostMiddleware(app)
    assert middleware.allowed_hosts == ["*"]


def test_www_redirect(test_client_factory):
    app = Starlette()

    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["www.example.com"])

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("OK", status_code=200)

    client = test_client_factory(app, base_url="https://example.com")
    response = client.get("/")
    assert response.status_code == 200
    assert response.url == "https://www.example.com/"
