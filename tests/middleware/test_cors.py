from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse
from starlette.testclient import TestClient


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
        allow_headers=["X-Example", "Content-Type"],
    )

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("Homepage", status_code=200)

    client = TestClient(app)

    # Test pre-flight response
    headers = {
        "Origin": "https://example.org",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Example, Content-Type",
    }
    response = client.options("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "OK"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-allow-headers"] == "X-Example, Content-Type"

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


def test_cors_allow_origin_regex():
    app = Starlette()

    app.add_middleware(
        CORSMiddleware,
        allow_headers=["X-Example", "Content-Type"],
        allow_origin_regex="https://.*",
    )

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("Homepage", status_code=200)

    client = TestClient(app)

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"

    # Test diallowed standard response
    # Note that enforcement is a browser concern. The disallowed-ness is reflected
    # in the lack of an "access-control-allow-origin" header in the response.
    headers = {"Origin": "http://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers

    # Test pre-flight response
    headers = {
        "Origin": "https://another.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Example, content-type",
    }
    response = client.options("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "OK"
    assert response.headers["access-control-allow-origin"] == "https://another.com"
    assert response.headers["access-control-allow-headers"] == "X-Example, Content-Type"

    # Test disallowed pre-flight response
    headers = {
        "Origin": "http://another.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Example",
    }
    response = client.options("/", headers=headers)
    assert response.status_code == 400
    assert response.text == "Disallowed CORS origin"
    assert "access-control-allow-origin" not in response.headers


def test_cors_allow_origin_regex_fullmatch():
    app = Starlette()

    app.add_middleware(
        CORSMiddleware,
        allow_headers=["X-Example", "Content-Type"],
        allow_origin_regex="https://.*\.example.org",
    )

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("Homepage", status_code=200)

    client = TestClient(app)

    # Test standard response
    headers = {"Origin": "https://subdomain.example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert (
        response.headers["access-control-allow-origin"]
        == "https://subdomain.example.org"
    )

    # Test diallowed standard response
    headers = {"Origin": "https://subdomain.example.org.hacker.com"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers


def test_cors_credentialed_requests_return_specific_origin():
    app = Starlette()

    app.add_middleware(CORSMiddleware, allow_origins=["*"])

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("Homepage", status_code=200)

    client = TestClient(app)

    # Test credentialed request
    headers = {"Origin": "https://example.org", "Cookie": "star_cookie=sugar"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"


def test_cors_vary_header_defaults_to_origin():
    app = Starlette()

    app.add_middleware(CORSMiddleware, allow_origins=["https://example.org"])

    headers = {"Origin": "https://example.org"}

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("Homepage", status_code=200)

    client = TestClient(app)

    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.headers["vary"] == "Origin"


def test_cors_vary_header_is_properly_set():
    app = Starlette()

    app.add_middleware(CORSMiddleware, allow_origins=["https://example.org"])

    headers = {"Origin": "https://example.org"}

    @app.route("/")
    def homepage(request):
        return PlainTextResponse(
            "Homepage", status_code=200, headers={"Vary": "Accept-Encoding"}
        )

    client = TestClient(app)

    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.headers["vary"] == "Accept-Encoding, Origin"


def test_cors_allowed_origin_does_not_leak_between_credentialed_requests():
    app = Starlette()
    app.add_middleware(
        CORSMiddleware, allow_origins=["*"], allow_headers=["*"], allow_methods=["*"]
    )

    @app.route("/")
    def homepage(request):
        return PlainTextResponse("Homepage", status_code=200)

    client = TestClient(app)
    response = client.get("/", headers={"Origin": "https://someplace.org"})
    assert response.headers["access-control-allow-origin"] == "*"

    response = client.get(
        "/", headers={"Cookie": "foo=bar", "Origin": "https://someplace.org"}
    )
    assert response.headers["access-control-allow-origin"] == "https://someplace.org"

    response = client.get("/", headers={"Origin": "https://someplace.org"})
    assert response.headers["access-control-allow-origin"] == "*"
