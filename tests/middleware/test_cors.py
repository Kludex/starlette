import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.types import ASGIApp
from tests.types import TestClientFactory


def test_cors_allow_all(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_headers=["*"],
                allow_methods=["*"],
                expose_headers=["X-Status"],
                allow_credentials=True,
            )
        ],
    )

    client = test_client_factory(app)

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
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["vary"] == "Origin"

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-expose-headers"] == "X-Status"
    assert response.headers["access-control-allow-credentials"] == "true"

    # Test standard credentialed response
    headers = {"Origin": "https://example.org", "Cookie": "star_cookie=sugar"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-expose-headers"] == "X-Status"
    assert response.headers["access-control-allow-credentials"] == "true"

    # Test non-CORS response
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers


def test_cors_allow_all_except_credentials(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_headers=["*"],
                allow_methods=["*"],
                expose_headers=["X-Status"],
            )
        ],
    )

    client = test_client_factory(app)

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
    assert "access-control-allow-credentials" not in response.headers
    assert "vary" not in response.headers

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.headers["access-control-expose-headers"] == "X-Status"
    assert "access-control-allow-credentials" not in response.headers

    # Test non-CORS response
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers


def test_cors_allow_specific_origin(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["https://example.org"],
                allow_headers=["X-Example", "Content-Type"],
            )
        ],
    )

    client = test_client_factory(app)

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
    assert response.headers["access-control-allow-headers"] == (
        "Accept, Accept-Language, Content-Language, Content-Type, X-Example"
    )
    assert "access-control-allow-credentials" not in response.headers

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert "access-control-allow-credentials" not in response.headers

    # Test non-CORS response
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers


def test_cors_disallowed_preflight(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> None:
        pass  # pragma: no cover

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["https://example.org"],
                allow_headers=["X-Example"],
            )
        ],
    )

    client = test_client_factory(app)

    # Test pre-flight response
    headers = {
        "Origin": "https://another.org",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "X-Nope",
    }
    response = client.options("/", headers=headers)
    assert response.status_code == 400
    assert response.text == "Disallowed CORS origin, method, headers"
    assert "access-control-allow-origin" not in response.headers

    # Bug specific test, https://github.com/Kludex/starlette/pull/1199
    # Test preflight response text with multiple disallowed headers
    headers = {
        "Origin": "https://example.org",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Nope-1, X-Nope-2",
    }
    response = client.options("/", headers=headers)
    assert response.text == "Disallowed CORS headers"


def test_preflight_allows_request_origin_if_origins_wildcard_and_credentials_allowed(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> None:
        return  # pragma: no cover

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["POST"],
                allow_credentials=True,
            )
        ],
    )

    client = test_client_factory(app)

    # Test pre-flight response
    headers = {
        "Origin": "https://example.org",
        "Access-Control-Request-Method": "POST",
    }
    response = client.options(
        "/",
        headers=headers,
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.headers["vary"] == "Origin"


def test_cors_preflight_allow_all_methods(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> None:
        pass  # pragma: no cover

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])],
    )

    client = test_client_factory(app)

    for method in ("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY"):
        headers = {
            "Origin": "https://example.org",
            "Access-Control-Request-Method": method,
        }
        response = client.options("/", headers=headers)
        assert response.status_code == 200
        assert method in response.headers["access-control-allow-methods"]


def test_cors_allow_all_methods(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[
            Route(
                "/",
                endpoint=homepage,
                methods=["delete", "get", "head", "options", "patch", "post", "put"],
            )
        ],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])],
    )

    client = test_client_factory(app)

    headers = {"Origin": "https://example.org"}

    for method in ("patch", "post", "put"):
        response = getattr(client, method)("/", headers=headers, json={})
        assert response.status_code == 200
    for method in ("delete", "get", "head", "options"):
        response = getattr(client, method)("/", headers=headers)
        assert response.status_code == 200


def test_cors_allow_origin_regex(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_headers=["X-Example", "Content-Type"],
                allow_origin_regex="https://.*",
                allow_credentials=True,
            )
        ],
    )

    client = test_client_factory(app)

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-allow-credentials"] == "true"

    # Test standard credentialed response
    headers = {"Origin": "https://example.org", "Cookie": "star_cookie=sugar"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-allow-credentials"] == "true"

    # Test disallowed standard response
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
    assert response.headers["access-control-allow-headers"] == (
        "Accept, Accept-Language, Content-Language, Content-Type, X-Example"
    )
    assert response.headers["access-control-allow-credentials"] == "true"

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


def test_cors_allow_origin_regex_fullmatch(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_headers=["X-Example", "Content-Type"],
                allow_origin_regex=r"https://.*\.example.org",
            )
        ],
    )

    client = test_client_factory(app)

    # Test standard response
    headers = {"Origin": "https://subdomain.example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://subdomain.example.org"
    assert "access-control-allow-credentials" not in response.headers

    # Test disallowed standard response
    headers = {"Origin": "https://subdomain.example.org.hacker.com"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers


def test_cors_vary_header_defaults_to_origin(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["https://example.org"])],
    )

    headers = {"Origin": "https://example.org"}

    client = test_client_factory(app)

    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.headers["vary"] == "Origin"


def test_cors_vary_header_is_set_for_non_credentialed_request(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200, headers={"Vary": "Accept-Encoding"})

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"])],
    )
    client = test_client_factory(app)

    response = client.get("/", headers={"Origin": "https://someplace.org"})
    assert response.status_code == 200
    assert response.headers["vary"] == "Accept-Encoding, Origin"


def test_cors_vary_header_is_properly_set_for_credentialed_request(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200, headers={"Vary": "Accept-Encoding"})

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)],
    )
    client = test_client_factory(app)

    response = client.get("/", headers={"Origin": "https://someplace.org"})
    assert response.status_code == 200
    assert response.headers["vary"] == "Accept-Encoding, Origin"


def test_cors_vary_header_is_properly_set_when_allow_origins_is_not_wildcard(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200, headers={"Vary": "Accept-Encoding"})

    app = Starlette(
        routes=[
            Route("/", endpoint=homepage),
        ],
        middleware=[Middleware(CORSMiddleware, allow_origins=["https://example.org"])],
    )
    client = test_client_factory(app)

    response = client.get("/", headers={"Origin": "https://example.org"})
    assert response.status_code == 200
    assert response.headers["vary"] == "Accept-Encoding, Origin"


def test_cors_allowed_origin_does_not_leak_between_requests(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["https://example.org"])],
    )

    client = test_client_factory(app)

    response = client.get("/", headers={"Origin": "https://example.org"})
    assert response.headers["access-control-allow-origin"] == "https://example.org"

    response = client.get("/", headers={"Origin": "https://other.org"})
    assert "access-control-allow-origin" not in response.headers

    response = client.get("/", headers={"Origin": "https://example.org"})
    assert response.headers["access-control-allow-origin"] == "https://example.org"


def test_cors_private_network_access_allowed(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["*"],
                allow_private_network=True,
            )
        ],
    )

    client = test_client_factory(app)

    headers_without_pna = {"Origin": "https://example.org", "Access-Control-Request-Method": "GET"}
    headers_with_pna = {**headers_without_pna, "Access-Control-Request-Private-Network": "true"}

    # Test preflight with Private Network Access request
    response = client.options("/", headers=headers_with_pna)
    assert response.status_code == 200
    assert response.text == "OK"
    assert response.headers["access-control-allow-private-network"] == "true"

    # Test preflight without Private Network Access request
    response = client.options("/", headers=headers_without_pna)
    assert response.status_code == 200
    assert response.text == "OK"
    assert "access-control-allow-private-network" not in response.headers

    # The access-control-allow-private-network header is not set for non-preflight requests
    response = client.get("/", headers=headers_with_pna)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-private-network" not in response.headers
    assert "access-control-allow-origin" in response.headers


def test_cors_private_network_access_disallowed(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> None: ...  # pragma: no cover

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["*"],
                allow_private_network=False,
            )
        ],
    )

    client = test_client_factory(app)

    # Test preflight with Private Network Access request when not allowed
    headers_without_pna = {"Origin": "https://example.org", "Access-Control-Request-Method": "GET"}
    headers_with_pna = {**headers_without_pna, "Access-Control-Request-Private-Network": "true"}

    response = client.options("/", headers=headers_without_pna)
    assert response.status_code == 200
    assert response.text == "OK"
    assert "access-control-allow-private-network" not in response.headers

    # If the request includes a Private Network Access header, but the middleware is configured to disallow it, the
    # request should be denied with a 400 response.
    response = client.options("/", headers=headers_with_pna)
    assert response.status_code == 400
    assert response.text == "Disallowed CORS private-network"
    assert "access-control-allow-private-network" not in response.headers


@pytest.mark.parametrize(
    "allow_origins,allow_credentials,origin,expected_origin,vary_headers",
    [
        (
            ["https://example.org"],
            False,
            "https://example.org",
            "https://example.org",
            ["Accept-Encoding", "Accept-Language"],
        ),
        (["https://example.org"], False, "https://denied.example", None, ["Accept-Encoding", "Accept-Language"]),
        (["https://example.org"], False, None, None, []),
        (["*"], False, "https://example.org", "*", ["*"]),
        (["*"], False, None, None, []),
        (["*"], True, "https://example.org", "https://example.org", []),
        (["*"], True, None, None, []),
    ],
)
def test_cors_vary_origin(
    test_client_factory: TestClientFactory,
    allow_origins: list[str],
    allow_credentials: bool,
    origin: str | None,
    expected_origin: str | None,
    vary_headers: list[str],
) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        response = PlainTextResponse("Homepage")
        for vary in vary_headers:
            response.headers.append("Vary", vary)
        return response

    app = CORSMiddleware(
        Starlette(routes=[Route("/", homepage)]),
        allow_origins=allow_origins,
        allow_credentials=allow_credentials,
    )
    client = test_client_factory(app)
    response = client.get("/", headers={"Origin": origin} if origin is not None else {})

    assert response.status_code == 200
    assert response.text == "Homepage"
    assert {value.strip() for value in response.headers["vary"].split(",")} == {*vary_headers, "Origin"}
    assert response.headers.get("access-control-allow-origin") == expected_origin
    assert response.headers.get("access-control-allow-credentials") == (
        "true" if allow_credentials and origin is not None else None
    )


def test_cors_vary_origin_on_options_without_origin(test_client_factory: TestClientFactory) -> None:
    async def options(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Application OPTIONS")

    app = CORSMiddleware(
        Starlette(routes=[Route("/", options, methods=["OPTIONS"])]),
        allow_origins=["https://allowed.example"],
    )
    client = test_client_factory(app)
    response = client.options("/", headers={"Access-Control-Request-Method": "GET"})

    assert response.status_code == 200
    assert response.text == "Application OPTIONS"
    assert response.headers["vary"] == "Origin"


@pytest.mark.parametrize("cors_outermost", [True, False])
def test_cors_vary_origin_with_gzip(test_client_factory: TestClientFactory, cors_outermost: bool) -> None:
    async def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", headers={"Vary": "Accept-Language"})

    app: ASGIApp = Starlette(routes=[Route("/", homepage)])
    if cors_outermost:
        app = CORSMiddleware(GZipMiddleware(app, minimum_size=0), allow_origins=["https://allowed.example"])
    else:
        app = GZipMiddleware(CORSMiddleware(app, allow_origins=["https://allowed.example"]), minimum_size=0)

    client = test_client_factory(app)
    response = client.get("/", headers={"Origin": "https://allowed.example", "Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["content-encoding"] == "gzip"
    assert response.headers["access-control-allow-origin"] == "https://allowed.example"
    assert {value.strip() for value in response.headers["vary"].split(",")} == {
        "Accept-Language",
        "Accept-Encoding",
        "Origin",
    }
