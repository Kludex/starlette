from httpx import Response

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import ALL_METHODS, CORSMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from tests.types import TestClientFactory


def assert_vary(response: Response, expected: set[str] | None) -> None:
    vary_header = response.headers.get("vary")
    if expected is None:
        assert vary_header is None
        return

    assert vary_header is not None
    actual = {value.strip() for value in vary_header.split(",") if value.strip()}
    assert actual == expected


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
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-allow-headers"] == "X-Example"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert_vary(
        response,
        {"Access-Control-Request-Headers", "Access-Control-Request-Private-Network", "Origin"},
    )
    allowed_methods = {method.strip() for method in response.headers["access-control-allow-methods"].split(",")}
    assert allowed_methods == ALL_METHODS

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert response.headers["access-control-expose-headers"] == "X-Status"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert_vary(response, {"Origin"})

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
    assert_vary(
        response,
        {"Access-Control-Request-Headers", "Access-Control-Request-Private-Network"},
    )

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "*"
    assert response.headers["access-control-expose-headers"] == "X-Status"
    assert "access-control-allow-credentials" not in response.headers
    assert_vary(response, None)

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
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    allowed_headers = {h.strip() for h in response.headers["access-control-allow-headers"].split(",")}
    assert allowed_headers == {"Accept", "Accept-Language", "Content-Language", "Content-Type", "X-Example"}
    assert "access-control-allow-credentials" not in response.headers
    assert_vary(
        response,
        {
            "Access-Control-Request-Headers",
            "Access-Control-Request-Private-Network",
            "Access-Control-Request-Method",
            "Origin",
        },
    )
    assert response.headers["access-control-allow-methods"] == "GET"

    # Test standard response
    headers = {"Origin": "https://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert "access-control-allow-credentials" not in response.headers
    assert_vary(response, {"Origin"})

    # Test disallowed standard response
    headers = {"Origin": "https://another.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers
    assert_vary(response, {"Origin"})

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
    assert_vary(
        response,
        {
            "Access-Control-Request-Headers",
            "Access-Control-Request-Private-Network",
            "Access-Control-Request-Method",
            "Origin",
        },
    )

    # Bug specific test, https://github.com/Kludex/starlette/pull/1199
    # Test preflight response text with multiple disallowed headers
    headers = {
        "Origin": "https://example.org",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Nope-1, X-Nope-2",
    }
    response = client.options("/", headers=headers)
    assert response.text == "Disallowed CORS headers"


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

    headers = {
        "Origin": "https://example.org",
        "Access-Control-Request-Method": "POST",
    }

    response = client.options("/", headers=headers)
    assert response.status_code == 200
    allowed_methods = {m.strip() for m in response.headers["access-control-allow-methods"].split(",")}
    for method in ("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"):
        assert method in allowed_methods


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
    assert_vary(response, {"Origin"})

    # Test disallowed standard response
    # Note that enforcement is a browser concern. The disallowed-ness is reflected
    # in the lack of an "access-control-allow-origin" header in the response.
    headers = {"Origin": "http://example.org"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers
    assert_vary(response, {"Origin"})

    # Test pre-flight response
    headers = {
        "Origin": "https://another.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-Example, content-type",
    }
    response = client.options("/", headers=headers)
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://another.com"
    allowed_headers = {h.strip() for h in response.headers["access-control-allow-headers"].split(",")}
    assert allowed_headers == {"Accept", "Accept-Language", "Content-Language", "Content-Type", "X-Example"}
    assert response.headers["access-control-allow-credentials"] == "true"
    assert_vary(
        response,
        {
            "Access-Control-Request-Headers",
            "Access-Control-Request-Private-Network",
            "Access-Control-Request-Method",
            "Origin",
        },
    )

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
    assert_vary(response, {"Origin"})

    # Test disallowed standard response
    headers = {"Origin": "https://subdomain.example.org.hacker.com"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.text == "Homepage"
    assert "access-control-allow-origin" not in response.headers
    assert_vary(response, {"Origin"})


def test_cors_vary_header_behavior(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200, headers={"Vary": "Accept-Encoding"})

    # Test 1: Specific origins add Vary: Origin
    app_specific = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["https://example.org"])],
    )
    client = test_client_factory(app_specific)

    response = client.get("/", headers={"Origin": "https://example.org"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://example.org"
    assert_vary(response, {"Accept-Encoding", "Origin"})

    # Test 2: Wildcard without credentials does not add Vary: Origin
    app_wildcard = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"])],
    )
    client = test_client_factory(app_wildcard)

    response = client.get("/", headers={"Origin": "https://someplace.org"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
    assert_vary(response, {"Accept-Encoding"})

    # Test 3: Wildcard with credentials adds Vary: Origin
    app_wildcard_creds = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)],
    )
    client = test_client_factory(app_wildcard_creds)

    response = client.get("/", headers={"Cookie": "foo=bar", "Origin": "https://someplace.org"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://someplace.org"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert_vary(response, {"Accept-Encoding", "Origin"})


def test_cors_preflight_vary_with_wildcard_origins_specific_methods(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> None:
        pass  # pragma: no cover

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"])],
    )
    client = test_client_factory(app)

    # Preflight Vary should include Request-Method even with wildcard origins when methods are restricted
    response = client.options("/", headers={"Origin": "https://example.org", "Access-Control-Request-Method": "POST"})
    assert response.status_code == 200
    assert_vary(
        response,
        {"Access-Control-Request-Headers", "Access-Control-Request-Private-Network", "Access-Control-Request-Method"},
    )


def test_cors_preflight_vary_with_specific_origins_wildcard_methods(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> None:
        pass  # pragma: no cover

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["https://example.org"], allow_methods=["*"])],
    )
    client = test_client_factory(app)

    # Preflight Vary should NOT include Request-Method when methods are unrestricted
    response = client.options("/", headers={"Origin": "https://example.org", "Access-Control-Request-Method": "POST"})
    assert response.status_code == 200
    assert_vary(
        response,
        {"Access-Control-Request-Headers", "Access-Control-Request-Private-Network", "Origin"},
    )


def test_cors_allowed_origin_does_not_leak_between_credentialed_requests(
    test_client_factory: TestClientFactory,
) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[
            Route("/", endpoint=homepage),
        ],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_headers=["*"],
                allow_methods=["*"],
                allow_credentials=True,
            )
        ],
    )

    client = test_client_factory(app)
    first_origin = "https://first.example"
    second_origin = "https://second.example"

    response = client.get("/", headers={"Origin": first_origin})
    assert response.headers["access-control-allow-origin"] == first_origin
    assert response.headers["access-control-allow-credentials"] == "true"

    response = client.get("/", headers={"Cookie": "foo=bar", "Origin": second_origin})
    assert response.headers["access-control-allow-origin"] == second_origin
    assert response.headers["access-control-allow-credentials"] == "true"

    response = client.get("/", headers={"Origin": first_origin})
    assert response.headers["access-control-allow-origin"] == first_origin
    assert response.headers["access-control-allow-credentials"] == "true"


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
    assert_vary(
        response,
        {"Access-Control-Request-Headers", "Access-Control-Request-Private-Network"},
    )

    # Test preflight without Private Network Access request
    response = client.options("/", headers=headers_without_pna)
    assert response.status_code == 200
    assert response.text == "OK"
    assert "access-control-allow-private-network" not in response.headers
    assert_vary(
        response,
        {"Access-Control-Request-Headers", "Access-Control-Request-Private-Network"},
    )

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
    assert_vary(
        response,
        {"Access-Control-Request-Headers", "Access-Control-Request-Private-Network"},
    )


def test_cors_null_origin_rejection(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    # Test 1: Null rejected with wildcard origins
    app_wildcard = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"])],
    )
    client = test_client_factory(app_wildcard)

    response = client.options("/", headers={"Origin": "null", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 400
    assert "origin" in response.text.lower()

    response = client.get("/", headers={"Origin": "null"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers

    # Test 2: Null rejected with regex that matches everything
    app_regex = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origin_regex=r".*")],
    )
    client = test_client_factory(app_regex)

    response = client.options("/", headers={"Origin": "null", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 400
    assert "origin" in response.text.lower()

    # Test 3: Null rejected even when regex explicitly includes it
    app_regex_explicit = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origin_regex=r"null|https://.*")],
    )
    client = test_client_factory(app_regex_explicit)

    response = client.options("/", headers={"Origin": "null", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 400
    assert "origin" in response.text.lower()

    # Verify HTTPS origins still work with the regex
    response = client.get("/", headers={"Origin": "https://example.org"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://example.org"


def test_cors_null_origin_explicitly_allowed(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["null", "https://example.org"])],
    )

    client = test_client_factory(app)

    # Null origin should be allowed when explicitly whitelisted
    response = client.options("/", headers={"Origin": "null", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "null"

    # Simple request should also allow null origin
    response = client.get("/", headers={"Origin": "null"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "null"


def test_cors_method_case_sensitive(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> None:
        pass  # pragma: no cover

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["https://example.org"], allow_methods=["POST"])],
    )

    client = test_client_factory(app)

    # Uppercase POST should be allowed
    response = client.options("/", headers={"Origin": "https://example.org", "Access-Control-Request-Method": "POST"})
    assert response.status_code == 200

    # Lowercase "post" should be rejected (methods are case-sensitive per HTTP spec)
    response = client.options("/", headers={"Origin": "https://example.org", "Access-Control-Request-Method": "post"})
    assert response.status_code == 400
    assert "method" in response.text.lower()


def test_cors_empty_origins_list(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=[])],
    )
    client = test_client_factory(app)

    response = client.options("/", headers={"Origin": "https://example.org", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers
    assert_vary(
        response,
        {
            "Access-Control-Request-Headers",
            "Access-Control-Request-Private-Network",
            "Access-Control-Request-Method",
            "Origin",
        },
    )

    response = client.get("/", headers={"Origin": "https://example.org"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert_vary(response, {"Origin"})


def test_cors_origins_list_and_regex_both_accepted(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[
            Middleware(
                CORSMiddleware,
                allow_origins=["https://example.org"],
                allow_origin_regex=r"https://.*\.trusted\.com",
            )
        ],
    )
    client = test_client_factory(app)

    # Origin in explicit list should be accepted
    response = client.get("/", headers={"Origin": "https://example.org"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://example.org"

    # Origin matching regex should be accepted
    response = client.get("/", headers={"Origin": "https://api.trusted.com"})
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://api.trusted.com"

    # Origin matching neither should be rejected
    response = client.get("/", headers={"Origin": "https://evil.com"})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_cors_max_age_header(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> None:
        pass  # pragma: no cover

    app_default = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"])],
    )
    client = test_client_factory(app_default)

    response = client.options("/", headers={"Origin": "https://example.org", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 200
    assert response.headers["access-control-max-age"] == "600"

    app_custom = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"], max_age=7200)],
    )
    client = test_client_factory(app_custom)

    response = client.options("/", headers={"Origin": "https://example.org", "Access-Control-Request-Method": "GET"})
    assert response.status_code == 200
    assert response.headers["access-control-max-age"] == "7200"


def test_cors_no_origin_header_no_cors_processing(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> PlainTextResponse:
        return PlainTextResponse("Homepage", status_code=200)

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"])],
    )
    client = test_client_factory(app)

    response = client.get("/")
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers
    assert_vary(response, None)


def test_cors_header_name_case_insensitive(test_client_factory: TestClientFactory) -> None:
    def homepage(request: Request) -> None:
        pass  # pragma: no cover

    app = Starlette(
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CORSMiddleware, allow_origins=["*"], allow_headers=["X-Custom-Header"])],
    )
    client = test_client_factory(app)

    response = client.options(
        "/",
        headers={
            "Origin": "https://example.org",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-custom-header",
        },
    )
    assert response.status_code == 200
