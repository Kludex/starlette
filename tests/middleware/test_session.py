import re

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.sessions import Session, SessionMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.testclient import TestClient
from tests.types import TestClientFactory


def view_session(request: Request) -> JSONResponse:
    return JSONResponse({"session": request.session})


async def update_session(request: Request) -> JSONResponse:
    data = await request.json()
    request.session.update(data)
    return JSONResponse({"session": request.session})


async def clear_session(request: Request) -> JSONResponse:
    request.session.clear()
    return JSONResponse({"session": request.session})


def no_session_access(request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok"})


def test_session(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/view_session", endpoint=view_session),
            Route("/update_session", endpoint=update_session, methods=["POST"]),
            Route("/clear_session", endpoint=clear_session, methods=["POST"]),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example")],
    )
    client = test_client_factory(app)

    response = client.get("/view_session")
    assert response.json() == {"session": {}}

    response = client.post("/update_session", json={"some": "data"})
    assert response.json() == {"session": {"some": "data"}}

    # check cookie max-age
    set_cookie = response.headers["set-cookie"]
    max_age_matches = re.search(r"; Max-Age=([0-9]+);", set_cookie)
    assert max_age_matches is not None
    assert int(max_age_matches[1]) == 14 * 24 * 3600

    response = client.get("/view_session")
    assert response.json() == {"session": {"some": "data"}}

    response = client.post("/clear_session")
    assert response.json() == {"session": {}}

    response = client.get("/view_session")
    assert response.json() == {"session": {}}


def test_session_expires(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/view_session", endpoint=view_session),
            Route("/update_session", endpoint=update_session, methods=["POST"]),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example", max_age=-1)],
    )
    client = test_client_factory(app)

    response = client.post("/update_session", json={"some": "data"})
    assert response.json() == {"session": {"some": "data"}}

    # requests removes expired cookies from response.cookies, we need to
    # fetch session id from the headers and pass it explicitly
    expired_cookie_header = response.headers["set-cookie"]
    expired_session_match = re.search(r"session=([^;]*);", expired_cookie_header)
    assert expired_session_match is not None
    expired_session_value = expired_session_match[1]
    client = test_client_factory(app, cookies={"session": expired_session_value})
    response = client.get("/view_session")
    assert response.json() == {"session": {}}


def test_secure_session(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/view_session", endpoint=view_session),
            Route("/update_session", endpoint=update_session, methods=["POST"]),
            Route("/clear_session", endpoint=clear_session, methods=["POST"]),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example", https_only=True)],
    )
    secure_client = test_client_factory(app, base_url="https://testserver")
    unsecure_client = test_client_factory(app, base_url="http://testserver")

    response = unsecure_client.get("/view_session")
    assert response.json() == {"session": {}}

    response = unsecure_client.post("/update_session", json={"some": "data"})
    assert response.json() == {"session": {"some": "data"}}

    response = unsecure_client.get("/view_session")
    assert response.json() == {"session": {}}

    response = secure_client.get("/view_session")
    assert response.json() == {"session": {}}

    response = secure_client.post("/update_session", json={"some": "data"})
    assert response.json() == {"session": {"some": "data"}}

    response = secure_client.get("/view_session")
    assert response.json() == {"session": {"some": "data"}}

    response = secure_client.post("/clear_session")
    assert response.json() == {"session": {}}

    response = secure_client.get("/view_session")
    assert response.json() == {"session": {}}


def test_session_cookie_subpath(test_client_factory: TestClientFactory) -> None:
    second_app = Starlette(
        routes=[
            Route("/update_session", endpoint=update_session, methods=["POST"]),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example", path="/second_app")],
    )
    app = Starlette(routes=[Mount("/second_app", app=second_app)])
    client = test_client_factory(app, base_url="http://testserver/second_app")
    response = client.post("/update_session", json={"some": "data"})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    cookie_path_match = re.search(r"; path=(\S+);", cookie)
    assert cookie_path_match is not None
    cookie_path = cookie_path_match.groups()[0]
    assert cookie_path == "/second_app"


def test_invalid_session_cookie(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/view_session", endpoint=view_session),
            Route("/update_session", endpoint=update_session, methods=["POST"]),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example")],
    )
    client = test_client_factory(app)

    response = client.post("/update_session", json={"some": "data"})
    assert response.json() == {"session": {"some": "data"}}

    # we expect it to not raise an exception if we provide a bogus session cookie
    client = test_client_factory(app, cookies={"session": "invalid"})
    response = client.get("/view_session")
    assert response.json() == {"session": {}}


def test_session_cookie(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/view_session", endpoint=view_session),
            Route("/update_session", endpoint=update_session, methods=["POST"]),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example", max_age=None)],
    )
    client: TestClient = test_client_factory(app)

    response = client.post("/update_session", json={"some": "data"})
    assert response.json() == {"session": {"some": "data"}}

    # check cookie max-age
    set_cookie = response.headers["set-cookie"]
    assert "Max-Age" not in set_cookie

    client.cookies.delete("session")
    response = client.get("/view_session")
    assert response.json() == {"session": {}}


def test_domain_cookie(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/view_session", endpoint=view_session),
            Route("/update_session", endpoint=update_session, methods=["POST"]),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example", domain=".example.com")],
    )
    client: TestClient = test_client_factory(app)

    response = client.post("/update_session", json={"some": "data"})
    assert response.json() == {"session": {"some": "data"}}

    # check cookie max-age
    set_cookie = response.headers["set-cookie"]
    assert "domain=.example.com" in set_cookie

    client.cookies.delete("session")
    response = client.get("/view_session")
    assert response.json() == {"session": {}}


def test_set_cookie_only_on_modification(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/view_session", endpoint=view_session),
            Route("/update_session", endpoint=update_session, methods=["POST"]),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example")],
    )
    client = test_client_factory(app)

    # Write to session - should send Set-Cookie
    response = client.post("/update_session", json={"some": "data"})
    assert "set-cookie" in response.headers

    # Read-only access - should NOT send Set-Cookie
    response = client.get("/view_session")
    assert response.json() == {"session": {"some": "data"}}
    assert "set-cookie" not in response.headers


def test_vary_cookie_on_access(test_client_factory: TestClientFactory) -> None:
    app = Starlette(
        routes=[
            Route("/view_session", endpoint=view_session),
            Route("/update_session", endpoint=update_session, methods=["POST"]),
            Route("/no_session", endpoint=no_session_access),
        ],
        middleware=[Middleware(SessionMiddleware, secret_key="example")],
    )
    client = test_client_factory(app)

    # Modifying session should add Vary: Cookie
    response = client.post("/update_session", json={"some": "data"})
    assert "cookie" in response.headers.get("vary", "").lower()

    # Reading a non-empty session should add Vary: Cookie
    response = client.get("/view_session")
    assert "cookie" in response.headers.get("vary", "").lower()

    # Not accessing session at all should NOT add Vary: Cookie
    response = client.get("/no_session")
    assert "cookie" not in response.headers.get("vary", "").lower()


def test_session_tracks_modification() -> None:
    session = Session({"a": "1", "b": "2"})
    assert not session.modified

    # __setitem__
    session["c"] = "3"
    assert session.modified

    # __delitem__
    session = Session({"a": "1"})
    del session["a"]
    assert session.modified

    # clear
    session = Session({"a": "1"})
    session.clear()
    assert session.modified

    # pop with existing key
    session = Session({"a": "1"})
    session.pop("a")
    assert session.modified

    # pop with missing key
    session = Session({"a": "1"})
    session.pop("missing", None)
    assert not session.modified

    # setdefault with missing key
    session = Session({"a": "1"})
    session.setdefault("b", "2")
    assert session.modified

    # setdefault with existing key
    session = Session({"a": "1"})
    session.setdefault("a", "2")
    assert not session.modified
