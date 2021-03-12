import re

from starlette.applications import Starlette
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse
from starlette.testclient import TestClient


def view_session(request):
    return JSONResponse({"session": request.session})


async def update_session(request):
    data = await request.json()
    request.session.update(data)
    return JSONResponse({"session": request.session})


async def clear_session(request):
    request.session.clear()
    return JSONResponse({"session": request.session})


def create_app():
    app = Starlette()
    app.add_route("/view_session", view_session)
    app.add_route("/update_session", update_session, methods=["POST"])
    app.add_route("/clear_session", clear_session, methods=["POST"])
    return app


def test_session():
    app = create_app()
    app.add_middleware(SessionMiddleware, secret_key="example")
    client = TestClient(app)

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


def test_session_expires():
    app = create_app()
    app.add_middleware(SessionMiddleware, secret_key="example", max_age=-1)
    client = TestClient(app)

    response = client.post("/update_session", json={"some": "data"})
    assert response.json() == {"session": {"some": "data"}}

    # requests removes expired cookies from response.cookies, we need to
    # fetch session id from the headers and pass it explicitly
    expired_cookie_header = response.headers["set-cookie"]
    expired_session_value = re.search(r"session=([^;]*);", expired_cookie_header)[1]
    response = client.get("/view_session", cookies={"session": expired_session_value})
    assert response.json() == {"session": {}}


def test_secure_session():
    app = create_app()
    app.add_middleware(SessionMiddleware, secret_key="example", https_only=True)
    secure_client = TestClient(app, base_url="https://testserver")
    unsecure_client = TestClient(app, base_url="http://testserver")

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


def test_session_cookie_subpath():
    app = create_app()
    second_app = create_app()
    second_app.add_middleware(SessionMiddleware, secret_key="example")
    app.mount("/second_app", second_app)
    client = TestClient(app, base_url="http://testserver/second_app")
    response = client.post("second_app/update_session", json={"some": "data"})
    cookie = response.headers["set-cookie"]
    cookie_path = re.search(r"; path=(\S+);", cookie).groups()[0]
    assert cookie_path == "/second_app"
