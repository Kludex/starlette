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

    response = client.get("/view_session")
    assert response.json() == {"session": {}}
