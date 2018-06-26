from starlette import Response, Path, PathPrefix, Router, TestClient


def homepage(scope):
    return Response("Hello, world", media_type="text/plain")


def users(scope):
    return Response("All users", media_type="text/plain")


def user(scope):
    content = "User " + scope["kwargs"]["username"]
    return Response(content, media_type="text/plain")


def staticfiles(scope):
    return Response("xxxxx", media_type="image/png")


app = Router(
    [
        Path("/", app=homepage, methods=["GET"]),
        PathPrefix(
            "/users", app=Router([Path("", app=users), Path("/{username}", app=user)])
        ),
        PathPrefix("/static", app=staticfiles, methods=["GET"]),
    ]
)


def test_router():
    client = TestClient(app)

    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "Hello, world"

    response = client.post("/")
    assert response.status_code == 406
    assert response.text == "Method not allowed"

    response = client.get("/foo")
    assert response.status_code == 404
    assert response.text == "Not found"

    response = client.get("/users")
    assert response.status_code == 200
    assert response.text == "All users"

    response = client.get("/users/tomchristie")
    assert response.status_code == 200
    assert response.text == "User tomchristie"

    response = client.get("/static/123")
    assert response.status_code == 200
    assert response.text == "xxxxx"

    response = client.post("/static/123")
    assert response.status_code == 406
    assert response.text == "Method not allowed"
