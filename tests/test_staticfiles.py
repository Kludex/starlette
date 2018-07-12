from starlette import TestClient
from starlette.staticfiles import StaticFile, StaticFiles
import os
import pytest


def test_staticfile(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFile(path=path)
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == "<file content>"


def test_staticfile_post(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFile(path=path)
    client = TestClient(app)
    response = client.post("/")
    assert response.status_code == 406
    assert response.text == "Method not allowed"


def test_staticfile_with_directory_raises_error(tmpdir):
    app = StaticFile(path=tmpdir)
    client = TestClient(app)
    with pytest.raises(RuntimeError) as exc:
        response = client.get("/")
    assert "is not a file" in str(exc)


def test_staticfile_with_missing_file_raises_error(tmpdir):
    path = os.path.join(tmpdir, "404.txt")
    app = StaticFile(path=path)
    client = TestClient(app)
    with pytest.raises(RuntimeError) as exc:
        response = client.get("/")
    assert "does not exist" in str(exc)


def test_staticfiles(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    response = client.get("/example.txt")
    assert response.status_code == 200
    assert response.text == "<file content>"


def test_staticfiles_post(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    response = client.post("/example.txt")
    assert response.status_code == 406
    assert response.text == "Method not allowed"


def test_staticfiles_with_directory_returns_404(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 404
    assert response.text == "Not found"


def test_staticfiles_with_missing_file_returns_404(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    response = client.get("/404.txt")
    assert response.status_code == 404
    assert response.text == "Not found"


def test_staticfiles_configured_with_missing_directory(tmpdir):
    path = os.path.join(tmpdir, "no_such_directory")
    app = StaticFiles(directory=path)
    client = TestClient(app)
    with pytest.raises(RuntimeError) as exc:
        response = client.get("/example.txt")
    assert "does not exist" in str(exc)


def test_staticfiles_configured_with_file_instead_of_directory(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=path)
    client = TestClient(app)
    with pytest.raises(RuntimeError) as exc:
        response = client.get("/example.txt")
    assert "is not a directory" in str(exc)


def test_staticfiles_config_check_occurs_only_once(tmpdir):
    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    assert not app.config_checked
    response = client.get("/")
    assert app.config_checked
    response = client.get("/")
    assert app.config_checked


def test_staticfiles_prevents_breaking_out_of_directory(tmpdir):
    directory = os.path.join(tmpdir, 'foo')
    os.mkdir(directory)

    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("outside root dir")

    app = StaticFiles(directory=directory)
    # We can't test this with 'requests', so we call the app directly here.
    response = app({'method': 'GET', 'path': '/../example.txt'})
    assert response.status_code == 404
    assert response.body == b"Not found"
