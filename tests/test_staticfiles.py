import os
import time

import pytest

from starlette.staticfiles import StaticFiles
from starlette.testclient import TestClient


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
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"


def test_staticfiles_with_directory_returns_404(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 404
    assert response.text == "Not Found"


def test_staticfiles_with_missing_file_returns_404(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    response = client.get("/404.txt")
    assert response.status_code == 404
    assert response.text == "Not Found"


def test_staticfiles_instantiated_with_missing_directory(tmpdir):
    with pytest.raises(RuntimeError) as exc:
        path = os.path.join(tmpdir, "no_such_directory")
        app = StaticFiles(directory=path)
    assert "does not exist" in str(exc)


def test_staticfiles_configured_with_missing_directory(tmpdir):
    path = os.path.join(tmpdir, "no_such_directory")
    app = StaticFiles(directory=path, check_dir=False)
    client = TestClient(app)
    with pytest.raises(RuntimeError) as exc:
        client.get("/example.txt")
    assert "does not exist" in str(exc)


def test_staticfiles_configured_with_file_instead_of_directory(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=path, check_dir=False)
    client = TestClient(app)
    with pytest.raises(RuntimeError) as exc:
        client.get("/example.txt")
    assert "is not a directory" in str(exc)


def test_staticfiles_config_check_occurs_only_once(tmpdir):
    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    assert not app.config_checked
    client.get("/")
    assert app.config_checked
    client.get("/")
    assert app.config_checked


def test_staticfiles_prevents_breaking_out_of_directory(tmpdir):
    directory = os.path.join(tmpdir, "foo")
    os.mkdir(directory)

    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("outside root dir")

    app = StaticFiles(directory=directory)
    # We can't test this with 'requests', so we call the app directly here.
    response = app({"type": "http", "method": "GET", "path": "/../example.txt"})
    assert response.status_code == 404
    assert response.body == b"Not Found"


def test_staticfiles_never_read_file_for_head_method(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    response = client.head("/example.txt")
    assert response.status_code == 200
    assert response.content == b""
    assert response.headers["content-length"] == "14"


def test_staticfiles_304_with_etag_match(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    first_resp = client.get("/example.txt")
    assert first_resp.status_code == 200
    last_etag = first_resp.headers["etag"]
    second_resp = client.get("/example.txt", headers={"if-none-match": last_etag})
    assert second_resp.status_code == 304
    assert second_resp.content == b""


def test_staticfiles_304_with_last_modified_compare_last_req(tmpdir):
    path = os.path.join(tmpdir, "example.txt")
    file_last_modified_time = time.mktime(
        time.strptime("2013-10-10 23:40:00", "%Y-%m-%d %H:%M:%S")
    )
    with open(path, "w") as file:
        file.write("<file content>")
    os.utime(path, (file_last_modified_time, file_last_modified_time))

    app = StaticFiles(directory=tmpdir)
    client = TestClient(app)
    # last modified less than last request, 304
    response = client.get(
        "/example.txt", headers={"If-Modified-Since": "Thu, 11 Oct 2013 15:30:19 GMT"}
    )
    assert response.status_code == 304
    assert response.content == b""
    # last modified greater than last request, 200 with content
    response = client.get(
        "/example.txt", headers={"If-Modified-Since": "Thu, 20 Feb 2012 15:30:19 GMT"}
    )
    assert response.status_code == 200
    assert response.content == b"<file content>"
