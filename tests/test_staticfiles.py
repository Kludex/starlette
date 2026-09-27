import errno
import os
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, BinaryIO

import anyio
import pytest

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles
from starlette.types import Message, Scope
from starlette.websockets import WebSocketDisconnect
from tests.types import TestClientFactory


def test_staticfiles(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = test_client_factory(app)
    response = client.get("/example.txt")
    assert response.status_code == 200
    assert response.text == "<file content>"


def test_staticfiles_websocket(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    app = Starlette(routes=[Mount("/static", app=StaticFiles(directory=tmp_path))])
    client = test_client_factory(app)

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/static/example.txt"):
            pass  # pragma: no cover - The connection is rejected before entering the context.

    assert exc.value.code == 1000


def test_staticfiles_with_pathlib(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    path = tmp_path / "example.txt"
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmp_path)
    client = test_client_factory(app)
    response = client.get("/example.txt")
    assert response.status_code == 200
    assert response.text == "<file content>"


def test_staticfiles_head_with_middleware(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    """
    see https://github.com/Kludex/starlette/pull/935
    """
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("x" * 100)

    async def does_nothing_middleware(request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        return response

    routes = [Mount("/static", app=StaticFiles(directory=tmpdir), name="static")]
    middleware = [Middleware(BaseHTTPMiddleware, dispatch=does_nothing_middleware)]
    app = Starlette(routes=routes, middleware=middleware)

    client = test_client_factory(app)
    response = client.head("/static/example.txt")
    assert response.status_code == 200
    assert response.headers.get("content-length") == "100"


def test_staticfiles_with_package(test_client_factory: TestClientFactory) -> None:
    app = StaticFiles(packages=["tests"])
    client = test_client_factory(app)
    response = client.get("/example.txt")
    assert response.status_code == 200
    assert response.text == "123\n"

    app = StaticFiles(packages=[("tests", "statics")])
    client = test_client_factory(app)
    response = client.get("/example.txt")
    assert response.status_code == 200
    assert response.text == "123\n"


def test_staticfiles_post(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    routes = [Mount("/", app=StaticFiles(directory=tmpdir), name="static")]
    app = Starlette(routes=routes)
    client = test_client_factory(app)

    response = client.post("/example.txt")
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"


def test_staticfiles_with_directory_returns_404(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    routes = [Mount("/", app=StaticFiles(directory=tmpdir), name="static")]
    app = Starlette(routes=routes)
    client = test_client_factory(app)

    response = client.get("/")
    assert response.status_code == 404
    assert response.text == "Not Found"


def test_staticfiles_with_missing_file_returns_404(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    routes = [Mount("/", app=StaticFiles(directory=tmpdir), name="static")]
    app = Starlette(routes=routes)
    client = test_client_factory(app)

    response = client.get("/404.txt")
    assert response.status_code == 404
    assert response.text == "Not Found"


def test_staticfiles_instantiated_with_missing_directory(tmpdir: Path) -> None:
    with pytest.raises(RuntimeError) as exc_info:
        path = os.path.join(tmpdir, "no_such_directory")
        StaticFiles(directory=path)
    assert "does not exist" in str(exc_info.value)


def test_staticfiles_configured_with_missing_directory(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "no_such_directory")
    app = StaticFiles(directory=path, check_dir=False)
    client = test_client_factory(app)
    with pytest.raises(RuntimeError) as exc_info:
        client.get("/example.txt")
    assert "does not exist" in str(exc_info.value)


def test_staticfiles_configured_with_file_instead_of_directory(
    tmpdir: Path, test_client_factory: TestClientFactory
) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=path, check_dir=False)
    client = test_client_factory(app)
    with pytest.raises(RuntimeError) as exc_info:
        client.get("/example.txt")
    assert "is not a directory" in str(exc_info.value)


def test_staticfiles_config_check_occurs_only_once(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    app = StaticFiles(directory=tmpdir)
    client = test_client_factory(app)
    assert not app.config_checked

    with pytest.raises(HTTPException):
        client.get("/")

    assert app.config_checked

    with pytest.raises(HTTPException):
        client.get("/")


def test_staticfiles_prevents_breaking_out_of_directory(tmpdir: Path) -> None:
    directory = os.path.join(tmpdir, "foo")
    os.mkdir(directory)

    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("outside root dir")

    app = StaticFiles(directory=directory)
    # We can't test this with 'httpx', so we test the app directly here.
    path = app.get_path({"path": "/../example.txt"})
    scope = {"method": "GET"}

    with pytest.raises(HTTPException) as exc_info:
        anyio.run(app.get_response, path, scope)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Not Found"


def test_staticfiles_never_read_file_for_head_method(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = test_client_factory(app)
    response = client.head("/example.txt")
    assert response.status_code == 200
    assert response.content == b""
    assert response.headers["content-length"] == "14"


def test_staticfiles_304_with_etag_match(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    app = StaticFiles(directory=tmpdir)
    client = test_client_factory(app)
    first_resp = client.get("/example.txt")
    assert first_resp.status_code == 200
    last_etag = first_resp.headers["etag"]
    second_resp = client.get("/example.txt", headers={"if-none-match": last_etag})
    assert second_resp.status_code == 304
    assert second_resp.content == b""
    second_resp = client.get("/example.txt", headers={"if-none-match": f'W/{last_etag}, "123"'})
    assert second_resp.status_code == 304
    assert second_resp.content == b""
    second_resp = client.get("/example.txt", headers={"if-none-match": f'"123",\tW/{last_etag}'})
    assert second_resp.status_code == 304
    assert second_resp.content == b""


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("if_none_match", ["*", " \t* \t"])
def test_staticfiles_304_with_if_none_match_wildcard(
    tmp_path: Path,
    test_client_factory: TestClientFactory,
    method: str,
    if_none_match: str,
) -> None:
    (tmp_path / "example.txt").write_text("<file content>", encoding="utf-8")

    app = StaticFiles(directory=tmp_path)
    client = test_client_factory(app)
    response = client.request(method, "/example.txt", headers={"if-none-match": if_none_match})
    assert response.status_code == 304
    assert response.content == b""


@pytest.mark.parametrize("if_none_match", ['"123"', '"*"', '"foo,*,bar"'])
def test_staticfiles_200_with_etag_mismatch(
    tmp_path: Path,
    test_client_factory: TestClientFactory,
    if_none_match: str,
) -> None:
    (tmp_path / "example.txt").write_text("<file content>", encoding="utf-8")

    app = StaticFiles(directory=tmp_path)
    client = test_client_factory(app)
    response = client.get("/example.txt", headers={"if-none-match": if_none_match})
    assert response.status_code == 200
    assert response.content == b"<file content>"


def test_staticfiles_200_with_etag_mismatch_and_timestamp_match(
    tmpdir: Path, test_client_factory: TestClientFactory
) -> None:
    path = tmpdir / "example.txt"
    path.write_text("<file content>", encoding="utf-8")

    app = StaticFiles(directory=tmpdir)
    client = test_client_factory(app)
    first_resp = client.get("/example.txt")
    assert first_resp.status_code == 200
    assert first_resp.headers["etag"] != '"123"'
    last_modified = first_resp.headers["last-modified"]
    # If `if-none-match` is present, `if-modified-since` is ignored.
    second_resp = client.get("/example.txt", headers={"if-none-match": '"123"', "if-modified-since": last_modified})
    assert second_resp.status_code == 200
    assert second_resp.content == b"<file content>"


def test_staticfiles_304_with_last_modified_compare_last_req(
    tmpdir: Path, test_client_factory: TestClientFactory
) -> None:
    path = os.path.join(tmpdir, "example.txt")
    file_last_modified_time = time.mktime(time.strptime("2013-10-10 23:40:00", "%Y-%m-%d %H:%M:%S"))
    with open(path, "w") as file:
        file.write("<file content>")
    os.utime(path, (file_last_modified_time, file_last_modified_time))

    app = StaticFiles(directory=tmpdir)
    client = test_client_factory(app)
    # last modified less than last request, 304
    response = client.get("/example.txt", headers={"If-Modified-Since": "Thu, 11 Oct 2013 15:30:19 GMT"})
    assert response.status_code == 304
    assert response.content == b""
    # last modified greater than last request, 200 with content
    response = client.get("/example.txt", headers={"If-Modified-Since": "Thu, 20 Feb 2012 15:30:19 GMT"})
    assert response.status_code == 200
    assert response.content == b"<file content>"


def test_staticfiles_html_normal(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "404.html")
    with open(path, "w") as file:
        file.write("<h1>Custom not found page</h1>")
    path = os.path.join(tmpdir, "dir")
    os.mkdir(path)
    path = os.path.join(path, "index.html")
    with open(path, "w") as file:
        file.write("<h1>Hello</h1>")

    app = StaticFiles(directory=tmpdir, html=True)
    client = test_client_factory(app)

    response = client.get("/dir/")
    assert response.url == "http://testserver/dir/"
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"

    response = client.get("/dir")
    assert response.url == "http://testserver/dir/"
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"

    response = client.get("/dir/index.html")
    assert response.url == "http://testserver/dir/index.html"
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"

    response = client.get("/missing")
    assert response.status_code == 404
    assert response.text == "<h1>Custom not found page</h1>"


def test_staticfiles_html_without_index(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "404.html")
    with open(path, "w") as file:
        file.write("<h1>Custom not found page</h1>")
    path = os.path.join(tmpdir, "dir")
    os.mkdir(path)

    app = StaticFiles(directory=tmpdir, html=True)
    client = test_client_factory(app)

    response = client.get("/dir/")
    assert response.url == "http://testserver/dir/"
    assert response.status_code == 404
    assert response.text == "<h1>Custom not found page</h1>"

    response = client.get("/dir")
    assert response.url == "http://testserver/dir"
    assert response.status_code == 404
    assert response.text == "<h1>Custom not found page</h1>"

    response = client.get("/missing")
    assert response.status_code == 404
    assert response.text == "<h1>Custom not found page</h1>"


def test_staticfiles_html_without_404(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "dir")
    os.mkdir(path)
    path = os.path.join(path, "index.html")
    with open(path, "w") as file:
        file.write("<h1>Hello</h1>")

    app = StaticFiles(directory=tmpdir, html=True)
    client = test_client_factory(app)

    response = client.get("/dir/")
    assert response.url == "http://testserver/dir/"
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"

    response = client.get("/dir")
    assert response.url == "http://testserver/dir/"
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"

    with pytest.raises(HTTPException) as exc_info:
        response = client.get("/missing")
    assert exc_info.value.status_code == 404


def test_staticfiles_html_only_files(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "hello.html")
    with open(path, "w") as file:
        file.write("<h1>Hello</h1>")

    app = StaticFiles(directory=tmpdir, html=True)
    client = test_client_factory(app)

    with pytest.raises(HTTPException) as exc_info:
        response = client.get("/")
    assert exc_info.value.status_code == 404

    response = client.get("/hello.html")
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"


def test_staticfiles_cache_invalidation_for_deleted_file_html_mode(
    tmpdir: Path, test_client_factory: TestClientFactory
) -> None:
    path_404 = os.path.join(tmpdir, "404.html")
    with open(path_404, "w") as file:
        file.write("<p>404 file</p>")
    path_some = os.path.join(tmpdir, "some.html")
    with open(path_some, "w") as file:
        file.write("<p>some file</p>")

    common_modified_time = time.mktime(time.strptime("2013-10-10 23:40:00", "%Y-%m-%d %H:%M:%S"))
    os.utime(path_404, (common_modified_time, common_modified_time))
    os.utime(path_some, (common_modified_time, common_modified_time))

    app = StaticFiles(directory=tmpdir, html=True)
    client = test_client_factory(app)

    resp_exists = client.get("/some.html")
    assert resp_exists.status_code == 200
    assert resp_exists.text == "<p>some file</p>"

    resp_cached = client.get(
        "/some.html",
        headers={"If-Modified-Since": resp_exists.headers["last-modified"]},
    )
    assert resp_cached.status_code == 304

    os.remove(path_some)

    resp_deleted = client.get(
        "/some.html",
        headers={"If-Modified-Since": resp_exists.headers["last-modified"]},
    )
    assert resp_deleted.status_code == 404
    assert resp_deleted.text == "<p>404 file</p>"


def test_staticfiles_with_invalid_dir_permissions_returns_401(
    tmp_path: Path, test_client_factory: TestClientFactory
) -> None:
    (tmp_path / "example.txt").write_bytes(b"<file content>")

    original_mode = tmp_path.stat().st_mode
    tmp_path.chmod(stat.S_IRWXO)
    try:
        routes = [
            Mount(
                "/",
                app=StaticFiles(directory=os.fsdecode(tmp_path)),
                name="static",
            )
        ]
        app = Starlette(routes=routes)
        client = test_client_factory(app)

        response = client.get("/example.txt")
        assert response.status_code == 401
        assert response.text == "Unauthorized"
    finally:
        tmp_path.chmod(original_mode)


def test_staticfiles_with_missing_dir_returns_404(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    routes = [Mount("/", app=StaticFiles(directory=tmpdir), name="static")]
    app = Starlette(routes=routes)
    client = test_client_factory(app)

    response = client.get("/foo/example.txt")
    assert response.status_code == 404
    assert response.text == "Not Found"


def test_staticfiles_access_file_as_dir_returns_404(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    routes = [Mount("/", app=StaticFiles(directory=tmpdir), name="static")]
    app = Starlette(routes=routes)
    client = test_client_factory(app)

    response = client.get("/example.txt/foo")
    assert response.status_code == 404
    assert response.text == "Not Found"


def test_staticfiles_null_byte_in_path(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    routes = [Mount("/", app=StaticFiles(directory=tmpdir), name="static")]
    app = Starlette(routes=routes)
    client = test_client_factory(app)

    response = client.get("/example%00.txt")
    assert response.status_code == 404


@pytest.mark.skipif(not hasattr(os, "pathconf"), reason="os.pathconf is Unix-only")
def test_staticfiles_filename_too_long(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    routes = [Mount("/", app=StaticFiles(directory=tmpdir), name="static")]
    app = Starlette(routes=routes)
    client = test_client_factory(app)

    path_max_size = os.pathconf("/", "PC_PATH_MAX")
    response = client.get(f"/{'a' * path_max_size}.txt")
    assert response.status_code == 404
    assert response.text == "Not Found"


def test_staticfiles_unhandled_os_error_returns_500(
    tmpdir: Path,
    test_client_factory: TestClientFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def mock_timeout(*args: Any, **kwargs: Any) -> None:
        raise TimeoutError

    path = os.path.join(tmpdir, "example.txt")
    with open(path, "w") as file:
        file.write("<file content>")

    routes = [Mount("/", app=StaticFiles(directory=tmpdir), name="static")]
    app = Starlette(routes=routes)
    client = test_client_factory(app, raise_server_exceptions=False)

    monkeypatch.setattr("starlette.staticfiles.StaticFiles.lookup_path", mock_timeout)

    response = client.get("/example.txt")
    assert response.status_code == 500
    assert response.text == "Internal Server Error"


def test_staticfiles_follows_symlinks(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    statics_path = os.path.join(tmpdir, "statics")
    os.mkdir(statics_path)

    source_path = tempfile.mkdtemp()
    source_file_path = os.path.join(source_path, "page.html")
    with open(source_file_path, "w") as file:
        file.write("<h1>Hello</h1>")

    statics_file_path = os.path.join(statics_path, "index.html")
    os.symlink(source_file_path, statics_file_path)

    app = StaticFiles(directory=statics_path, follow_symlink=True)
    client = test_client_factory(app)

    response = client.get("/index.html")
    assert response.url == "http://testserver/index.html"
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"


def test_staticfiles_follows_symlink_directories(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    statics_path = os.path.join(tmpdir, "statics")
    statics_html_path = os.path.join(statics_path, "html")
    os.mkdir(statics_path)

    source_path = tempfile.mkdtemp()
    source_file_path = os.path.join(source_path, "page.html")
    with open(source_file_path, "w") as file:
        file.write("<h1>Hello</h1>")

    os.symlink(source_path, statics_html_path)

    app = StaticFiles(directory=statics_path, follow_symlink=True)
    client = test_client_factory(app)

    response = client.get("/html/page.html")
    assert response.url == "http://testserver/html/page.html"
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"


def test_staticfiles_disallows_path_traversal_with_symlinks(tmpdir: Path) -> None:
    statics_path = os.path.join(tmpdir, "statics")

    root_source_path = tempfile.mkdtemp()
    source_path = os.path.join(root_source_path, "statics")
    os.mkdir(source_path)

    source_file_path = os.path.join(root_source_path, "index.html")
    with open(source_file_path, "w") as file:
        file.write("<h1>Hello</h1>")

    os.symlink(source_path, statics_path)

    app = StaticFiles(directory=statics_path, follow_symlink=True)
    # We can't test this with 'httpx', so we test the app directly here.
    path = app.get_path({"path": "/../index.html"})
    scope = {"method": "GET"}

    with pytest.raises(HTTPException) as exc_info:
        anyio.run(app.get_response, path, scope)

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Not Found"


def test_staticfiles_avoids_path_traversal(tmp_path: Path) -> None:
    statics_path = tmp_path / "static"
    statics_disallow_path = tmp_path / "static_disallow"

    statics_path.mkdir()
    statics_disallow_path.mkdir()

    static_index_file = statics_path / "index.html"
    statics_disallow_path_index_file = statics_disallow_path / "index.html"
    static_file = tmp_path / "static1.txt"

    static_index_file.write_text("<h1>Hello</h1>")
    statics_disallow_path_index_file.write_text("<h1>Private</h1>")
    static_file.write_text("Private")

    app = StaticFiles(directory=statics_path)

    # We can't test this with 'httpx', so we test the app directly here.
    path = app.get_path({"path": "/../static1.txt"})
    with pytest.raises(HTTPException) as exc_info:
        anyio.run(app.get_response, path, {"method": "GET"})

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Not Found"

    path = app.get_path({"path": "/../static_disallow/index.html"})
    with pytest.raises(HTTPException) as exc_info:
        anyio.run(app.get_response, path, {"method": "GET"})

    assert exc_info.value.status_code == 404
    assert exc_info.value.detail == "Not Found"


def test_staticfiles_rejects_symlink_swapped_after_lookup(
    tmp_path: Path, test_client_factory: TestClientFactory
) -> None:
    statics_path = tmp_path / "static"
    assets_path = statics_path / "assets"
    outside_path = tmp_path / "outside"
    assets_path.mkdir(parents=True)
    outside_path.mkdir()
    (assets_path / "file.txt").write_text("safe", encoding="utf-8")
    (outside_path / "file.txt").write_text("secret", encoding="utf-8")

    class SwappingStaticFiles(StaticFiles):
        swapped = False

        def lookup_path(self, path: str) -> tuple[str, os.stat_result | None]:
            result = super().lookup_path(path)
            if not self.swapped and result[1] is not None and stat.S_ISREG(result[1].st_mode):  # pragma: no branch
                assets_path.rename(statics_path / "assets-old")
                assets_path.symlink_to(outside_path, target_is_directory=True)
                self.swapped = True
            return result

    app = Starlette(routes=[Mount("/", app=SwappingStaticFiles(directory=statics_path))])
    client = test_client_factory(app)
    response = client.get("/assets/file.txt")

    assert response.status_code == 404
    assert response.content != b"secret"


def test_staticfiles_rejects_root_symlink_swapped_after_lookup(
    tmp_path: Path, test_client_factory: TestClientFactory
) -> None:
    statics_path = tmp_path / "static"
    outside_path = tmp_path / "outside"
    statics_path.mkdir()
    outside_path.mkdir()
    (statics_path / "file.txt").write_text("safe", encoding="utf-8")
    (outside_path / "file.txt").write_text("secret", encoding="utf-8")

    class SwappingStaticFiles(StaticFiles):
        swapped = False

        def lookup_path(self, path: str) -> tuple[str, os.stat_result | None]:
            result = super().lookup_path(path)
            if not self.swapped and result[1] is not None:  # pragma: no branch
                statics_path.rename(tmp_path / "static-old")
                statics_path.symlink_to(outside_path, target_is_directory=True)
                self.swapped = True
            return result

    app = Starlette(routes=[Mount("/", app=SwappingStaticFiles(directory=statics_path))])
    client = test_client_factory(app)
    response = client.get("/file.txt")

    assert response.status_code == 404
    assert response.content != b"secret"


def test_open_path_rejects_replaced_root_directory(tmp_path: Path) -> None:
    statics_path = tmp_path / "static"
    statics_path.mkdir()
    (statics_path / "file.txt").write_text("safe", encoding="utf-8")
    app = StaticFiles(directory=statics_path)
    app.lookup_path("file.txt")

    statics_path.rename(tmp_path / "static-old")
    statics_path.mkdir()
    (statics_path / "file.txt").write_text("secret", encoding="utf-8")

    assert app._open_path("file.txt") is None


def test_directory_anchor_handles_missing_directory(tmp_path: Path) -> None:
    app = StaticFiles(directory=tmp_path / "missing", check_dir=False)

    assert app.lookup_path("file.txt") == ("", None)
    assert app._open_path("file.txt") is None


def test_staticfiles_uses_metadata_from_opened_file(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    statics_path = tmp_path / "static"
    statics_path.mkdir()
    target_path = statics_path / "file.txt"
    replacement_path = statics_path / "replacement.txt"
    target_path.write_text("old", encoding="utf-8")
    replacement_path.write_text("replacement", encoding="utf-8")

    class ReplacingStaticFiles(StaticFiles):
        replaced = False

        def lookup_path(self, path: str) -> tuple[str, os.stat_result | None]:
            result = super().lookup_path(path)
            if not self.replaced and result[1] is not None and stat.S_ISREG(result[1].st_mode):  # pragma: no branch
                replacement_path.replace(target_path)
                self.replaced = True
            return result

    client = test_client_factory(ReplacingStaticFiles(directory=statics_path))
    response = client.get("/file.txt")

    assert response.content == b"replacement"
    assert response.headers["content-length"] == str(len(b"replacement"))


@pytest.mark.anyio
async def test_staticfiles_does_not_use_pathsend_for_preopened_files(tmp_path: Path) -> None:
    statics_path = tmp_path / "static"
    statics_path.mkdir()
    (statics_path / "file.txt").write_text("content", encoding="utf-8")
    app = StaticFiles(directory=statics_path, check_dir=False)
    messages: list[Message] = []

    async def receive() -> Message:
        raise AssertionError("receive should not be called")  # pragma: no cover

    async def send(message: Message) -> None:
        messages.append(message)

    await app(
        {
            "type": "http",
            "asgi": {"spec_version": "2.4"},
            "method": "GET",
            "path": "/file.txt",
            "root_path": "",
            "headers": [],
            "extensions": {"http.response.pathsend": {}},
        },
        receive,
        send,
    )

    assert all(message["type"] != "http.response.pathsend" for message in messages)
    assert (
        b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
        == b"content"
    )


@pytest.mark.anyio
async def test_staticfiles_handles_files_disappearing_after_lookup(tmp_path: Path) -> None:
    class VanishingStaticFiles(StaticFiles):
        async def _open_file_response(self, path: str, scope: Scope, status_code: int = 200) -> Response | None:
            return None

    statics_path = tmp_path / "static"
    statics_path.mkdir()
    (statics_path / "index.html").write_text("index", encoding="utf-8")
    (statics_path / "404.html").write_text("not found", encoding="utf-8")
    app = VanishingStaticFiles(directory=statics_path, html=True, check_dir=False)
    scope: Scope = {"type": "http", "method": "GET", "path": "/"}

    with pytest.raises(HTTPException) as exc_info:
        await app.get_response("", scope)
    assert exc_info.value.status_code == 404

    with pytest.raises(HTTPException) as exc_info:
        await app.get_response("missing.txt", scope)
    assert exc_info.value.status_code == 404


@pytest.mark.anyio
async def test_open_file_response_handles_open_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    app = StaticFiles(directory=tmp_path, check_dir=False)
    scope: Scope = {"type": "http", "method": "GET", "path": "/file.txt"}

    def raise_permission_error(path: str) -> None:
        raise PermissionError

    monkeypatch.setattr(app, "_open_path", raise_permission_error)
    with pytest.raises(HTTPException) as permission_exc:
        await app._open_file_response("file.txt", scope)
    assert permission_exc.value.status_code == 401

    def raise_name_too_long(path: str) -> None:
        raise OSError(errno.ENAMETOOLONG, "Name too long")

    monkeypatch.setattr(app, "_open_path", raise_name_too_long)
    assert await app._open_file_response("file.txt", scope) is None

    error = OSError(errno.EIO, "I/O error")

    def raise_io_error(path: str) -> None:
        raise error

    monkeypatch.setattr(app, "_open_path", raise_io_error)
    with pytest.raises(OSError) as os_exc:
        await app._open_file_response("file.txt", scope)
    assert os_exc.value is error


@pytest.mark.anyio
async def test_open_file_response_closes_file_on_response_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = tmp_path / "file.txt"
    file_path.write_text("content", encoding="utf-8")
    file = file_path.open("rb")
    app = StaticFiles(directory=tmp_path, check_dir=False)
    scope: Scope = {"type": "http", "method": "GET", "path": "/file.txt"}
    error = RuntimeError("response construction failed")

    monkeypatch.setattr(app, "_open_path", lambda path: (str(file_path), os.fstat(file.fileno()), file))

    def raise_response_error(full_path: Any, stat_result: os.stat_result, scope: Scope) -> Response:
        raise error

    monkeypatch.setattr(app, "file_response", raise_response_error)

    with pytest.raises(RuntimeError) as exc_info:
        await app._open_file_response("file.txt", scope)
    assert exc_info.value is error
    assert file.closed


def test_open_path_rejects_invalid_paths_and_expected_open_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    statics_path = tmp_path / "static"
    statics_path.mkdir()
    app = StaticFiles(directory=statics_path)

    assert app._open_path("/file.txt") is None
    assert app._open_path("../file.txt") is None

    app.follow_symlink = True
    assert app._open_path("../file.txt") is None
    assert app._open_path("missing.txt") is None

    app.follow_symlink = False
    error = OSError(errno.EIO, "I/O error")

    def raise_io_error(directory: str, path: str, directory_stat: os.stat_result) -> BinaryIO:
        raise error

    monkeypatch.setattr(app, "_open_path_without_symlinks", raise_io_error)
    with pytest.raises(OSError) as exc_info:
        app._open_path("file.txt")
    assert exc_info.value is error


def test_open_path_closes_file_on_stat_error_or_non_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = tmp_path / "file.txt"
    file_path.write_text("content", encoding="utf-8")
    app = StaticFiles(directory=tmp_path)

    file = file_path.open("rb")
    with monkeypatch.context() as patch:
        patch.setattr(app, "_open_path_without_symlinks", lambda directory, path, directory_stat: file)
        patch.setattr(os, "fstat", lambda fd: (_ for _ in ()).throw(OSError(errno.EIO, "I/O error")))
        with pytest.raises(OSError):
            app._open_path("file.txt")
    assert file.closed

    file = file_path.open("rb")
    with monkeypatch.context() as patch:
        patch.setattr(app, "_open_path_without_symlinks", lambda directory, path, directory_stat: file)
        patch.setattr(stat, "S_ISREG", lambda mode: False)
        assert app._open_path("file.txt") is None
    assert file.closed


def test_open_path_without_symlinks_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "file.txt"
    file_path.write_text("content", encoding="utf-8")
    directory_stat = os.stat(tmp_path)

    monkeypatch.setattr(os, "supports_dir_fd", set())
    file = StaticFiles._open_path_without_symlinks(tmp_path, "file.txt", directory_stat)
    assert file.read() == b"content"
    file.close()

    outside_path = tmp_path.parent / "outside.txt"
    outside_path.write_text("outside", encoding="utf-8")
    link_path = tmp_path / "link.txt"
    link_path.symlink_to(outside_path)
    with pytest.raises(OSError) as exc_info:
        StaticFiles._open_path_without_symlinks(tmp_path, "link.txt", directory_stat)
    assert exc_info.value.errno == errno.ELOOP

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", lambda fd: (_ for _ in ()).throw(OSError(errno.EIO, "I/O error")))
        with pytest.raises(OSError):
            StaticFiles._open_path_without_symlinks(tmp_path, "file.txt", directory_stat)

    with monkeypatch.context() as patch:
        patch.setattr(os.path, "samestat", lambda stat1, stat2: False)
        with pytest.raises(OSError) as exc_info:
            StaticFiles._open_path_without_symlinks(tmp_path, "file.txt")
    assert exc_info.value.errno == errno.ELOOP

    with pytest.raises(OSError) as exc_info:
        StaticFiles._open_path_without_symlinks(tmp_path, "file.txt", os.stat(tmp_path.parent))
    assert exc_info.value.errno == errno.ELOOP


def test_open_path_without_symlinks_rejects_empty_and_parent_paths(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        StaticFiles._open_path_without_symlinks(tmp_path, "")
    with pytest.raises(FileNotFoundError):
        StaticFiles._open_path_without_symlinks(tmp_path, "../file.txt")


@pytest.mark.skipif(
    not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0) or os.open not in os.supports_dir_fd,
    reason="requires descriptor-relative file opening",
)
def test_open_path_without_symlinks_closes_descriptor_if_fdopen_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    file_path = tmp_path / "file.txt"
    file_path.write_text("content", encoding="utf-8")
    opened_fds: list[int] = []

    def fail_fdopen(fd: int, mode: str) -> BinaryIO:
        opened_fds.append(fd)
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, "fdopen", fail_fdopen)
    with pytest.raises(OSError):
        StaticFiles._open_path_without_symlinks(tmp_path, "file.txt")

    with pytest.raises(OSError) as exc_info:
        os.fstat(opened_fds[0])
    assert exc_info.value.errno == errno.EBADF


def test_staticfiles_rejects_absolute_paths(tmp_path: Path) -> None:
    statics_path = tmp_path / "static"
    statics_path.mkdir()
    app = StaticFiles(directory=statics_path)

    full_path, stat_result = app.lookup_path("/etc/passwd")
    assert full_path == ""
    assert stat_result is None


def test_staticfiles_rejects_absolute_windows_paths(tmp_path: Path) -> None:
    statics_path = tmp_path / "static"
    statics_path.mkdir()
    app = StaticFiles(directory=statics_path)

    full_path, stat_result = app.lookup_path("\\\\server\\share")
    assert full_path == ""
    assert stat_result is None


def test_staticfiles_self_symlinks(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    statics_path = tmp_path / "statics"
    statics_path.mkdir()

    source_file_path = statics_path / "index.html"
    source_file_path.write_text("<h1>Hello</h1>", encoding="utf-8")

    statics_symlink_path = tmp_path / "statics_symlink"
    statics_symlink_path.symlink_to(statics_path)

    app = StaticFiles(directory=statics_symlink_path, follow_symlink=True)
    client = test_client_factory(app)

    response = client.get("/index.html")
    assert response.url == "http://testserver/index.html"
    assert response.status_code == 200
    assert response.text == "<h1>Hello</h1>"


def test_staticfiles_relative_directory_symlinks(test_client_factory: TestClientFactory) -> None:
    app = StaticFiles(directory="tests/statics", follow_symlink=True)
    client = test_client_factory(app)
    response = client.get("/example.txt")
    assert response.status_code == 200
    assert response.text == "123\n"
