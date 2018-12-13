import asyncio
import os

import pytest

from starlette import status
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
    TemplateResponse,
    UJSONResponse,
)
from starlette.testclient import TestClient


def test_text_response():
    def app(scope):
        async def asgi(receive, send):
            response = Response("hello, world", media_type="text/plain")
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "hello, world"


def test_bytes_response():
    def app(scope):
        async def asgi(receive, send):
            response = Response(b"xxxxx", media_type="image/png")
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.content == b"xxxxx"


def test_ujson_response():
    def app(scope):
        async def asgi(receive, send):
            response = UJSONResponse({"hello": "world"})
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.json() == {"hello": "world"}


def test_redirect_response():
    def app(scope):
        async def asgi(receive, send):
            if scope["path"] == "/":
                response = Response("hello, world", media_type="text/plain")
            else:
                response = RedirectResponse("/")
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/redirect")
    assert response.text == "hello, world"
    assert response.url == "http://testserver/"


def test_streaming_response():
    filled_by_bg_task = ""

    def app(scope):
        async def numbers(minimum, maximum):
            for i in range(minimum, maximum + 1):
                yield str(i)
                if i != maximum:
                    yield ", "
                await asyncio.sleep(0)

        async def numbers_for_cleanup(start=1, stop=5):
            nonlocal filled_by_bg_task
            async for thing in numbers(start, stop):
                filled_by_bg_task = filled_by_bg_task + thing

        cleanup_task = BackgroundTask(numbers_for_cleanup, start=6, stop=9)

        async def asgi(receive, send):
            generator = numbers(1, 5)
            response = StreamingResponse(
                generator, media_type="text/plain", background=cleanup_task
            )
            await response(receive, send)

        return asgi

    assert filled_by_bg_task == ""
    client = TestClient(app)
    response = client.get("/")
    assert response.text == "1, 2, 3, 4, 5"
    assert filled_by_bg_task == "6, 7, 8, 9"


def test_response_headers():
    def app(scope):
        async def asgi(receive, send):
            headers = {"x-header-1": "123", "x-header-2": "456"}
            response = Response(
                "hello, world", media_type="text/plain", headers=headers
            )
            response.headers["x-header-2"] = "789"
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.headers["x-header-1"] == "123"
    assert response.headers["x-header-2"] == "789"


def test_response_phrase():
    def app(scope):
        return Response(status_code=204)

    client = TestClient(app)
    response = client.get("/")
    assert response.reason == "No Content"

    def app(scope):
        return Response(b"", status_code=123)

    client = TestClient(app)
    response = client.get("/")
    assert response.reason == ""


def test_file_response(tmpdir):
    path = os.path.join(tmpdir, "xyz")
    content = b"<file content>" * 1000
    with open(path, "wb") as file:
        file.write(content)

    filled_by_bg_task = ""

    async def numbers(minimum, maximum):
        for i in range(minimum, maximum + 1):
            yield str(i)
            if i != maximum:
                yield ", "
            await asyncio.sleep(0)

    async def numbers_for_cleanup(start=1, stop=5):
        nonlocal filled_by_bg_task
        async for thing in numbers(start, stop):
            filled_by_bg_task = filled_by_bg_task + thing

    cleanup_task = BackgroundTask(numbers_for_cleanup, start=6, stop=9)

    def app(scope):
        return FileResponse(path=path, filename="example.png", background=cleanup_task)

    assert filled_by_bg_task == ""
    client = TestClient(app)
    response = client.get("/")
    expected_disposition = 'attachment; filename="example.png"'
    assert response.status_code == status.HTTP_200_OK
    assert response.content == content
    assert response.headers["content-type"] == "image/png"
    assert response.headers["content-disposition"] == expected_disposition
    assert "content-length" in response.headers
    assert "last-modified" in response.headers
    assert "etag" in response.headers
    assert filled_by_bg_task == "6, 7, 8, 9"


def test_file_response_with_directory_raises_error(tmpdir):
    def app(scope):
        return FileResponse(path=tmpdir, filename="example.png")

    client = TestClient(app)
    with pytest.raises(RuntimeError) as exc:
        client.get("/")
    assert "is not a file" in str(exc)


def test_file_response_with_missing_file_raises_error(tmpdir):
    path = os.path.join(tmpdir, "404.txt")

    def app(scope):
        return FileResponse(path=path, filename="404.txt")

    client = TestClient(app)
    with pytest.raises(RuntimeError) as exc:
        client.get("/")
    assert "does not exist" in str(exc)


def test_set_cookie():
    def app(scope):
        async def asgi(receive, send):
            response = Response("Hello, world!", media_type="text/plain")
            response.set_cookie(
                "mycookie",
                "myvalue",
                max_age=10,
                expires=10,
                path="/",
                domain="localhost",
                secure=True,
                httponly=True,
            )

            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "Hello, world!"


def test_delete_cookie():
    def app(scope):
        async def asgi(receive, send):
            request = Request(scope, receive)
            response = Response("Hello, world!", media_type="text/plain")
            if request.cookies.get("mycookie"):
                response.delete_cookie("mycookie")
            else:
                response.set_cookie("mycookie", "myvalue")
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.cookies["mycookie"]
    response = client.get("/")
    assert not response.cookies.get("mycookie")


def test_template_response():
    def app(scope):
        request = Request(scope)

        class Template:
            def __init__(self, name):
                self.name = name

            def render(self, context):
                return "username: %s" % context["username"]

        async def asgi(receive, send):
            template = Template("index.html")
            context = {"username": "tomchristie", "request": request}
            response = TemplateResponse(template, context)
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "username: tomchristie"
    assert response.template.name == "index.html"
    assert response.context["username"] == "tomchristie"


def test_template_response_requires_request():
    with pytest.raises(ValueError):
        TemplateResponse(None, {})
