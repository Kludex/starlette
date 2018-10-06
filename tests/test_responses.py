from starlette.responses import (
    FileResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.requests import Request
from starlette.testclient import TestClient
import asyncio
import os


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
    def app(scope):
        async def numbers(minimum, maximum):
            for i in range(minimum, maximum + 1):
                yield str(i)
                if i != maximum:
                    yield ", "
                await asyncio.sleep(0)

        async def asgi(receive, send):
            generator = numbers(1, 5)
            response = StreamingResponse(generator, media_type="text/plain")
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "1, 2, 3, 4, 5"


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
        return Response(b"", status_code=200)

    client = TestClient(app)
    response = client.get("/")
    assert response.reason == "OK"

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

    def app(scope):
        return FileResponse(path=path, filename="example.png")

    client = TestClient(app)
    response = client.get("/")
    expected_disposition = 'attachment; filename="example.png"'
    assert response.status_code == 200
    assert response.content == content
    assert response.headers["content-type"] == "image/png"
    assert response.headers["content-disposition"] == expected_disposition
    assert "content-length" in response.headers
    assert "last-modified" in response.headers
    assert "etag" in response.headers


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
