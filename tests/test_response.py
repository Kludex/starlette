from starlette import FileResponse, Response, StreamingResponse, TestClient
import asyncio


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


def test_file_response(tmpdir):
    with open("xyz", "wb") as file:
        file.write(b"<file content>")

    def app(scope):
        return FileResponse(path="xyz", filename="example.png")

    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.content == b"<file content>"
    assert response.headers["content-type"] == "image/png"
    assert (
        response.headers["content-disposition"] == 'attachment; filename="example.png"'
    )
