from __future__ import annotations

import datetime as dt
import time
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any, AsyncGenerator, AsyncIterator, Iterator

import anyio
import pytest

from starlette import status
from starlette.background import BackgroundTask
from starlette.datastructures import Headers
from starlette.requests import ClientDisconnect, Request
from starlette.responses import FileResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from starlette.testclient import TestClient
from starlette.types import Message, Receive, Scope, Send
from tests.types import TestClientFactory


def test_text_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("hello, world", media_type="text/plain")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "hello, world"


def test_bytes_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response(b"xxxxx", media_type="image/png")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.content == b"xxxxx"


def test_json_none_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(None)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.json() is None
    assert response.content == b"null"


def test_redirect_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["path"] == "/":
            response = Response("hello, world", media_type="text/plain")
        else:
            response = RedirectResponse("/")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/redirect")
    assert response.text == "hello, world"
    assert response.url == "http://testserver/"


def test_quoting_redirect_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["path"] == "/I ♥ Starlette/":
            response = Response("hello, world", media_type="text/plain")
        else:
            response = RedirectResponse("/I ♥ Starlette/")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/redirect")
    assert response.text == "hello, world"
    assert response.url == "http://testserver/I%20%E2%99%A5%20Starlette/"


def test_redirect_response_content_length_header(
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["path"] == "/":
            response = Response("hello", media_type="text/plain")  # pragma: no cover
        else:
            response = RedirectResponse("/")
        await response(scope, receive, send)

    client: TestClient = test_client_factory(app)
    response = client.request("GET", "/redirect", follow_redirects=False)
    assert response.url == "http://testserver/redirect"
    assert response.headers["content-length"] == "0"


def test_streaming_response(test_client_factory: TestClientFactory) -> None:
    filled_by_bg_task = ""

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        async def numbers(minimum: int, maximum: int) -> AsyncIterator[str]:
            for i in range(minimum, maximum + 1):
                yield str(i)
                if i != maximum:
                    yield ", "
                await anyio.sleep(0)

        async def numbers_for_cleanup(start: int = 1, stop: int = 5) -> None:
            nonlocal filled_by_bg_task
            async for thing in numbers(start, stop):
                filled_by_bg_task = filled_by_bg_task + thing

        cleanup_task = BackgroundTask(numbers_for_cleanup, start=6, stop=9)
        generator = numbers(1, 5)
        response = StreamingResponse(generator, media_type="text/plain", background=cleanup_task)
        await response(scope, receive, send)

    assert filled_by_bg_task == ""
    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "1, 2, 3, 4, 5"
    assert filled_by_bg_task == "6, 7, 8, 9"


def test_streaming_response_custom_iterator(
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        class CustomAsyncIterator:
            def __init__(self) -> None:
                self._called = 0

            def __aiter__(self) -> AsyncIterator[str]:
                return self

            async def __anext__(self) -> str:
                if self._called == 5:
                    raise StopAsyncIteration()
                self._called += 1
                return str(self._called)

        response = StreamingResponse(CustomAsyncIterator(), media_type="text/plain")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "12345"


def test_streaming_response_custom_iterable(
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        class CustomAsyncIterable:
            async def __aiter__(self) -> AsyncIterator[str | bytes]:
                for i in range(5):
                    yield str(i + 1)

        response = StreamingResponse(CustomAsyncIterable(), media_type="text/plain")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "12345"


def test_sync_streaming_response(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        def numbers(minimum: int, maximum: int) -> Iterator[str]:
            for i in range(minimum, maximum + 1):
                yield str(i)
                if i != maximum:
                    yield ", "

        generator = numbers(1, 5)
        response = StreamingResponse(generator, media_type="text/plain")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "1, 2, 3, 4, 5"


def test_response_headers(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        headers = {"x-header-1": "123", "x-header-2": "456"}
        response = Response("hello, world", media_type="text/plain", headers=headers)
        response.headers["x-header-2"] = "789"
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.headers["x-header-1"] == "123"
    assert response.headers["x-header-2"] == "789"


def test_response_phrase(test_client_factory: TestClientFactory) -> None:
    app = Response(status_code=204)
    client = test_client_factory(app)
    response = client.get("/")
    assert response.reason_phrase == "No Content"

    app = Response(b"", status_code=123)
    client = test_client_factory(app)
    response = client.get("/")
    assert response.reason_phrase == ""


def test_file_response(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    path = tmp_path / "xyz"
    content = b"<file content>" * 1000
    path.write_bytes(content)

    filled_by_bg_task = ""

    async def numbers(minimum: int, maximum: int) -> AsyncIterator[str]:
        for i in range(minimum, maximum + 1):
            yield str(i)
            if i != maximum:
                yield ", "
            await anyio.sleep(0)

    async def numbers_for_cleanup(start: int = 1, stop: int = 5) -> None:
        nonlocal filled_by_bg_task
        async for thing in numbers(start, stop):
            filled_by_bg_task = filled_by_bg_task + thing

    cleanup_task = BackgroundTask(numbers_for_cleanup, start=6, stop=9)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = FileResponse(path=path, filename="example.png", background=cleanup_task)
        await response(scope, receive, send)

    assert filled_by_bg_task == ""
    client = test_client_factory(app)
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


@pytest.mark.anyio
async def test_file_response_on_head_method(tmp_path: Path) -> None:
    path = tmp_path / "xyz"
    content = b"<file content>" * 1000
    path.write_bytes(content)

    app = FileResponse(path=path, filename="example.png")

    async def receive() -> Message:  # type: ignore[empty-body]
        ...  # pragma: no cover

    async def send(message: Message) -> None:
        if message["type"] == "http.response.start":
            assert message["status"] == status.HTTP_200_OK
            headers = Headers(raw=message["headers"])
            assert headers["content-type"] == "image/png"
            assert "content-length" in headers
            assert "content-disposition" in headers
            assert "last-modified" in headers
            assert "etag" in headers
        elif message["type"] == "http.response.body":  # pragma: no branch
            assert message["body"] == b""
            assert message["more_body"] is False

    # Since the TestClient drops the response body on HEAD requests, we need to test
    # this directly.
    await app({"type": "http", "method": "head", "headers": [(b"key", b"value")]}, receive, send)


def test_file_response_set_media_type(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    path = tmp_path / "xyz"
    path.write_bytes(b"<file content>")

    # By default, FileResponse will determine the `content-type` based on
    # the filename or path, unless a specific `media_type` is provided.
    app = FileResponse(path=path, filename="example.png", media_type="image/jpeg")
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert response.headers["content-type"] == "image/jpeg"


def test_file_response_with_directory_raises_error(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    app = FileResponse(path=tmp_path, filename="example.png")
    client = test_client_factory(app)
    with pytest.raises(RuntimeError) as exc_info:
        client.get("/")
    assert "is not a file" in str(exc_info.value)


def test_file_response_with_missing_file_raises_error(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    path = tmp_path / "404.txt"
    app = FileResponse(path=path, filename="404.txt")
    client = test_client_factory(app)
    with pytest.raises(RuntimeError) as exc_info:
        client.get("/")
    assert "does not exist" in str(exc_info.value)


def test_file_response_with_chinese_filename(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    content = b"file content"
    filename = "你好.txt"  # probably "Hello.txt" in Chinese
    path = tmp_path / filename
    path.write_bytes(content)
    app = FileResponse(path=path, filename=filename)
    client = test_client_factory(app)
    response = client.get("/")
    expected_disposition = "attachment; filename*=utf-8''%E4%BD%A0%E5%A5%BD.txt"
    assert response.status_code == status.HTTP_200_OK
    assert response.content == content
    assert response.headers["content-disposition"] == expected_disposition


def test_file_response_with_inline_disposition(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    content = b"file content"
    filename = "hello.txt"
    path = tmp_path / filename
    path.write_bytes(content)
    app = FileResponse(path=path, filename=filename, content_disposition_type="inline")
    client = test_client_factory(app)
    response = client.get("/")
    expected_disposition = 'inline; filename="hello.txt"'
    assert response.status_code == status.HTTP_200_OK
    assert response.content == content
    assert response.headers["content-disposition"] == expected_disposition


def test_file_response_with_method_warns(tmp_path: Path) -> None:
    with pytest.warns(DeprecationWarning):
        FileResponse(path=tmp_path, filename="example.png", method="GET")


def test_file_response_with_range_header(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    content = b"file content"
    filename = "hello.txt"
    path = tmp_path / filename
    path.write_bytes(content)
    etag = '"a_non_autogenerated_etag"'
    app = FileResponse(path=path, filename=filename, headers={"etag": etag})
    client = test_client_factory(app)
    response = client.get("/", headers={"range": "bytes=0-4", "if-range": etag})
    assert response.status_code == status.HTTP_206_PARTIAL_CONTENT
    assert response.content == content[:5]
    assert response.headers["etag"] == etag
    assert response.headers["content-length"] == "5"
    assert response.headers["content-range"] == f"bytes 0-4/{len(content)}"


def test_set_cookie(test_client_factory: TestClientFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock time used as a reference for `Expires` by stdlib `SimpleCookie`.
    mocked_now = dt.datetime(2037, 1, 22, 12, 0, 0, tzinfo=dt.timezone.utc)
    monkeypatch.setattr(time, "time", lambda: mocked_now.timestamp())

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
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
            samesite="none",
        )
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "Hello, world!"
    assert (
        response.headers["set-cookie"] == "mycookie=myvalue; Domain=localhost; expires=Thu, 22 Jan 2037 12:00:10 GMT; "
        "HttpOnly; Max-Age=10; Path=/; SameSite=none; Secure"
    )


def test_set_cookie_path_none(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("Hello, world!", media_type="text/plain")
        response.set_cookie("mycookie", "myvalue", path=None)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "Hello, world!"
    assert response.headers["set-cookie"] == "mycookie=myvalue; SameSite=lax"


def test_set_cookie_samesite_none(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("Hello, world!", media_type="text/plain")
        response.set_cookie("mycookie", "myvalue", samesite=None)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "Hello, world!"
    assert response.headers["set-cookie"] == "mycookie=myvalue; Path=/"


@pytest.mark.parametrize(
    "expires",
    [
        pytest.param(dt.datetime(2037, 1, 22, 12, 0, 10, tzinfo=dt.timezone.utc), id="datetime"),
        pytest.param("Thu, 22 Jan 2037 12:00:10 GMT", id="str"),
        pytest.param(10, id="int"),
    ],
)
def test_expires_on_set_cookie(
    test_client_factory: TestClientFactory,
    monkeypatch: pytest.MonkeyPatch,
    expires: str,
) -> None:
    # Mock time used as a reference for `Expires` by stdlib `SimpleCookie`.
    mocked_now = dt.datetime(2037, 1, 22, 12, 0, 0, tzinfo=dt.timezone.utc)
    monkeypatch.setattr(time, "time", lambda: mocked_now.timestamp())

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        response = Response("Hello, world!", media_type="text/plain")
        response.set_cookie("mycookie", "myvalue", expires=expires)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    cookie = SimpleCookie(response.headers.get("set-cookie"))
    assert cookie["mycookie"]["expires"] == "Thu, 22 Jan 2037 12:00:10 GMT"


def test_delete_cookie(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        response = Response("Hello, world!", media_type="text/plain")
        if request.cookies.get("mycookie"):
            response.delete_cookie("mycookie")
        else:
            response.set_cookie("mycookie", "myvalue")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.cookies["mycookie"]
    response = client.get("/")
    assert not response.cookies.get("mycookie")


def test_populate_headers(test_client_factory: TestClientFactory) -> None:
    app = Response(content="hi", headers={}, media_type="text/html")
    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "hi"
    assert response.headers["content-length"] == "2"
    assert response.headers["content-type"] == "text/html; charset=utf-8"


def test_head_method(test_client_factory: TestClientFactory) -> None:
    app = Response("hello, world", media_type="text/plain")
    client = test_client_factory(app)
    response = client.head("/")
    assert response.text == ""


def test_empty_response(test_client_factory: TestClientFactory) -> None:
    app = Response()
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert response.content == b""
    assert response.headers["content-length"] == "0"
    assert "content-type" not in response.headers


def test_empty_204_response(test_client_factory: TestClientFactory) -> None:
    app = Response(status_code=204)
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert "content-length" not in response.headers


def test_non_empty_response(test_client_factory: TestClientFactory) -> None:
    app = Response(content="hi")
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert response.headers["content-length"] == "2"


def test_response_do_not_add_redundant_charset(
    test_client_factory: TestClientFactory,
) -> None:
    app = Response(media_type="text/plain; charset=utf-8")
    client = test_client_factory(app)
    response = client.get("/")
    assert response.headers["content-type"] == "text/plain; charset=utf-8"


def test_file_response_known_size(tmp_path: Path, test_client_factory: TestClientFactory) -> None:
    path = tmp_path / "xyz"
    content = b"<file content>" * 1000
    path.write_bytes(content)

    app = FileResponse(path=path, filename="example.png")
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert response.headers["content-length"] == str(len(content))


def test_streaming_response_unknown_size(
    test_client_factory: TestClientFactory,
) -> None:
    app = StreamingResponse(content=iter(["hello", "world"]))
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert "content-length" not in response.headers


def test_streaming_response_known_size(test_client_factory: TestClientFactory) -> None:
    app = StreamingResponse(content=iter(["hello", "world"]), headers={"content-length": "10"})
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert response.headers["content-length"] == "10"


def test_response_memoryview(test_client_factory: TestClientFactory) -> None:
    app = Response(content=memoryview(b"\xc0"))
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert response.content == b"\xc0"


def test_streaming_response_memoryview(test_client_factory: TestClientFactory) -> None:
    app = StreamingResponse(content=iter([memoryview(b"\xc0"), memoryview(b"\xf5")]))
    client: TestClient = test_client_factory(app)
    response = client.get("/")
    assert response.content == b"\xc0\xf5"


@pytest.mark.anyio
async def test_streaming_response_stops_if_receiving_http_disconnect() -> None:
    streamed = 0

    disconnected = anyio.Event()

    async def receive_disconnect() -> Message:
        await disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        nonlocal streamed
        if message["type"] == "http.response.body":
            streamed += len(message.get("body", b""))
            # Simulate disconnection after download has started
            if streamed >= 16:
                disconnected.set()

    async def stream_indefinitely() -> AsyncIterator[bytes]:
        while True:
            # Need a sleep for the event loop to switch to another task
            await anyio.sleep(0)
            yield b"chunk "

    response = StreamingResponse(content=stream_indefinitely())

    with anyio.move_on_after(1) as cancel_scope:
        await response({}, receive_disconnect, send)
    assert not cancel_scope.cancel_called, "Content streaming should stop itself."


@pytest.mark.anyio
async def test_streaming_response_on_client_disconnects() -> None:
    chunks = bytearray()
    streamed = False

    async def receive_disconnect() -> Message:
        raise NotImplementedError

    async def send(message: Message) -> None:
        nonlocal streamed
        if message["type"] == "http.response.body":
            if not streamed:
                chunks.extend(message.get("body", b""))
                streamed = True
            else:
                raise OSError

    async def stream_indefinitely() -> AsyncGenerator[bytes, None]:
        while True:
            await anyio.sleep(0)
            yield b"chunk"

    stream = stream_indefinitely()
    response = StreamingResponse(content=stream)

    with anyio.move_on_after(1) as cancel_scope:
        with pytest.raises(ClientDisconnect):
            await response({"asgi": {"spec_version": "2.4"}}, receive_disconnect, send)
    assert not cancel_scope.cancel_called, "Content streaming should stop itself."
    assert chunks == b"chunk"
    await stream.aclose()


README = """\
# BáiZé

Powerful and exquisite WSGI/ASGI framework/toolkit.

The minimize implementation of methods required in the Web framework. No redundant implementation means that you can freely customize functions without considering the conflict with baize's own implementation.

Under the ASGI/WSGI protocol, the interface of the request object and the response object is almost the same, only need to add or delete `await` in the appropriate place. In addition, it should be noted that ASGI supports WebSocket but WSGI does not.
"""  # noqa: E501


@pytest.fixture
def readme_file(tmp_path: Path) -> Path:
    filepath = tmp_path / "README.txt"
    filepath.write_bytes(README.encode("utf8"))
    return filepath


@pytest.fixture
def file_response_client(readme_file: Path, test_client_factory: TestClientFactory) -> TestClient:
    return test_client_factory(app=FileResponse(str(readme_file)))


def test_file_response_without_range(file_response_client: TestClient) -> None:
    response = file_response_client.get("/")
    assert response.status_code == 200
    assert response.headers["content-length"] == str(len(README.encode("utf8")))
    assert response.text == README


def test_file_response_head(file_response_client: TestClient) -> None:
    response = file_response_client.head("/")
    assert response.status_code == 200
    assert response.headers["content-length"] == str(len(README.encode("utf8")))
    assert response.content == b""


def test_file_response_range(file_response_client: TestClient) -> None:
    response = file_response_client.get("/", headers={"Range": "bytes=0-100"})
    assert response.status_code == 206
    assert response.headers["content-range"] == f"bytes 0-100/{len(README.encode('utf8'))}"
    assert response.headers["content-length"] == "101"
    assert response.content == README.encode("utf8")[:101]


def test_file_response_range_head(file_response_client: TestClient) -> None:
    response = file_response_client.head("/", headers={"Range": "bytes=0-100"})
    assert response.status_code == 206
    assert response.headers["content-length"] == str(101)
    assert response.content == b""


def test_file_response_range_multi(file_response_client: TestClient) -> None:
    response = file_response_client.get("/", headers={"Range": "bytes=0-100, 200-300"})
    assert response.status_code == 206
    assert response.headers["content-range"].startswith("multipart/byteranges; boundary=")
    assert response.headers["content-length"] == "439"


def test_file_response_range_multi_head(file_response_client: TestClient) -> None:
    response = file_response_client.head("/", headers={"Range": "bytes=0-100, 200-300"})
    assert response.status_code == 206
    assert response.headers["content-length"] == "439"
    assert response.content == b""

    response = file_response_client.head(
        "/",
        headers={"Range": "bytes=200-300", "if-range": response.headers["etag"][:-1]},
    )
    assert response.status_code == 200
    response = file_response_client.head(
        "/",
        headers={"Range": "bytes=200-300", "if-range": response.headers["etag"]},
    )
    assert response.status_code == 206


def test_file_response_range_invalid(file_response_client: TestClient) -> None:
    response = file_response_client.head("/", headers={"Range": "bytes: 0-1000"})
    assert response.status_code == 400


def test_file_response_range_head_max(file_response_client: TestClient) -> None:
    response = file_response_client.head("/", headers={"Range": f"bytes=0-{len(README.encode('utf8'))+1}"})
    assert response.status_code == 206


def test_file_response_range_416(file_response_client: TestClient) -> None:
    response = file_response_client.head("/", headers={"Range": f"bytes={len(README.encode('utf8'))+1}-"})
    assert response.status_code == 416
    assert response.headers["Content-Range"] == f"*/{len(README.encode('utf8'))}"


def test_file_response_only_support_bytes_range(file_response_client: TestClient) -> None:
    response = file_response_client.get("/", headers={"Range": "items=0-100"})
    assert response.status_code == 400
    assert response.text == "Only support bytes range"


def test_file_response_range_must_be_requested(file_response_client: TestClient) -> None:
    response = file_response_client.get("/", headers={"Range": "bytes="})
    assert response.status_code == 400
    assert response.text == "Range header: range must be requested"


def test_file_response_start_must_be_less_than_end(file_response_client: TestClient) -> None:
    response = file_response_client.get("/", headers={"Range": "bytes=100-0"})
    assert response.status_code == 400
    assert response.text == "Range header: start must be less than end"


def test_file_response_merge_ranges(file_response_client: TestClient) -> None:
    response = file_response_client.get("/", headers={"Range": "bytes=0-100, 50-200"})
    assert response.status_code == 206
    assert response.headers["content-length"] == "201"
    assert response.headers["content-range"] == f"bytes 0-200/{len(README.encode('utf8'))}"


def test_file_response_insert_ranges(file_response_client: TestClient) -> None:
    response = file_response_client.get("/", headers={"Range": "bytes=100-200, 0-50"})

    assert response.status_code == 206
    assert response.headers["content-range"].startswith("multipart/byteranges; boundary=")
    boundary = response.headers["content-range"].split("boundary=")[1]
    assert response.text.splitlines() == [
        f"--{boundary}",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Range: bytes 0-50/526",
        "",
        "# BáiZé",
        "",
        "Powerful and exquisite WSGI/ASGI framewo",
        f"--{boundary}",
        "Content-Type: text/plain; charset=utf-8",
        "Content-Range: bytes 100-200/526",
        "",
        "ds required in the Web framework. No redundant implementation means that you can freely customize fun",
        "",
        f"--{boundary}--",
    ]


@pytest.mark.anyio
async def test_file_response_multi_small_chunk_size(readme_file: Path) -> None:
    class SmallChunkSizeFileResponse(FileResponse):
        chunk_size = 10

    app = SmallChunkSizeFileResponse(path=str(readme_file))

    received_chunks: list[bytes] = []
    start_message: dict[str, Any] = {}

    async def receive() -> Message:
        raise NotImplementedError("Should not be called!")

    async def send(message: Message) -> None:
        if message["type"] == "http.response.start":
            start_message.update(message)
        elif message["type"] == "http.response.body":  # pragma: no branch
            received_chunks.append(message["body"])

    await app({"type": "http", "method": "get", "headers": [(b"range", b"bytes=0-15,20-35,35-50")]}, receive, send)
    assert start_message["status"] == 206

    headers = Headers(raw=start_message["headers"])
    assert headers.get("content-type") == "text/plain; charset=utf-8"
    assert headers.get("accept-ranges") == "bytes"
    assert "content-length" in headers
    assert "last-modified" in headers
    assert "etag" in headers
    assert headers["content-range"].startswith("multipart/byteranges; boundary=")
    boundary = headers["content-range"].split("boundary=")[1]

    assert received_chunks == [
        # Send the part headers.
        f"--{boundary}\nContent-Type: text/plain; charset=utf-8\nContent-Range: bytes 0-15/526\n\n".encode(),
        # Send the first chunk (10 bytes).
        b"# B\xc3\xa1iZ\xc3\xa9\n",
        # Send the second chunk (6 bytes).
        b"\nPower",
        # Send the new line to separate the parts.
        b"\n",
        # Send the part headers. We merge the ranges 20-35 and 35-50 into a single part.
        f"--{boundary}\nContent-Type: text/plain; charset=utf-8\nContent-Range: bytes 20-50/526\n\n".encode(),
        # Send the first chunk (10 bytes).
        b"and exquis",
        # Send the second chunk (10 bytes).
        b"ite WSGI/A",
        # Send the third chunk (10 bytes).
        b"SGI framew",
        # Send the last chunk (1 byte).
        b"o",
        b"\n",
        f"\n--{boundary}--\n".encode(),
    ]
