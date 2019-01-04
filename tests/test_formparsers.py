import os

from starlette.formparsers import UploadFile
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.testclient import TestClient


class ForceMultipartDict(dict):
    def __bool__(self):
        return True


# FORCE_MULTIPART is an empty dict that boolean-evaluates as `True`.
FORCE_MULTIPART = ForceMultipartDict()


def app(scope):
    async def asgi(receive, send):
        request = Request(scope, receive)
        data = await request.form()
        output = {}
        for key, value in data.items():
            if isinstance(value, UploadFile):
                content = await value.read()
                output[key] = {"filename": value.filename, "content": content.decode()}
            else:
                output[key] = value
        await request.close()
        response = JSONResponse(output)
        await response(receive, send)

    return asgi


def app_read_body(scope):
    async def asgi(receive, send):
        request = Request(scope, receive)
        # Read bytes, to force request.stream() to return the already parsed body
        body_bytes = await request.body()
        data = await request.form()
        output = {}
        for key, value in data.items():
            output[key] = value
        await request.close()
        response = JSONResponse(output)
        await response(receive, send)

    return asgi


def test_multipart_request_data(tmpdir):
    client = TestClient(app)
    response = client.post("/", data={"some": "data"}, files=FORCE_MULTIPART)
    assert response.json() == {"some": "data"}


def test_multipart_request_files(tmpdir):
    path = os.path.join(tmpdir, "test.txt")
    with open(path, "wb") as file:
        file.write(b"<file content>")

    client = TestClient(app)
    response = client.post("/", files={"test": open(path, "rb")})
    assert response.json() == {
        "test": {"filename": "test.txt", "content": "<file content>"}
    }


def test_multipart_request_multiple_files(tmpdir):
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = TestClient(app)
    response = client.post(
        "/", files={"test1": open(path1, "rb"), "test2": open(path2, "rb")}
    )
    assert response.json() == {
        "test1": {"filename": "test1.txt", "content": "<file1 content>"},
        "test2": {"filename": "test2.txt", "content": "<file2 content>"},
    }


def test_multipart_request_mixed_files_and_data(tmpdir):
    client = TestClient(app)
    response = client.post(
        "/",
        data=(
            # data
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"
            b'Content-Disposition: form-data; name="field0"\r\n\r\n'
            b"value0\r\n"
            # file
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"
            b'Content-Disposition: form-data; name="file"; filename="file.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"<file content>\r\n"
            # data
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"
            b'Content-Disposition: form-data; name="field1"\r\n\r\n'
            b"value1\r\n"
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c--\r\n"
        ),
        headers={
            "Content-Type": "multipart/form-data; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c"
        },
    )
    assert response.json() == {
        "file": {"filename": "file.txt", "content": "<file content>"},
        "field0": "value0",
        "field1": "value1",
    }


def test_urlencoded_request_data(tmpdir):
    client = TestClient(app)
    response = client.post("/", data={"some": "data"})
    assert response.json() == {"some": "data"}


def test_no_request_data(tmpdir):
    client = TestClient(app)
    response = client.post("/")
    assert response.json() == {}


def test_urlencoded_multi_field_app_reads_body(tmpdir):
    client = TestClient(app_read_body)
    response = client.post("/", data={"some": "data", "second": "key pair"})
    assert response.json() == {"some": "data", "second": "key pair"}


def test_multipart_multi_field_app_reads_body(tmpdir):
    client = TestClient(app_read_body)
    response = client.post(
        "/", data={"some": "data", "second": "key pair"}, files=FORCE_MULTIPART
    )
    assert response.json() == {"some": "data", "second": "key pair"}
