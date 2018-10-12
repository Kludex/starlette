from starlette.formparsers import UploadFile
from starlette.responses import JSONResponse
from starlette.requests import Request
from starlette.testclient import TestClient
import os


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


def test_urlencoded_request_data(tmpdir):
    client = TestClient(app)
    response = client.post("/", data={"some": "data"})
    assert response.json() == {"some": "data"}


def test_no_request_data(tmpdir):
    client = TestClient(app)
    response = client.post("/")
    assert response.json() == {}
