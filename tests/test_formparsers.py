from __future__ import annotations

import os
import typing
from contextlib import nullcontext as does_not_raise
from pathlib import Path

import pytest

from starlette.applications import Starlette
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, _user_safe_decode
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount
from starlette.types import ASGIApp, Receive, Scope, Send
from tests.types import TestClientFactory


class ForceMultipartDict(typing.Dict[typing.Any, typing.Any]):
    def __bool__(self) -> bool:
        return True


# FORCE_MULTIPART is an empty dict that boolean-evaluates as `True`.
FORCE_MULTIPART = ForceMultipartDict()


async def app(scope: Scope, receive: Receive, send: Send) -> None:
    request = Request(scope, receive)
    data = await request.form()
    output: dict[str, typing.Any] = {}
    for key, value in data.items():
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key] = {
                "filename": value.filename,
                "size": value.size,
                "content": content.decode(),
                "content_type": value.content_type,
            }
        else:
            output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def multi_items_app(scope: Scope, receive: Receive, send: Send) -> None:
    request = Request(scope, receive)
    data = await request.form()
    output: dict[str, list[typing.Any]] = {}
    for key, value in data.multi_items():
        if key not in output:
            output[key] = []
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key].append(
                {
                    "filename": value.filename,
                    "size": value.size,
                    "content": content.decode(),
                    "content_type": value.content_type,
                }
            )
        else:
            output[key].append(value)
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def app_with_headers(scope: Scope, receive: Receive, send: Send) -> None:
    request = Request(scope, receive)
    data = await request.form()
    output: dict[str, typing.Any] = {}
    for key, value in data.items():
        if isinstance(value, UploadFile):
            content = await value.read()
            output[key] = {
                "filename": value.filename,
                "size": value.size,
                "content": content.decode(),
                "content_type": value.content_type,
                "headers": list(value.headers.items()),
            }
        else:
            output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


async def app_read_body(scope: Scope, receive: Receive, send: Send) -> None:
    request = Request(scope, receive)
    # Read bytes, to force request.stream() to return the already parsed body
    await request.body()
    data = await request.form()
    output = {}
    for key, value in data.items():
        output[key] = value
    await request.close()
    response = JSONResponse(output)
    await response(scope, receive, send)


def make_app_max_parts(max_files: int = 1000, max_fields: int = 1000, max_part_size: int = 1024 * 1024) -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        data = await request.form(max_files=max_files, max_fields=max_fields, max_part_size=max_part_size)
        output: dict[str, typing.Any] = {}
        for key, value in data.items():
            if isinstance(value, UploadFile):
                content = await value.read()
                output[key] = {
                    "filename": value.filename,
                    "size": value.size,
                    "content": content.decode(),
                    "content_type": value.content_type,
                }
            else:
                output[key] = value
        await request.close()
        response = JSONResponse(output)
        await response(scope, receive, send)

    return app


def test_multipart_request_data(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/", data={"some": "data"}, files=FORCE_MULTIPART)
    assert response.json() == {"some": "data"}


def test_multipart_request_files(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "test.txt")
    with open(path, "wb") as file:
        file.write(b"<file content>")

    client = test_client_factory(app)
    with open(path, "rb") as f:
        response = client.post("/", files={"test": f})
        assert response.json() == {
            "test": {
                "filename": "test.txt",
                "size": 14,
                "content": "<file content>",
                "content_type": "text/plain",
            }
        }


def test_multipart_request_files_with_content_type(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path = os.path.join(tmpdir, "test.txt")
    with open(path, "wb") as file:
        file.write(b"<file content>")

    client = test_client_factory(app)
    with open(path, "rb") as f:
        response = client.post("/", files={"test": ("test.txt", f, "text/plain")})
        assert response.json() == {
            "test": {
                "filename": "test.txt",
                "size": 14,
                "content": "<file content>",
                "content_type": "text/plain",
            }
        }


def test_multipart_request_multiple_files(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = test_client_factory(app)
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        response = client.post("/", files={"test1": f1, "test2": ("test2.txt", f2, "text/plain")})
        assert response.json() == {
            "test1": {
                "filename": "test1.txt",
                "size": 15,
                "content": "<file1 content>",
                "content_type": "text/plain",
            },
            "test2": {
                "filename": "test2.txt",
                "size": 15,
                "content": "<file2 content>",
                "content_type": "text/plain",
            },
        }


def test_multipart_request_multiple_files_with_headers(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = test_client_factory(app_with_headers)
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        response = client.post(
            "/",
            files=[
                ("test1", (None, f1)),
                ("test2", ("test2.txt", f2, "text/plain", {"x-custom": "f2"})),
            ],
        )
        assert response.json() == {
            "test1": "<file1 content>",
            "test2": {
                "filename": "test2.txt",
                "size": 15,
                "content": "<file2 content>",
                "content_type": "text/plain",
                "headers": [
                    [
                        "content-disposition",
                        'form-data; name="test2"; filename="test2.txt"',
                    ],
                    ["x-custom", "f2"],
                    ["content-type", "text/plain"],
                ],
            },
        }


def test_multi_items(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    path1 = os.path.join(tmpdir, "test1.txt")
    with open(path1, "wb") as file:
        file.write(b"<file1 content>")

    path2 = os.path.join(tmpdir, "test2.txt")
    with open(path2, "wb") as file:
        file.write(b"<file2 content>")

    client = test_client_factory(multi_items_app)
    with open(path1, "rb") as f1, open(path2, "rb") as f2:
        response = client.post(
            "/",
            data={"test1": "abc"},
            files=[("test1", f1), ("test1", ("test2.txt", f2, "text/plain"))],
        )
        assert response.json() == {
            "test1": [
                "abc",
                {
                    "filename": "test1.txt",
                    "size": 15,
                    "content": "<file1 content>",
                    "content_type": "text/plain",
                },
                {
                    "filename": "test2.txt",
                    "size": 15,
                    "content": "<file2 content>",
                    "content_type": "text/plain",
                },
            ]
        }


def test_multipart_request_mixed_files_and_data(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post(
        "/",
        data=(
            # data
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"  # type: ignore
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
        headers={"Content-Type": ("multipart/form-data; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c")},
    )
    assert response.json() == {
        "file": {
            "filename": "file.txt",
            "size": 14,
            "content": "<file content>",
            "content_type": "text/plain",
        },
        "field0": "value0",
        "field1": "value1",
    }


def test_multipart_request_with_charset_for_filename(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post(
        "/",
        data=(
            # file
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"  # type: ignore
            b'Content-Disposition: form-data; name="file"; filename="\xe6\x96\x87\xe6\x9b\xb8.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            b"<file content>\r\n"
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c--\r\n"
        ),
        headers={"Content-Type": ("multipart/form-data; charset=utf-8; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c")},
    )
    assert response.json() == {
        "file": {
            "filename": "文書.txt",
            "size": 14,
            "content": "<file content>",
            "content_type": "text/plain",
        }
    }


def test_multipart_request_without_charset_for_filename(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post(
        "/",
        data=(
            # file
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"  # type: ignore
            b'Content-Disposition: form-data; name="file"; filename="\xe7\x94\xbb\xe5\x83\x8f.jpg"\r\n'
            b"Content-Type: image/jpeg\r\n\r\n"
            b"<file content>\r\n"
            b"--a7f7ac8d4e2e437c877bb7b8d7cc549c--\r\n"
        ),
        headers={"Content-Type": ("multipart/form-data; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c")},
    )
    assert response.json() == {
        "file": {
            "filename": "画像.jpg",
            "size": 14,
            "content": "<file content>",
            "content_type": "image/jpeg",
        }
    }


def test_multipart_request_with_encoded_value(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post(
        "/",
        data=(
            b"--20b303e711c4ab8c443184ac833ab00f\r\n"  # type: ignore
            b"Content-Disposition: form-data; "
            b'name="value"\r\n\r\n'
            b"Transf\xc3\xa9rer\r\n"
            b"--20b303e711c4ab8c443184ac833ab00f--\r\n"
        ),
        headers={"Content-Type": ("multipart/form-data; charset=utf-8; boundary=20b303e711c4ab8c443184ac833ab00f")},
    )
    assert response.json() == {"value": "Transférer"}


def test_urlencoded_request_data(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/", data={"some": "data"})
    assert response.json() == {"some": "data"}


def test_no_request_data(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/")
    assert response.json() == {}


def test_urlencoded_percent_encoding(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/", data={"some": "da ta"})
    assert response.json() == {"some": "da ta"}


def test_urlencoded_percent_encoding_keys(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.post("/", data={"so me": "data"})
    assert response.json() == {"so me": "data"}


def test_urlencoded_multi_field_app_reads_body(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app_read_body)
    response = client.post("/", data={"some": "data", "second": "key pair"})
    assert response.json() == {"some": "data", "second": "key pair"}


def test_multipart_multi_field_app_reads_body(tmpdir: Path, test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app_read_body)
    response = client.post("/", data={"some": "data", "second": "key pair"}, files=FORCE_MULTIPART)
    assert response.json() == {"some": "data", "second": "key pair"}


def test_user_safe_decode_helper() -> None:
    result = _user_safe_decode(b"\xc4\x99\xc5\xbc\xc4\x87", "utf-8")
    assert result == "ężć"


def test_user_safe_decode_ignores_wrong_charset() -> None:
    result = _user_safe_decode(b"abc", "latin-8")
    assert result == "abc"


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_missing_boundary_parameter(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    with expectation:
        res = client.post(
            "/",
            data=(
                # file
                b'Content-Disposition: form-data; name="file"; filename="\xe6\x96\x87\xe6\x9b\xb8.txt"\r\n'  # type: ignore
                b"Content-Type: text/plain\r\n\r\n"
                b"<file content>\r\n"
            ),
            headers={"Content-Type": "multipart/form-data; charset=utf-8"},
        )
        assert res.status_code == 400
        assert res.text == "Missing boundary in multipart."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_missing_name_parameter_on_content_disposition(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    with expectation:
        res = client.post(
            "/",
            data=(
                # data
                b"--a7f7ac8d4e2e437c877bb7b8d7cc549c\r\n"  # type: ignore
                b'Content-Disposition: form-data; ="field0"\r\n\r\n'
                b"value0\r\n"
            ),
            headers={"Content-Type": ("multipart/form-data; boundary=a7f7ac8d4e2e437c877bb7b8d7cc549c")},
        )
        assert res.status_code == 400
        assert res.text == 'The Content-Disposition header field "name" must be provided.'


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_too_many_fields_raise(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(1001):
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="N{i}";\r\n\r\n' "\r\n")
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many fields. Maximum number of fields is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_too_many_files_raise(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(1001):
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="N{i}"; filename="F{i}";\r\n\r\n' "\r\n")
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many files. Maximum number of files is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_too_many_files_single_field_raise(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(1001):
        # This uses the same field name "N" for all files, equivalent to a
        # multifile upload form field
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="N"; filename="F{i}";\r\n\r\n' "\r\n")
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many files. Maximum number of files is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_too_many_files_and_fields_raise(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(1001):
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="F{i}"; filename="F{i}";\r\n\r\n' "\r\n")
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="N{i}";\r\n\r\n' "\r\n")
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many files. Maximum number of files is 1000."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_max_parts(max_fields=1), pytest.raises(MultiPartException)),
        (
            Starlette(routes=[Mount("/", app=make_app_max_parts(max_fields=1))]),
            does_not_raise(),
        ),
    ],
)
def test_max_fields_is_customizable_low_raises(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(2):
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="N{i}";\r\n\r\n' "\r\n")
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many fields. Maximum number of fields is 1."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_max_parts(max_files=1), pytest.raises(MultiPartException)),
        (
            Starlette(routes=[Mount("/", app=make_app_max_parts(max_files=1))]),
            does_not_raise(),
        ),
    ],
)
def test_max_files_is_customizable_low_raises(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    fields = []
    for i in range(2):
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="F{i}"; filename="F{i}";\r\n\r\n' "\r\n")
    data = "".join(fields).encode("utf-8")
    with expectation:
        res = client.post(
            "/",
            data=data,  # type: ignore
            headers={"Content-Type": ("multipart/form-data; boundary=B")},
        )
        assert res.status_code == 400
        assert res.text == "Too many files. Maximum number of files is 1."


def test_max_fields_is_customizable_high(test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(make_app_max_parts(max_fields=2000, max_files=2000))
    fields = []
    for i in range(2000):
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="N{i}";\r\n\r\n' "\r\n")
        fields.append("--B\r\n" f'Content-Disposition: form-data; name="F{i}"; filename="F{i}";\r\n\r\n' "\r\n")
    data = "".join(fields).encode("utf-8")
    data += b"--B--\r\n"
    res = client.post(
        "/",
        data=data,  # type: ignore
        headers={"Content-Type": ("multipart/form-data; boundary=B")},
    )
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["N1999"] == ""
    assert res_data["F1999"] == {
        "filename": "F1999",
        "size": 0,
        "content": "",
        "content_type": None,
    }


@pytest.mark.parametrize(
    "app,expectation",
    [
        (app, pytest.raises(MultiPartException)),
        (Starlette(routes=[Mount("/", app=app)]), does_not_raise()),
    ],
)
def test_max_part_size_exceeds_limit(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    boundary = "------------------------4K1ON9fZkj9uCUmqLHRbbR"

    multipart_data = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="small"\r\n\r\n'
        "small content\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="large"\r\n\r\n'
        + ("x" * 1024 * 1024 + "x")  # 1MB + 1 byte of data
        + "\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Transfer-Encoding": "chunked",
    }

    with expectation:
        response = client.post("/", data=multipart_data, headers=headers)  # type: ignore
        assert response.status_code == 400
        assert response.text == "Part exceeded maximum size of 1024KB."


@pytest.mark.parametrize(
    "app,expectation",
    [
        (make_app_max_parts(max_part_size=1024 * 10), pytest.raises(MultiPartException)),
        (
            Starlette(routes=[Mount("/", app=make_app_max_parts(max_part_size=1024 * 10))]),
            does_not_raise(),
        ),
    ],
)
def test_max_part_size_exceeds_custom_limit(
    app: ASGIApp,
    expectation: typing.ContextManager[Exception],
    test_client_factory: TestClientFactory,
) -> None:
    client = test_client_factory(app)
    boundary = "------------------------4K1ON9fZkj9uCUmqLHRbbR"

    multipart_data = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="small"\r\n\r\n'
        "small content\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="large"\r\n\r\n'
        + ("x" * 1024 * 10 + "x")  # 1MB + 1 byte of data
        + "\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Transfer-Encoding": "chunked",
    }

    with expectation:
        response = client.post("/", content=multipart_data, headers=headers)
        assert response.status_code == 400
        assert response.text == "Part exceeded maximum size of 10KB."
