from __future__ import annotations

from dataclasses import dataclass

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner, ChunkedReceive, send_result
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException
from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

KiB = 1024
MiB = 1024 * KiB
BOUNDARY = b"starlette-benchmark-boundary"
CONTENT_TYPE = b"multipart/form-data; boundary=" + BOUNDARY


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    fields: int = 0
    field_size: int = 8
    file_sizes: tuple[int, ...] = ()
    chunk_size: int | None = 64 * KiB
    boundary_like: bool = False
    malformed: bool = False
    max_files: int = 1000
    max_fields: int = 1000
    max_part_size: int = MiB
    expected_error: str | None = None
    warmup: bool = False


CASES = (
    BenchmarkCase("fields-1000", fields=1000),
    BenchmarkCase("file-512KiB", file_sizes=(512 * KiB,), warmup=True),
    BenchmarkCase("file-10MiB-single", file_sizes=(10 * MiB,), chunk_size=None),
    BenchmarkCase("file-10MiB-64KiB", file_sizes=(10 * MiB,)),
    BenchmarkCase("mixed", fields=100, file_sizes=(512 * KiB,), warmup=True),
    BenchmarkCase("boundary-like-file", file_sizes=(MiB,), boundary_like=True, warmup=True),
    BenchmarkCase(
        "malformed-after-spooled-file",
        file_sizes=(2 * MiB,),
        malformed=True,
        expected_error='The Content-Disposition header field "name" must be provided.',
    ),
    BenchmarkCase(
        "max-fields",
        fields=101,
        max_fields=100,
        expected_error="Too many fields. Maximum number of fields is 100.",
    ),
    BenchmarkCase(
        "max-files",
        file_sizes=(1, 1),
        max_files=1,
        expected_error="Too many files. Maximum number of files is 1.",
    ),
    BenchmarkCase(
        "max-part-size",
        fields=1,
        field_size=2 * KiB,
        max_part_size=KiB,
        expected_error="Part exceeded maximum size of 1KB.",
    ),
)


class MultipartApp:
    def __init__(self, case: BenchmarkCase) -> None:
        self.case = case

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        try:
            async with request.form(
                max_files=self.case.max_files,
                max_fields=self.case.max_fields,
                max_part_size=self.case.max_part_size,
            ) as form:
                fields = 0
                files = 0
                file_bytes = 0
                for _, value in form.multi_items():
                    if isinstance(value, UploadFile):
                        files += 1
                        assert value.size is not None
                        file_bytes += value.size
                    else:
                        fields += 1
        except MultiPartException as exc:
            await send_result(send, 400, exc.message.encode())
            return

        await send_result(send, 200, f"{fields}:{files}:{file_bytes}".encode())


def http_scope() -> Scope:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "root_path": "",
        "query_string": b"",
        "headers": [(b"content-type", CONTENT_TYPE)],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 80),
    }


def field_part(index: int, size: int) -> bytes:
    value = bytes((65 + index % 26,)) * size
    return (
        b"--"
        + BOUNDARY
        + b'\r\nContent-Disposition: form-data; name="field'
        + str(index).encode()
        + b'"\r\n\r\n'
        + value
        + b"\r\n"
    )


def file_part(index: int, size: int, boundary_like: bool) -> bytes:
    if boundary_like:
        marker = b"\r\n--" + BOUNDARY[:-1] + b"x"
        content = (marker * (size // len(marker) + 1))[:size]
    else:
        content = bytes((65 + index % 26,)) * size
    return (
        b"--"
        + BOUNDARY
        + b'\r\nContent-Disposition: form-data; name="file'
        + str(index).encode()
        + b'"; filename="file.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'
        + content
        + b"\r\n"
    )


def make_body(case: BenchmarkCase) -> bytes:
    parts = [field_part(index, case.field_size) for index in range(case.fields)]
    parts.extend(file_part(index, size, case.boundary_like) for index, size in enumerate(case.file_sizes))
    if case.malformed:
        parts.append(b"--" + BOUNDARY + b"\r\nContent-Disposition: form-data\r\n\r\ninvalid\r\n")
    parts.append(b"--" + BOUNDARY + b"--\r\n")
    return b"".join(parts)


def make_chunks(body: bytes, chunk_size: int | None) -> tuple[bytes, ...]:
    if chunk_size is None:
        return (body,)
    return tuple(body[offset : offset + chunk_size] for offset in range(0, len(body), chunk_size))


def dispatch(runner: ASGIRunner, app: ASGIApp, chunks: tuple[bytes, ...]) -> list[Message]:
    return runner.run(app, http_scope(), ChunkedReceive(chunks))


@pytest.fixture(scope="module", autouse=True)
def warm_multipart(asgi_runner: ASGIRunner) -> None:
    case = BenchmarkCase("warm", fields=1, file_sizes=(1,))
    chunks = make_chunks(make_body(case), case.chunk_size)
    app = MultipartApp(case)
    for _ in range(100):
        dispatch(asgi_runner, app, chunks)

    spooled_case = BenchmarkCase("warm-spooled", file_sizes=(MiB + 1,))
    chunks = make_chunks(make_body(spooled_case), spooled_case.chunk_size)
    dispatch(asgi_runner, MultipartApp(spooled_case), chunks)

    boundary_case = BenchmarkCase("warm-boundary-like", file_sizes=(64 * KiB,), boundary_like=True)
    chunks = make_chunks(make_body(boundary_case), boundary_case.chunk_size)
    app = MultipartApp(boundary_case)
    for _ in range(10):
        dispatch(asgi_runner, app, chunks)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
@pytest.mark.benchmark(max_time=0.5, max_rounds=1)
def test_multipart(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture, case: BenchmarkCase) -> None:
    body = make_body(case)
    chunks = make_chunks(body, case.chunk_size)
    app = MultipartApp(case)
    if case.warmup:
        dispatch(asgi_runner, app, chunks)
    messages = benchmark.pedantic(dispatch, args=(asgi_runner, app, chunks), rounds=1)

    if case.expected_error is None:
        expected_status = 200
        expected_body = f"{case.fields}:{len(case.file_sizes)}:{sum(case.file_sizes)}".encode()
    else:
        expected_status = 400
        expected_body = case.expected_error.encode()

    assert messages == [
        {"type": "http.response.start", "status": expected_status, "headers": []},
        {"type": "http.response.body", "body": expected_body},
    ]
    benchmark.extra_info["body_bytes"] = len(body)
    benchmark.extra_info["chunk_bytes"] = case.chunk_size or len(body)
    benchmark.extra_info["chunks"] = len(chunks)
    benchmark.extra_info["fields"] = case.fields
    benchmark.extra_info["files"] = len(case.file_sizes)
