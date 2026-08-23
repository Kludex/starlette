from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner, ChunkedReceive, send_result
from starlette.formparsers import MultiPartException
from starlette.requests import Request
from starlette.types import Message, Receive, Scope, Send

KiB = 1024
MiB = 1024 * KiB


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    fields: int
    field_size: int
    chunk_size: int | None = 64 * KiB
    percent_encoded: bool = False
    max_fields: int = 1000
    max_part_size: int = MiB
    expected_error: str | None = None
    warmup: bool = False


CASES = (
    BenchmarkCase("fields-1000", fields=1000, field_size=8),
    BenchmarkCase("field-1MiB-single", fields=1, field_size=MiB, chunk_size=None, max_part_size=2 * MiB),
    BenchmarkCase("field-1MiB-64KiB", fields=1, field_size=MiB, max_part_size=2 * MiB, warmup=True),
    BenchmarkCase("percent-encoded", fields=100, field_size=8, percent_encoded=True),
    BenchmarkCase(
        "max-fields",
        fields=101,
        field_size=8,
        max_fields=100,
        expected_error="Too many fields. Maximum number of fields is 100.",
    ),
    BenchmarkCase(
        "max-part-size",
        fields=1,
        field_size=2 * KiB,
        max_part_size=KiB,
        expected_error="Field exceeded maximum size of 1KB.",
    ),
)


class FormApp:
    def __init__(self, case: BenchmarkCase) -> None:
        self.case = case

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        try:
            async with request.form(
                max_fields=self.case.max_fields,
                max_part_size=self.case.max_part_size,
            ) as form:
                value_size = 0
                for value in form.values():
                    assert isinstance(value, str)
                    value_size += len(value)
                result = f"{len(form)}:{value_size}".encode()
        except MultiPartException as exc:
            await send_result(send, 400, exc.message.encode())
            return

        await send_result(send, 200, result)


def make_fields(case: BenchmarkCase) -> list[tuple[str, str]]:
    if case.percent_encoded:
        return [(f"field {index}", f"café / {index}" * case.field_size) for index in range(case.fields)]
    return [(f"field{index}", "x" * case.field_size) for index in range(case.fields)]


def make_chunks(body: bytes, chunk_size: int | None) -> tuple[bytes, ...]:
    if chunk_size is None:
        return (body,)
    return tuple(body[offset : offset + chunk_size] for offset in range(0, len(body), chunk_size))


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
        "headers": [(b"content-type", b"application/x-www-form-urlencoded")],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 80),
    }


def dispatch(runner: ASGIRunner, app: FormApp, chunks: tuple[bytes, ...]) -> list[Message]:
    return runner.run(app, http_scope(), ChunkedReceive(chunks))


@pytest.fixture(scope="module", autouse=True)
def warm_form(asgi_runner: ASGIRunner) -> None:
    case = BenchmarkCase("warm", fields=1, field_size=1)
    body = urlencode(make_fields(case)).encode()
    for _ in range(100):
        dispatch(asgi_runner, FormApp(case), (body,))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
@pytest.mark.benchmark(max_time=0.5, max_rounds=1)
def test_urlencoded_form(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture, case: BenchmarkCase) -> None:
    fields = make_fields(case)
    body = urlencode(fields).encode()
    chunks = make_chunks(body, case.chunk_size)
    app = FormApp(case)
    if case.warmup:
        dispatch(asgi_runner, app, chunks)
    messages = benchmark.pedantic(dispatch, args=(asgi_runner, app, chunks), rounds=1)

    if case.expected_error is None:
        expected_status = 200
        expected_body = f"{case.fields}:{sum(len(value) for _, value in fields)}".encode()
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
