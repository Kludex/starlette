from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner
from starlette.datastructures import Headers
from starlette.responses import FileResponse
from starlette.types import Message, Receive, Scope, Send

KiB = 1024
MiB = 1024 * KiB


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    file_size: int
    pathsend: bool = False
    range_header: bytes | None = None
    expected_size: int | None = None


CASES = (
    BenchmarkCase("fallback-1KiB", KiB),
    BenchmarkCase("fallback-10MiB", 10 * MiB),
    BenchmarkCase("pathsend-10MiB", 10 * MiB, pathsend=True),
    BenchmarkCase("range-64KiB", 10 * MiB, range_header=b"bytes=262144-327679", expected_size=64 * KiB),
)


class FileApp:
    def __init__(self, path: Path) -> None:
        self.path = path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await FileResponse(self.path, media_type="application/octet-stream")(scope, receive, send)


def http_scope(case: BenchmarkCase) -> Scope:
    headers = [] if case.range_header is None else [(b"range", case.range_header)]
    extensions: dict[str, dict[str, object]] = {"http.response.pathsend": {}} if case.pathsend else {}
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "root_path": "",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 80),
        "extensions": extensions,
    }


def dispatch(runner: ASGIRunner, app: FileApp, case: BenchmarkCase) -> list[Message]:
    return runner.run(app, http_scope(case))


@pytest.fixture(scope="module", autouse=True)
def warm_file_response(asgi_runner: ASGIRunner, tmp_path_factory: pytest.TempPathFactory) -> None:
    path = tmp_path_factory.mktemp("file-response-warm") / "file.bin"
    path.write_bytes(b"x" * KiB)
    app = FileApp(path)
    cases = (
        BenchmarkCase("warm-fallback", KiB),
        BenchmarkCase("warm-pathsend", KiB, pathsend=True),
        BenchmarkCase("warm-range", KiB, range_header=b"bytes=0-0", expected_size=1),
    )
    for case in cases:
        for _ in range(100):
            dispatch(asgi_runner, app, case)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
@pytest.mark.benchmark(max_time=0.5, max_rounds=1)
def test_file_response(
    tmp_path: Path,
    asgi_runner: ASGIRunner,
    benchmark: BenchmarkFixture,
    case: BenchmarkCase,
) -> None:
    path = tmp_path / "file.bin"
    path.write_bytes(b"x" * case.file_size)
    messages = benchmark.pedantic(dispatch, args=(asgi_runner, FileApp(path), case), rounds=1)

    expected_status = 206 if case.range_header is not None else 200
    assert messages[0]["type"] == "http.response.start"
    assert messages[0]["status"] == expected_status
    headers = Headers(raw=messages[0]["headers"])
    expected_size = case.expected_size or case.file_size
    assert headers["content-length"] == str(expected_size)

    if case.pathsend:
        assert messages[1:] == [{"type": "http.response.pathsend", "path": str(path)}]
    else:
        body_messages = messages[1:]
        assert sum(len(message.get("body", b"")) for message in body_messages) == expected_size
        assert body_messages[-1].get("more_body") is False

    if case.range_header is not None:
        assert headers["content-range"] == f"bytes 262144-327679/{case.file_size}"

    benchmark.extra_info["file_bytes"] = case.file_size
    benchmark.extra_info["response_bytes"] = expected_size
    benchmark.extra_info["pathsend"] = case.pathsend
