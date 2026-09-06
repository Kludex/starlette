from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import anyio
import pytest

from starlette.background import BackgroundTask
from starlette.responses import FileResponse
from starlette.types import Message, Scope

pytestmark = pytest.mark.anyio


@pytest.fixture
def file_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, list[anyio.AsyncFile[bytes]]]:
    path = tmp_path / "file.bin"
    path.write_bytes(b"x" * (8 * FileResponse.chunk_size))
    files: list[anyio.AsyncFile[bytes]] = []
    open_file = anyio.open_file

    async def track_open_file(path: str | os.PathLike[str], mode: Literal["rb"]) -> anyio.AsyncFile[bytes]:
        file = await open_file(path, mode=mode)
        files.append(file)
        return file

    monkeypatch.setattr(anyio, "open_file", track_open_file)
    return path, files


@pytest.fixture(params=[None, b"bytes=0-", b"bytes=0-131071,196608-524287"])
def scope(request: pytest.FixtureRequest) -> Scope:
    return {
        "type": "http",
        "method": "GET",
        "headers": [] if request.param is None else [(b"range", request.param)],
        "extensions": {"http.response.pathsend": {}} if request.param is not None else {},
    }


@pytest.mark.parametrize("spec_version", [None, "2.0", "2.3"])
async def test_file_response_stops_on_disconnect(
    file_path: tuple[Path, list[anyio.AsyncFile[bytes]]], scope: Scope, spec_version: str | None
) -> None:
    path, files = file_path
    if spec_version is not None:
        scope["asgi"] = {"spec_version": spec_version}
    disconnected = anyio.Event()
    received_request = False
    submitted = 0
    background_ran = False

    async def receive() -> Message:
        nonlocal received_request
        if not received_request:
            received_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await disconnected.wait()
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        nonlocal submitted
        if message["type"] == "http.response.body":
            submitted += len(message["body"])
            if submitted >= FileResponse.chunk_size:
                disconnected.set()

    async def cleanup() -> None:
        nonlocal background_ran
        assert len(files) == 1
        assert files[0].closed
        await anyio.sleep(0)
        background_ran = True

    with anyio.fail_after(5):
        await FileResponse(path, background=BackgroundTask(cleanup))(scope, receive, send)

    assert FileResponse.chunk_size <= submitted < 3 * FileResponse.chunk_size
    assert background_ran


@pytest.mark.parametrize("spec_version", ["2.0", "2.3", "2.4"])
async def test_file_response_closes_on_cancellation(
    file_path: tuple[Path, list[anyio.AsyncFile[bytes]]], scope: Scope, spec_version: str
) -> None:
    path, files = file_path
    scope["asgi"] = {"spec_version": spec_version}

    async def receive() -> Message:
        await anyio.sleep_forever()
        pytest.fail("The disconnect listener should be cancelled")  # pragma: no cover - sleep never returns

    async def send(message: Message) -> None:
        if message["type"] == "http.response.body":
            cancel_scope.cancel()
            await anyio.sleep_forever()

    async def cleanup() -> None:
        pytest.fail(
            "Background tasks should not run after external cancellation"
        )  # pragma: no cover - failure sentinel

    with anyio.fail_after(5), anyio.CancelScope() as cancel_scope:
        await FileResponse(path, background=BackgroundTask(cleanup))(scope, receive, send)

    assert cancel_scope.cancelled_caught
    assert len(files) == 1
    assert files[0].closed


@pytest.mark.parametrize("spec_version", ["2.0", "2.3", "2.4"])
async def test_file_response_closes_on_send_error(
    file_path: tuple[Path, list[anyio.AsyncFile[bytes]]], scope: Scope, spec_version: str
) -> None:
    path, files = file_path
    scope["asgi"] = {"spec_version": spec_version}
    error = OSError("Disconnected")

    async def receive() -> Message:
        assert spec_version != "2.4"
        await anyio.sleep_forever()
        pytest.fail("The disconnect listener should be cancelled")  # pragma: no cover - sleep never returns

    async def send(message: Message) -> None:
        if message["type"] == "http.response.body":
            raise error

    with anyio.fail_after(5), pytest.raises(OSError) as exc:
        await FileResponse(path)(scope, receive, send)

    assert exc.value is error
    assert len(files) == 1
    assert files[0].closed
