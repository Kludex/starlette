from __future__ import annotations

from pathlib import Path

import anyio
import pytest
from httpx2 import ASGITransport, AsyncClient

from starlette.background import BackgroundTask, BackgroundTasks
from starlette.middleware.compression import CompressionMiddleware
from starlette.responses import FileResponse, PlainTextResponse
from starlette.types import Receive, Scope, Send

pytestmark = pytest.mark.anyio


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("headers", [{}, {"content-encoding": "custom"}, {"content-type": "text/event-stream"}])
async def test_rejected_response_background_tasks(method: str, headers: dict[str, str]) -> None:
    completed: list[str] = []

    async def async_task() -> None:
        await anyio.sleep(0)
        completed.append("async")

    def sync_task() -> None:
        completed.append("sync")

    background = BackgroundTasks()
    background.add_task(async_task)
    background.add_task(sync_task)
    app = CompressionMiddleware(PlainTextResponse("hello", headers=headers, background=background))
    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.request(method, "/", headers={"accept-encoding": "*;q=0"})
    assert response.status_code == 406
    assert response.content == (b"Not Acceptable" if method == "GET" else b"")
    assert completed == ["async", "sync"]


@pytest.mark.parametrize("pathsend", [False, True])
async def test_rejected_file_response_background_task(tmp_path: Path, pathsend: bool) -> None:
    path = tmp_path / "body.txt"
    path.write_text("hello")
    completed: list[bool] = []

    async def background() -> None:
        await anyio.sleep(0)
        completed.append(True)

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        scope = {**scope, "extensions": {"http.response.pathsend": {}} if pathsend else {}}
        response = FileResponse(path, background=BackgroundTask(background))
        await CompressionMiddleware(response)(scope, receive, send)

    async with AsyncClient(transport=ASGITransport(app), base_url="http://test") as client:
        response = await client.get("/", headers={"accept-encoding": "*;q=0"})
    assert response.status_code == 406
    assert response.text == "Not Acceptable"
    assert completed == [True]
