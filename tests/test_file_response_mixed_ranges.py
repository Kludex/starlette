from pathlib import Path

import pytest

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, Response
from starlette.routing import Route
from tests.types import TestClientFactory


@pytest.mark.parametrize("range_header", ["bytes=0-1,20-30", "bytes=20-30,0-1", "bytes=0-1,20-", "bytes=0-1,-0"])
def test_file_response_keeps_satisfiable_ranges(
    tmp_path: Path, test_client_factory: TestClientFactory, range_header: str
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"0123456789")

    async def download(request: Request) -> Response:
        return FileResponse(path)

    with test_client_factory(Starlette(routes=[Route("/", download)])) as client:
        response = client.get("/", headers={"range": range_header})
    assert response.status_code == 206
    assert response.headers["content-range"] == "bytes 0-1/10"
    assert response.content == b"01"


@pytest.mark.parametrize("range_header,status", [("bytes=20-30,40-", 416), ("bytes=-0", 416), ("bytes=0-1,5-4", 400)])
def test_file_response_rejects_unsatisfiable_or_invalid_ranges(
    tmp_path: Path, test_client_factory: TestClientFactory, range_header: str, status: int
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"0123456789")

    async def download(request: Request) -> Response:
        return FileResponse(path)

    with test_client_factory(Starlette(routes=[Route("/", download)])) as client:
        response = client.get("/", headers={"range": range_header})
    assert response.status_code == status


def test_file_response_multipart_ignores_unsatisfiable_ranges(
    tmp_path: Path, test_client_factory: TestClientFactory
) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"0123456789")

    async def download(request: Request) -> Response:
        return FileResponse(path)

    with test_client_factory(Starlette(routes=[Route("/", download)])) as client:
        response = client.get("/", headers={"range": "bytes=0-1,4-5,20-30"})
    assert response.status_code == 206
    assert response.headers["content-type"].startswith("multipart/byteranges; boundary=")
    assert b"Content-Range: bytes 0-1/10" in response.content
    assert b"Content-Range: bytes 4-5/10" in response.content
    assert b"Content-Range: bytes 20-" not in response.content
    assert len(response.content) == int(response.headers["content-length"])
