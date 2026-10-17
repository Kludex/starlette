from __future__ import annotations

from tempfile import SpooledTemporaryFile
from typing import BinaryIO

import pytest

from starlette.datastructures import UploadFile


@pytest.mark.anyio
@pytest.mark.parametrize("max_size", [1, 1024], ids=["disk", "memory"])
@pytest.mark.parametrize(
    ("position", "data", "expected_size"),
    [(0, b"abc", 10), (8, b"abc", 11), (10, b"abc", 13), (15, b"abc", 18), (15, b"", 10), (4, b"", 10)],
)
async def test_write_tracks_file_extent(max_size: int, position: int, data: bytes, expected_size: int) -> None:
    stream: BinaryIO = SpooledTemporaryFile(max_size=max_size)  # type: ignore[assignment]
    stream.write(b"0123456789")
    upload = UploadFile(stream, size=10)
    try:
        await upload.seek(position)
        await upload.write(data)
        assert upload.size == expected_size
        await upload.seek(0)
        content = await upload.read()
        assert len(content) == expected_size
        if data:
            assert content[position : position + len(data)] == data
    finally:
        await upload.close()


@pytest.mark.anyio
@pytest.mark.parametrize("max_size", [1, 1024], ids=["disk", "memory"])
async def test_failed_write_preserves_known_size(max_size: int, monkeypatch: pytest.MonkeyPatch) -> None:
    stream: BinaryIO = SpooledTemporaryFile(max_size=max_size)  # type: ignore[assignment]
    stream.write(b"0123456789")
    upload = UploadFile(stream, size=10)

    def fail_write(data: bytes) -> int:
        raise OSError("write failed")

    monkeypatch.setattr(stream, "write", fail_write)
    try:
        with pytest.raises(OSError, match="write failed"):
            await upload.write(b"abc")
        assert upload.size == 10
        await upload.seek(0)
        assert await upload.read() == b"0123456789"
    finally:
        await upload.close()


@pytest.mark.anyio
@pytest.mark.parametrize("max_size", [1, 1024], ids=["disk", "memory"])
async def test_write_preserves_unknown_size(max_size: int) -> None:
    stream: BinaryIO = SpooledTemporaryFile(max_size=max_size)  # type: ignore[assignment]
    stream.write(b"0123456789")
    upload = UploadFile(stream)
    try:
        await upload.seek(0)
        await upload.write(b"abc")
        assert upload.size is None
        await upload.seek(0)
        assert await upload.read() == b"abc3456789"
    finally:
        await upload.close()
