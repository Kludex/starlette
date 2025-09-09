import os

import pytest

from starlette._fileio import AsyncFileIO


class GoodAsyncFile:
    async def read(self, size: int = -1) -> bytes:
        return b"ok"

    async def write(self, data: bytes) -> int:
        return len(data)

    async def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return offset

    async def aclose(self) -> None:
        return None


class BadAsyncFile_MissingSeek:
    async def read(self, size: int = -1) -> bytes:
        return b"ok"

    async def write(self, data: bytes) -> int:
        return len(data)

    async def aclose(self) -> None:
        return None


def test_async_fileio_runtime_check_positive() -> None:
    obj = GoodAsyncFile()
    assert isinstance(obj, AsyncFileIO)
    assert issubclass(GoodAsyncFile, AsyncFileIO)


def test_async_fileio_runtime_check_negative() -> None:
    obj = BadAsyncFile_MissingSeek()
    assert not isinstance(obj, AsyncFileIO)
    assert not issubclass(BadAsyncFile_MissingSeek, AsyncFileIO)


def test_async_fileio_runtime_check_unrelated_type() -> None:
    assert not isinstance(123, AsyncFileIO)


def test_async_fileio_runtime_check_typeerror() -> None:
    with pytest.raises(TypeError):
        issubclass(123, AsyncFileIO)  # type: ignore[arg-type]


@pytest.mark.anyio
async def test_goodasyncfile_methods_execute() -> None:
    f = GoodAsyncFile()
    assert await f.read() == b"ok"
    assert await f.write(b"abc") == 3
    assert await f.seek(5) == 5
    await f.aclose()


@pytest.mark.anyio
async def test_badasyncfile_methods_execute() -> None:
    f = BadAsyncFile_MissingSeek()
    assert await f.read() == b"ok"
    assert await f.write(b"abc") == 3
    await f.aclose()
