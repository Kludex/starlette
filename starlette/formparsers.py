import asyncio
import io
import tempfile
import typing
from enum import Enum
from urllib.parse import unquote_plus

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers

try:
    from multipart.multipart import parse_options_header
    import multipart
except ImportError:  # pragma: nocover
    parse_options_header = None  # type: ignore
    multipart = None  # type: ignore


class FormMessage(Enum):
    FIELD_START = 1
    FIELD_NAME = 2
    FIELD_DATA = 3
    FIELD_END = 4
    END = 5


class MultiPartMessage(Enum):
    PART_BEGIN = 1
    PART_DATA = 2
    PART_END = 3
    HEADER_FIELD = 4
    HEADER_VALUE = 5
    HEADER_END = 6
    HEADERS_FINISHED = 7
    END = 8


class UploadFile:
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self._file = io.BytesIO()  # type: typing.IO[typing.Any]
        self._loop = asyncio.get_event_loop()

    def create_tempfile(self) -> None:
        self._file = tempfile.SpooledTemporaryFile()

    async def setup(self) -> None:
        await run_in_threadpool(self.create_tempfile)

    async def write(self, data: bytes) -> None:
        await run_in_threadpool(self._file.write, data)

    async def read(self, size: int = None) -> bytes:
        return await run_in_threadpool(self._file.read, size)

    async def seek(self, offset: int) -> None:
        await run_in_threadpool(self._file.seek, offset)

    async def close(self) -> None:
        await run_in_threadpool(self._file.close)


class FormParser:
    def __init__(
        self, headers: Headers, stream: typing.AsyncGenerator[bytes, None]
    ) -> None:
        assert (
            multipart is not None
        ), "The `python-multipart` library must be installed to use form parsing."
        self.headers = headers
        self.stream = stream
        self.messages = []  # type: typing.List[typing.Tuple[FormMessage, bytes]]

    def on_field_start(self) -> None:
        message = (FormMessage.FIELD_START, b"")
        self.messages.append(message)

    def on_field_name(self, data: bytes, start: int, end: int) -> None:
        message = (FormMessage.FIELD_NAME, data[start:end])
        self.messages.append(message)

    def on_field_data(self, data: bytes, start: int, end: int) -> None:
        message = (FormMessage.FIELD_DATA, data[start:end])
        self.messages.append(message)

    def on_field_end(self) -> None:
        message = (FormMessage.FIELD_END, b"")
        self.messages.append(message)

    def on_end(self) -> None:
        message = (FormMessage.END, b"")
        self.messages.append(message)

    async def parse(self) -> typing.Dict[str, typing.Union[str, UploadFile]]:
        # Callbacks dictionary.
        callbacks = {
            "on_field_start": self.on_field_start,
            "on_field_name": self.on_field_name,
            "on_field_data": self.on_field_data,
            "on_field_end": self.on_field_end,
            "on_end": self.on_end,
        }

        # Create the parser.
        parser = multipart.QuerystringParser(callbacks)
        field_name = b""
        field_value = b""

        result = {}  # type: typing.Dict[str, typing.Union[str, UploadFile]]

        # Feed the parser with data from the request.
        async for chunk in self.stream:
            if chunk:
                parser.write(chunk)
            else:
                parser.finalize()
            messages = list(self.messages)
            self.messages.clear()
            for message_type, message_bytes in messages:
                if message_type == FormMessage.FIELD_START:
                    field_name = b""
                    field_value = b""
                elif message_type == FormMessage.FIELD_NAME:
                    field_name += message_bytes
                elif message_type == FormMessage.FIELD_DATA:
                    field_value += message_bytes
                elif message_type == FormMessage.FIELD_END:
                    name = unquote_plus(field_name.decode("latin-1"))
                    value = unquote_plus(field_value.decode("latin-1"))
                    result[name] = value
                elif message_type == FormMessage.END:
                    pass

        return result


class MultiPartParser:
    def __init__(
        self, headers: Headers, stream: typing.AsyncGenerator[bytes, None]
    ) -> None:
        assert (
            multipart is not None
        ), "The `python-multipart` library must be installed to use form parsing."
        self.headers = headers
        self.stream = stream
        self.messages = []  # type: typing.List[typing.Tuple[MultiPartMessage, bytes]]

    def on_part_begin(self) -> None:
        message = (MultiPartMessage.PART_BEGIN, b"")
        self.messages.append(message)

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        message = (MultiPartMessage.PART_DATA, data[start:end])
        self.messages.append(message)

    def on_part_end(self) -> None:
        message = (MultiPartMessage.PART_END, b"")
        self.messages.append(message)

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        message = (MultiPartMessage.HEADER_FIELD, data[start:end])
        self.messages.append(message)

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        message = (MultiPartMessage.HEADER_VALUE, data[start:end])
        self.messages.append(message)

    def on_header_end(self) -> None:
        message = (MultiPartMessage.HEADER_END, b"")
        self.messages.append(message)

    def on_headers_finished(self) -> None:
        message = (MultiPartMessage.HEADERS_FINISHED, b"")
        self.messages.append(message)

    def on_end(self) -> None:
        message = (MultiPartMessage.END, b"")
        self.messages.append(message)

    async def parse(self) -> typing.Dict[str, typing.Union[str, UploadFile]]:
        # Parse the Content-Type header to get the multipart boundary.
        content_type, params = parse_options_header(self.headers["Content-Type"])
        boundary = params.get(b"boundary")

        # Callbacks dictionary.
        callbacks = {
            "on_part_begin": self.on_part_begin,
            "on_part_data": self.on_part_data,
            "on_part_end": self.on_part_end,
            "on_header_field": self.on_header_field,
            "on_header_value": self.on_header_value,
            "on_header_end": self.on_header_end,
            "on_headers_finished": self.on_headers_finished,
            "on_end": self.on_end,
        }

        # Create the parser.
        parser = multipart.MultipartParser(boundary, callbacks)
        header_field = b""
        header_value = b""
        raw_headers = []  # type: typing.List[typing.Tuple[bytes, bytes]]
        field_name = ""
        data = b""
        file = None  # type: typing.Optional[UploadFile]

        result = {}  # type: typing.Dict[str, typing.Union[str, UploadFile]]

        # Feed the parser with data from the request.
        async for chunk in self.stream:
            parser.write(chunk)
            messages = list(self.messages)
            self.messages.clear()
            for message_type, message_bytes in messages:
                if message_type == MultiPartMessage.PART_BEGIN:
                    raw_headers = []
                    data = b""
                elif message_type == MultiPartMessage.HEADER_FIELD:
                    header_field += message_bytes
                elif message_type == MultiPartMessage.HEADER_VALUE:
                    header_value += message_bytes
                elif message_type == MultiPartMessage.HEADER_END:
                    raw_headers.append((header_field.lower(), header_value))
                    header_field = b""
                    header_value = b""
                elif message_type == MultiPartMessage.HEADERS_FINISHED:
                    headers = Headers(raw=raw_headers)
                    content_disposition = headers.get("Content-Disposition")
                    disposition, options = parse_options_header(content_disposition)
                    field_name = options[b"name"].decode("latin-1")
                    if b"filename" in options:
                        filename = options[b"filename"].decode("latin-1")
                        file = UploadFile(filename=filename)
                        await file.setup()
                    else:
                        file = None
                elif message_type == MultiPartMessage.PART_DATA:
                    if file is None:
                        data += message_bytes
                    else:
                        await file.write(message_bytes)
                elif message_type == MultiPartMessage.PART_END:
                    if file is None:
                        result[field_name] = data.decode("latin-1")
                    else:
                        await file.seek(0)
                        result[field_name] = file
                elif message_type == MultiPartMessage.END:
                    pass

        parser.finalize()
        return result
