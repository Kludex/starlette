from starlette.datastructures import MutableHeaders
from starlette.types import Receive, Send
import json
import typing
import os


class Response:
    media_type = None
    charset = "utf-8"

    def __init__(
        self,
        content: typing.Any,
        status_code: int = 200,
        headers: dict = None,
        media_type: str = None,
    ) -> None:
        self.body = self.render(content)
        self.status_code = status_code
        self.media_type = self.media_type if media_type is None else media_type
        self.raw_headers = [] if headers is None else [
            (k.lower().encode("latin-1"), v.encode("latin-1"))
            for k, v in headers.items()
        ]
        self.headers = MutableHeaders(self.raw_headers)
        self.set_default_headers()

    def render(self, content: typing.Any) -> bytes:
        if isinstance(content, bytes):
            return content
        return content.encode(self.charset)

    def set_default_headers(self):
        content_length = str(len(self.body)) if hasattr(self, 'body') else None
        content_type = self.default_content_type

        if content_length is not None:
            self.headers.set_default("content-length", content_length)
        if content_type is not None:
            self.headers.set_default("content-type", content_type)

    @property
    def default_content_type(self):
        if self.media_type is None:
            return None

        if self.media_type.startswith('text/') and self.charset is not None:
            return '%s; charset=%s' % (self.media_type, self.charset)
        return self.media_type

    async def __call__(self, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )
        await send({"type": "http.response.body", "body": self.body})


class HTMLResponse(Response):
    media_type = "text/html"


class PlainTextResponse(Response):
    media_type = "text/plain"


class JSONResponse(Response):
    media_type = "application/json"
    options = {
        "ensure_ascii": False,
        "allow_nan": False,
        "indent": None,
        "separators": (",", ":"),
    }  # type: typing.Dict[str, typing.Any]

    def render(self, content: typing.Any) -> bytes:
        return json.dumps(content, **self.options).encode("utf-8")


class StreamingResponse(Response):
    def __init__(
        self,
        content: typing.Any,
        status_code: int = 200,
        headers: dict = None,
        media_type: str = None,
    ) -> None:
        self.body_iterator = content
        self.status_code = status_code
        self.media_type = self.media_type if media_type is None else media_type
        self.raw_headers = [] if headers is None else [
            (k.lower().encode("latin-1"), v.encode("latin-1"))
            for k, v in headers.items()
        ]
        self.headers = MutableHeaders(self.raw_headers)
        self.set_default_headers()

    async def __call__(self, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": [
                    [key.encode(), value.encode()] for key, value in self.headers
                ],
            }
        )
        async for chunk in self.body_iterator:
            if not isinstance(chunk, bytes):
                chunk = chunk.encode(self.charset)
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

#
# class FileResponse:
#     def __init__(
#         self,
#         path: str,
#         headers: dict = None,
#         media_type: str = None,
#         filename: str = None
#     ) -> None:
#         self.path = path
#         self.status_code = 200
#         if media_type is not None:
#             self.media_type = media_type
#         if filename is not None:
#             self.filename = filename
#         else:
#             self.filename = os.path.basename(path)
#
#         self.set_default_headers(headers)
