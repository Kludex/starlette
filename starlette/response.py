from starlette.datastructures import MutableHeaders
from starlette.types import Receive, Send
import json
import typing


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
        if media_type is not None:
            self.media_type = media_type
        self.set_default_headers(headers)

    def render(self, content: typing.Any) -> bytes:
        if isinstance(content, bytes):
            return content
        return content.encode(self.charset)

    def set_default_headers(self, headers: dict = None):
        if headers is None:
            raw_headers = []
            missing_content_length = True
            missing_content_type = True
        else:
            raw_headers = [
                (k.lower().encode("latin-1"), v.encode("latin-1"))
                for k, v in headers.items()
            ]
            missing_content_length = "content-length" not in headers
            missing_content_type = "content-type" not in headers

        if missing_content_length:
            content_length = str(len(self.body)).encode()
            raw_headers.append((b"content-length", content_length))

        if self.media_type is not None and missing_content_type:
            content_type = self.media_type
            if content_type.startswith("text/") and self.charset is not None:
                content_type += "; charset=%s" % self.charset
            content_type_value = content_type.encode("latin-1")
            raw_headers.append((b"content-type", content_type_value))

        self.raw_headers = raw_headers

    @property
    def headers(self):
        if not hasattr(self, "_headers"):
            self._headers = MutableHeaders(self.raw_headers)
        return self._headers

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
        if media_type is not None:
            self.media_type = media_type
        self.set_default_headers(headers)

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

    def set_default_headers(self, headers: dict = None):
        if headers is None:
            raw_headers = []
            missing_content_type = True
        else:
            raw_headers = [
                (k.lower().encode("latin-1"), v.encode("latin-1"))
                for k, v in headers.items()
            ]
            missing_content_type = "content-type" not in headers

        if self.media_type is not None and missing_content_type:
            content_type = self.media_type
            if content_type.startswith("text/") and self.charset is not None:
                content_type += "; charset=%s" % self.charset
            content_type_value = content_type.encode("latin-1")
            raw_headers.append((b"content-type", content_type_value))

        self.raw_headers = raw_headers
