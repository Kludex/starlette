from starlette.datastructures import MutableHeaders
from starlette.types import Receive, Send
import json
import typing

StrPairs = typing.Sequence[typing.Tuple[str, str]]
StrDict = typing.Mapping[str, str]


class Response:
    media_type = None
    charset = "utf-8"

    def __init__(
        self,
        content: typing.Any,
        status_code: int = 200,
        headers: typing.Union[StrDict, StrPairs] = None,
        media_type: str = None,
    ) -> None:
        self.body = self.render(content)
        self.status_code = status_code
        self.headers = MutableHeaders(headers)
        if media_type is not None:
            self.media_type = media_type
        self.set_content_type()
        self.set_content_length()

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
        await send({"type": "http.response.body", "body": self.body})

    def render(self, content: typing.Any) -> bytes:
        if isinstance(content, bytes):
            return content
        return content.encode(self.charset)

    def set_content_length(self):
        if "content-length" not in self.headers:
            self.headers["content-length"] = str(len(self.body))

    def set_content_type(self):
        if "content-type" not in self.headers and self.media_type is not None:
            content_type = self.media_type
            if content_type.startswith("text/") and self.charset is not None:
                content_type += "; charset=%s" % self.charset
            self.headers["content-type"] = content_type


class HTMLResponse(Response):
    media_type = "text/html"


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
        headers: typing.Union[StrDict, StrPairs] = None,
        media_type: str = None,
    ) -> None:
        self.body_iterator = content
        self.status_code = status_code
        self.headers = MutableHeaders(headers)
        if media_type is not None:
            self.media_type = media_type
        self.set_content_type()

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
