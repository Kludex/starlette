import hashlib
import http.cookies
import json
import os
import stat
import typing
from email.utils import formatdate
from mimetypes import guess_type
from urllib.parse import quote_plus

from starlette.background import BackgroundTask
from starlette.datastructures import URL, MutableHeaders
from starlette.types import Receive, Send

try:
    import aiofiles
    from aiofiles.os import stat as aio_stat
except ImportError:  # pragma: nocover
    aiofiles = None  # type: ignore
    aio_stat = None  # type: ignore

try:
    import ujson
except ImportError:  # pragma: nocover
    ujson = None  # type: ignore


class Response:
    media_type = None
    charset = "utf-8"

    def __init__(
        self,
        content: typing.Any = None,
        status_code: int = 200,
        headers: dict = None,
        media_type: str = None,
        background: BackgroundTask = None,
    ) -> None:
        if content is None:
            self.body = b""
        else:
            self.body = self.render(content)
        self.status_code = status_code
        if media_type is not None:
            self.media_type = media_type
        self.background = background
        self.init_headers(headers)

    def render(self, content: typing.Any) -> bytes:
        if isinstance(content, bytes):
            return content
        return content.encode(self.charset)

    def init_headers(self, headers: typing.Mapping[str, str] = None) -> None:
        if headers is None:
            raw_headers = []  # type: typing.List[typing.Tuple[bytes, bytes]]
            populate_content_length = True
            populate_content_type = True
        else:
            raw_headers = [
                (k.lower().encode("latin-1"), v.encode("latin-1"))
                for k, v in headers.items()
            ]
            keys = [h[0] for h in raw_headers]
            populate_content_length = b"content-length" not in keys
            populate_content_type = b"content-type" not in keys

        body = getattr(self, "body", b"")
        if body and populate_content_length:
            content_length = str(len(body))
            raw_headers.append((b"content-length", content_length.encode("latin-1")))

        content_type = self.media_type
        if content_type is not None and populate_content_type:
            if content_type.startswith("text/"):
                content_type += "; charset=" + self.charset
            raw_headers.append((b"content-type", content_type.encode("latin-1")))

        self.raw_headers = raw_headers

    @property
    def headers(self) -> MutableHeaders:
        if not hasattr(self, "_headers"):
            self._headers = MutableHeaders(raw=self.raw_headers)
        return self._headers

    def set_cookie(
        self,
        key: str,
        value: str = "",
        max_age: int = None,
        expires: int = None,
        path: str = "/",
        domain: str = None,
        secure: bool = False,
        httponly: bool = False,
    ) -> None:
        cookie = http.cookies.SimpleCookie()
        cookie[key] = value
        if max_age is not None:
            cookie[key]["max-age"] = max_age  # type: ignore
        if expires is not None:
            cookie[key]["expires"] = expires  # type: ignore
        if path is not None:
            cookie[key]["path"] = path
        if domain is not None:
            cookie[key]["domain"] = domain
        if secure:
            cookie[key]["secure"] = True  # type: ignore
        if httponly:
            cookie[key]["httponly"] = True  # type: ignore
        cookie_val = cookie.output(header="").strip()
        self.raw_headers.append((b"set-cookie", cookie_val.encode("latin-1")))

    def delete_cookie(self, key: str, path: str = "/", domain: str = None) -> None:
        self.set_cookie(key, expires=0, max_age=0, path=path, domain=domain)

    async def __call__(self, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )
        await send({"type": "http.response.body", "body": self.body})

        if self.background is not None:
            await self.background()


class HTMLResponse(Response):
    media_type = "text/html"


class PlainTextResponse(Response):
    media_type = "text/plain"


class JSONResponse(Response):
    media_type = "application/json"

    def render(self, content: typing.Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
        ).encode("utf-8")


class UJSONResponse(JSONResponse):
    media_type = "application/json"

    def render(self, content: typing.Any) -> bytes:
        return ujson.dumps(content, ensure_ascii=False).encode("utf-8")


class RedirectResponse(Response):
    def __init__(
        self, url: typing.Union[str, URL], status_code: int = 302, headers: dict = None
    ) -> None:
        super().__init__(content=b"", status_code=status_code, headers=headers)
        self.headers["location"] = quote_plus(str(url), safe=":/#?&=@[]!$&'()*+,;")


class StreamingResponse(Response):
    def __init__(
        self,
        content: typing.Any,
        status_code: int = 200,
        headers: dict = None,
        media_type: str = None,
        background: BackgroundTask = None,
    ) -> None:
        self.body_iterator = content
        self.status_code = status_code
        self.media_type = self.media_type if media_type is None else media_type
        self.background = background
        self.init_headers(headers)

    async def __call__(self, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )
        async for chunk in self.body_iterator:
            if not isinstance(chunk, bytes):
                chunk = chunk.encode(self.charset)
            await send({"type": "http.response.body", "body": chunk, "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

        if self.background is not None:
            await self.background()


class FileResponse(Response):
    chunk_size = 4096

    def __init__(
        self,
        path: str,
        headers: dict = None,
        media_type: str = None,
        background: BackgroundTask = None,
        filename: str = None,
        stat_result: os.stat_result = None,
        method: str = None,
    ) -> None:
        assert aiofiles is not None, "'aiofiles' must be installed to use FileResponse"
        self.path = path
        self.status_code = 200
        self.filename = filename
        self.send_header_only = method is not None and method.upper() == "HEAD"
        if media_type is None:
            media_type = guess_type(filename or path)[0] or "text/plain"
        self.media_type = media_type
        self.background = background
        self.init_headers(headers)
        if self.filename is not None:
            content_disposition = 'attachment; filename="{}"'.format(self.filename)
            self.headers.setdefault("content-disposition", content_disposition)
        self.stat_result = stat_result
        if stat_result is not None:
            self.set_stat_headers(stat_result)

    def set_stat_headers(self, stat_result: os.stat_result) -> None:
        content_length = str(stat_result.st_size)
        last_modified = formatdate(stat_result.st_mtime, usegmt=True)
        etag_base = str(stat_result.st_mtime) + "-" + str(stat_result.st_size)
        etag = hashlib.md5(etag_base.encode()).hexdigest()

        self.headers.setdefault("content-length", content_length)
        self.headers.setdefault("last-modified", last_modified)
        self.headers.setdefault("etag", etag)

    async def __call__(self, receive: Receive, send: Send) -> None:
        if self.stat_result is None:
            try:
                stat_result = await aio_stat(self.path)
                self.set_stat_headers(stat_result)
            except FileNotFoundError:
                raise RuntimeError(f"File at path {self.path} does not exist.")
            else:
                mode = stat_result.st_mode
                if not stat.S_ISREG(mode):
                    raise RuntimeError(f"File at path {self.path} is not a file.")
        await send(
            {
                "type": "http.response.start",
                "status": self.status_code,
                "headers": self.raw_headers,
            }
        )
        if self.send_header_only:
            await send({"type": "http.response.body"})
        else:
            async with aiofiles.open(self.path, mode="rb") as file:
                more_body = True
                while more_body:
                    chunk = await file.read(self.chunk_size)
                    more_body = len(chunk) == self.chunk_size
                    await send(
                        {
                            "type": "http.response.body",
                            "body": chunk,
                            "more_body": more_body,
                        }
                    )
        if self.background is not None:
            await self.background()
