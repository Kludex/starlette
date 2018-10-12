import typing
import json
from collections.abc import Mapping
from urllib.parse import unquote
import http.cookies
from starlette.datastructures import URL, Headers, QueryParams
from starlette.formparsers import FormParser, MultiPartParser
from starlette.types import Scope, Receive

try:
    from multipart.multipart import parse_options_header
except ImportError:  # pragma: nocover
    parse_options_header = None  # type: ignore


class ClientDisconnect(Exception):
    pass


class Request(Mapping):
    def __init__(self, scope: Scope, receive: Receive = None) -> None:
        assert scope["type"] == "http"
        self._scope = scope
        self._receive = receive
        self._stream_consumed = False

    def __getitem__(self, key: str) -> str:
        return self._scope[key]

    def __iter__(self) -> typing.Iterator[str]:
        return iter(self._scope)

    def __len__(self) -> int:
        return len(self._scope)

    @property
    def method(self) -> str:
        return self._scope["method"]

    @property
    def url(self) -> URL:
        if not hasattr(self, "_url"):
            self._url = URL(scope=self._scope)
        return self._url

    @property
    def headers(self) -> Headers:
        if not hasattr(self, "_headers"):
            self._headers = Headers(self._scope["headers"])
        return self._headers

    @property
    def query_params(self) -> QueryParams:
        if not hasattr(self, "_query_params"):
            query_string = self._scope["query_string"].decode()
            self._query_params = QueryParams(query_string)
        return self._query_params

    @property
    def cookies(self) -> typing.Dict[str, str]:
        if not hasattr(self, "_cookies"):
            cookies = {}
            cookie_header = self.headers.get("cookie")
            if cookie_header:
                cookie = http.cookies.SimpleCookie()
                cookie.load(cookie_header)
                for key, morsel in cookie.items():
                    cookies[key] = morsel.value
            self._cookies = cookies
        return self._cookies

    async def stream(self) -> typing.AsyncGenerator[bytes, None]:
        if hasattr(self, "_body"):
            yield self._body
            return

        if self._stream_consumed:
            raise RuntimeError("Stream consumed")

        if self._receive is None:
            raise RuntimeError("Receive channel has not been made available")

        self._stream_consumed = True
        while True:
            message = await self._receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                if body:
                    yield body
                if not message.get("more_body", False):
                    break
            elif message["type"] == "http.disconnect":
                raise ClientDisconnect()
        yield b""

    async def body(self) -> bytes:
        if not hasattr(self, "_body"):
            body = b""
            async for chunk in self.stream():
                body += chunk
            self._body = body
        return self._body

    async def json(self) -> typing.Any:
        if not hasattr(self, "_json"):
            body = await self.body()
            self._json = json.loads(body)
        return self._json

    async def form(self):
        if not hasattr(self, "_form"):
            assert (
                parse_options_header is not None
            ), "The `python-multipart` library must be installed to use form parsing."
            content_type_header = self.headers.get("Content-Type")
            content_type, options = parse_options_header(content_type_header)
            if content_type == b"multipart/form-data":
                parser = MultiPartParser(self.headers, self.stream)
                self._form = await parser.parse()
            elif content_type == b"application/x-www-form-urlencoded":
                parser = FormParser(self.headers, self.stream)
                self._form = await parser.parse()
            else:
                self._form = {}
        return self._form

    async def close(self):
        if hasattr(self, "_form"):
            for item in self._form.values():
                if hasattr(item, "close"):
                    await item.close()
