import http.cookies
import json
import typing
from collections.abc import Mapping
from urllib.parse import unquote

from starlette.datastructures import URL, Headers, QueryParams
from starlette.formparsers import FormParser, MultiPartParser
from starlette.types import Message, Receive, Scope

try:
    from multipart.multipart import parse_options_header
except ImportError:  # pragma: nocover
    parse_options_header = None  # type: ignore


class ClientDisconnect(Exception):
    pass


async def empty_receive() -> Message:
    raise RuntimeError("Receive channel has not been made available")


class Request(Mapping):
    def __init__(self, scope: Scope, receive: Receive = None) -> None:
        assert scope["type"] == "http"
        self._scope = scope
        self._receive = empty_receive if receive is None else receive
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
            self._headers = Headers(scope=self._scope)
        return self._headers

    @property
    def query_params(self) -> QueryParams:
        if not hasattr(self, "_query_params"):
            self._query_params = QueryParams(scope=self._scope)
        return self._query_params

    @property
    def path_params(self) -> dict:
        return self._scope.get("path_params", {})

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

    @property
    def receive(self) -> Receive:
        return self._receive

    def url_for(self, name: str, **path_params: typing.Any) -> URL:
        router = self._scope["router"]
        url = router.url_path_for(name, **path_params)
        return url.replace(secure=self.url.is_secure, netloc=self.url.netloc)

    async def stream(self) -> typing.AsyncGenerator[bytes, None]:
        if hasattr(self, "_body"):
            yield self._body
            return

        if self._stream_consumed:
            raise RuntimeError("Stream consumed")

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

    async def form(self) -> dict:
        if not hasattr(self, "_form"):
            assert (
                parse_options_header is not None
            ), "The `python-multipart` library must be installed to use form parsing."
            content_type_header = self.headers.get("Content-Type")
            content_type, options = parse_options_header(content_type_header)
            if content_type == b"multipart/form-data":
                multipart_parser = MultiPartParser(self.headers, self.stream())
                self._form = await multipart_parser.parse()
            elif content_type == b"application/x-www-form-urlencoded":
                from_parser = FormParser(self.headers, self.stream())
                self._form = await from_parser.parse()
            else:
                self._form = {}
        return self._form

    async def close(self) -> None:
        if hasattr(self, "_form"):
            for item in self._form.values():
                if hasattr(item, "close"):
                    await item.close()  # type: ignore
