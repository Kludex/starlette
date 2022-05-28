import contextlib
import http
import inspect
import io
import json
import math
import queue
import sys
import types
import typing
from concurrent.futures import Future
from urllib.parse import unquote, urljoin, urlsplit

import anyio.abc
import requests
from anyio.streams.stapled import StapledObjectStream

from starlette._utils import is_async_callable
from starlette.types import Message, Receive, Scope, Send
from starlette.websockets import WebSocketDisconnect

if sys.version_info >= (3, 8):  # pragma: no cover
    from typing import TypedDict
else:  # pragma: no cover
    from typing_extensions import TypedDict


_PortalFactoryType = typing.Callable[
    [], typing.ContextManager[anyio.abc.BlockingPortal]
]


# Annotations for `Session.request()`
Cookies = typing.Union[
    typing.MutableMapping[str, str], requests.cookies.RequestsCookieJar
]
Params = typing.Union[bytes, typing.MutableMapping[str, str]]
DataType = typing.Union[bytes, typing.MutableMapping[str, str], typing.IO]
TimeOut = typing.Union[float, typing.Tuple[float, float]]
FileType = typing.MutableMapping[str, typing.IO]
AuthType = typing.Union[
    typing.Tuple[str, str],
    requests.auth.AuthBase,
    typing.Callable[[requests.PreparedRequest], requests.PreparedRequest],
]


ASGIInstance = typing.Callable[[Receive, Send], typing.Awaitable[None]]
ASGI2App = typing.Callable[[Scope], ASGIInstance]
ASGI3App = typing.Callable[[Scope, Receive, Send], typing.Awaitable[None]]


class _HeaderDict(requests.packages.urllib3._collections.HTTPHeaderDict):
    def get_all(self, key: str, default: str) -> str:
        return self.getheaders(key)


class _MockOriginalResponse:
    """
    We have to jump through some hoops to present the response as if
    it was made using urllib3.
    """

    def __init__(self, headers: typing.List[typing.Tuple[bytes, bytes]]) -> None:
        self.msg = _HeaderDict(headers)
        self.closed = False

    def isclosed(self) -> bool:
        return self.closed


class _Upgrade(Exception):
    def __init__(self, session: "WebSocketTestSession") -> None:
        self.session = session


def _get_reason_phrase(status_code: int) -> str:
    try:
        return http.HTTPStatus(status_code).phrase
    except ValueError:
        return ""


def _is_asgi3(app: typing.Union[ASGI2App, ASGI3App]) -> bool:
    if inspect.isclass(app):
        return hasattr(app, "__await__")
    return is_async_callable(app)


class _WrapASGI2:
    """
    Provide an ASGI3 interface onto an ASGI2 app.
    """

    def __init__(self, app: ASGI2App) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        instance = self.app(scope)
        await instance(receive, send)


class _AsyncBackend(TypedDict):
    backend: str
    backend_options: typing.Dict[str, typing.Any]


class _ASGIAdapter(requests.adapters.HTTPAdapter):
    def __init__(
        self,
        app: ASGI3App,
        portal_factory: _PortalFactoryType,
        raise_server_exceptions: bool = True,
        root_path: str = "",
    ) -> None:
        self.app = app
        self.raise_server_exceptions = raise_server_exceptions
        self.root_path = root_path
        self.portal_factory = portal_factory

    def send(
        self, request: requests.PreparedRequest, *args: typing.Any, **kwargs: typing.Any
    ) -> requests.Response:
        scheme, netloc, path, query, fragment = (
            str(item) for item in urlsplit(request.url)
        )

        default_port = {"http": 80, "ws": 80, "https": 443, "wss": 443}[scheme]

        if ":" in netloc:
            host, port_string = netloc.split(":", 1)
            port = int(port_string)
        else:
            host = netloc
            port = default_port

        # Include the 'host' header.
        if "host" in request.headers:
            headers: typing.List[typing.Tuple[bytes, bytes]] = []
        elif port == default_port:
            headers = [(b"host", host.encode())]
        else:
            headers = [(b"host", (f"{host}:{port}").encode())]

        # Include other request headers.
        headers += [
            (key.lower().encode(), value.encode())
            for key, value in request.headers.items()
        ]

        scope: typing.Dict[str, typing.Any]

        if scheme in {"ws", "wss"}:
            subprotocol = request.headers.get("sec-websocket-protocol", None)
            if subprotocol is None:
                subprotocols: typing.Sequence[str] = []
            else:
                subprotocols = [value.strip() for value in subprotocol.split(",")]
            scope = {
                "type": "websocket",
                "path": unquote(path),
                "raw_path": path.encode(),
                "root_path": self.root_path,
                "scheme": scheme,
                "query_string": query.encode(),
                "headers": headers,
                "client": ["testclient", 50000],
                "server": [host, port],
                "subprotocols": subprotocols,
            }
            session = WebSocketTestSession(self.app, scope, self.portal_factory)
            raise _Upgrade(session)

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": request.method,
            "path": unquote(path),
            "raw_path": path.encode(),
            "root_path": self.root_path,
            "scheme": scheme,
            "query_string": query.encode(),
            "headers": headers,
            "client": ["testclient", 50000],
            "server": [host, port],
            "extensions": {"http.response.template": {}},
        }

        request_complete = False
        response_started = False
        response_complete: anyio.Event
        raw_kwargs: typing.Dict[str, typing.Any] = {"body": io.BytesIO()}
        template = None
        context = None

        async def receive() -> Message:
            nonlocal request_complete

            if request_complete:
                if not response_complete.is_set():
                    await response_complete.wait()
                return {"type": "http.disconnect"}

            body = request.body
            if isinstance(body, str):
                body_bytes: bytes = body.encode("utf-8")
            elif body is None:
                body_bytes = b""
            elif isinstance(body, types.GeneratorType):
                try:
                    chunk = body.send(None)
                    if isinstance(chunk, str):
                        chunk = chunk.encode("utf-8")
                    return {"type": "http.request", "body": chunk, "more_body": True}
                except StopIteration:
                    request_complete = True
                    return {"type": "http.request", "body": b""}
            else:
                body_bytes = body

            request_complete = True
            return {"type": "http.request", "body": body_bytes}

        async def send(message: Message) -> None:
            nonlocal raw_kwargs, response_started, template, context

            if message["type"] == "http.response.start":
                assert (
                    not response_started
                ), 'Received multiple "http.response.start" messages.'
                raw_kwargs["version"] = 11
                raw_kwargs["status"] = message["status"]
                raw_kwargs["reason"] = _get_reason_phrase(message["status"])
                raw_kwargs["headers"] = [
                    (key.decode(), value.decode())
                    for key, value in message.get("headers", [])
                ]
                raw_kwargs["preload_content"] = False
                raw_kwargs["original_response"] = _MockOriginalResponse(
                    raw_kwargs["headers"]
                )
                response_started = True
            elif message["type"] == "http.response.body":
                assert (
                    response_started
                ), 'Received "http.response.body" without "http.response.start".'
                assert (
                    not response_complete.is_set()
                ), 'Received "http.response.body" after response completed.'
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                if request.method != "HEAD":
                    raw_kwargs["body"].write(body)
                if not more_body:
                    raw_kwargs["body"].seek(0)
                    response_complete.set()
            elif message["type"] == "http.response.template":
                template = message["template"]
                context = message["context"]

        try:
            with self.portal_factory() as portal:
                response_complete = portal.call(anyio.Event)
                portal.call(self.app, scope, receive, send)
        except BaseException as exc:
            if self.raise_server_exceptions:
                raise exc

        if self.raise_server_exceptions:
            assert response_started, "TestClient did not receive any response."
        elif not response_started:
            raw_kwargs = {
                "version": 11,
                "status": 500,
                "reason": "Internal Server Error",
                "headers": [],
                "preload_content": False,
                "original_response": _MockOriginalResponse([]),
                "body": io.BytesIO(),
            }

        raw = requests.packages.urllib3.HTTPResponse(**raw_kwargs)
        response = self.build_response(request, raw)
        if template is not None:
            response.template = template
            response.context = context
        return response


class WebSocketTestSession:
    def __init__(
        self,
        app: ASGI3App,
        scope: Scope,
        portal_factory: _PortalFactoryType,
    ) -> None:
        self.app = app
        self.scope = scope
        self.accepted_subprotocol = None
        self.extra_headers = None
        self.portal_factory = portal_factory
        self._receive_queue: "queue.Queue[typing.Any]" = queue.Queue()
        self._send_queue: "queue.Queue[typing.Any]" = queue.Queue()

    def __enter__(self) -> "WebSocketTestSession":
        self.exit_stack = contextlib.ExitStack()
        self.portal = self.exit_stack.enter_context(self.portal_factory())

        try:
            _: "Future[None]" = self.portal.start_task_soon(self._run)
            self.send({"type": "websocket.connect"})
            message = self.receive()
            self._raise_on_close(message)
        except Exception:
            self.exit_stack.close()
            raise
        self.accepted_subprotocol = message.get("subprotocol", None)
        self.extra_headers = message.get("headers", None)
        return self

    def __exit__(self, *args: typing.Any) -> None:
        try:
            self.close(1000)
        finally:
            self.exit_stack.close()
        while not self._send_queue.empty():
            message = self._send_queue.get()
            if isinstance(message, BaseException):
                raise message

    async def _run(self) -> None:
        """
        The sub-thread in which the websocket session runs.
        """
        scope = self.scope
        receive = self._asgi_receive
        send = self._asgi_send
        try:
            await self.app(scope, receive, send)
        except BaseException as exc:
            self._send_queue.put(exc)
            raise

    async def _asgi_receive(self) -> Message:
        while self._receive_queue.empty():
            await anyio.sleep(0)
        return self._receive_queue.get()

    async def _asgi_send(self, message: Message) -> None:
        self._send_queue.put(message)

    def _raise_on_close(self, message: Message) -> None:
        if message["type"] == "websocket.close":
            raise WebSocketDisconnect(
                message.get("code", 1000), message.get("reason", "")
            )

    def send(self, message: Message) -> None:
        self._receive_queue.put(message)

    def send_text(self, data: str) -> None:
        self.send({"type": "websocket.receive", "text": data})

    def send_bytes(self, data: bytes) -> None:
        self.send({"type": "websocket.receive", "bytes": data})

    def send_json(self, data: typing.Any, mode: str = "text") -> None:
        assert mode in ["text", "binary"]
        text = json.dumps(data)
        if mode == "text":
            self.send({"type": "websocket.receive", "text": text})
        else:
            self.send({"type": "websocket.receive", "bytes": text.encode("utf-8")})

    def close(self, code: int = 1000) -> None:
        self.send({"type": "websocket.disconnect", "code": code})

    def receive(self) -> Message:
        message = self._send_queue.get()
        if isinstance(message, BaseException):
            raise message
        return message

    def receive_text(self) -> str:
        message = self.receive()
        self._raise_on_close(message)
        return message["text"]

    def receive_bytes(self) -> bytes:
        message = self.receive()
        self._raise_on_close(message)
        return message["bytes"]

    def receive_json(self, mode: str = "text") -> typing.Any:
        assert mode in ["text", "binary"]
        message = self.receive()
        self._raise_on_close(message)
        if mode == "text":
            text = message["text"]
        else:
            text = message["bytes"].decode("utf-8")
        return json.loads(text)


class TestClient(requests.Session):
    __test__ = False  # For pytest to not discover this up.
    task: "Future[None]"
    portal: typing.Optional[anyio.abc.BlockingPortal] = None

    def __init__(
        self,
        app: typing.Union[ASGI2App, ASGI3App],
        base_url: str = "http://testserver",
        raise_server_exceptions: bool = True,
        root_path: str = "",
        backend: str = "asyncio",
        backend_options: typing.Optional[typing.Dict[str, typing.Any]] = None,
    ) -> None:
        super().__init__()
        self.async_backend = _AsyncBackend(
            backend=backend, backend_options=backend_options or {}
        )
        if _is_asgi3(app):
            app = typing.cast(ASGI3App, app)
            asgi_app = app
        else:
            app = typing.cast(ASGI2App, app)
            asgi_app = _WrapASGI2(app)  #  type: ignore
        adapter = _ASGIAdapter(
            asgi_app,
            portal_factory=self._portal_factory,
            raise_server_exceptions=raise_server_exceptions,
            root_path=root_path,
        )
        self.mount("http://", adapter)
        self.mount("https://", adapter)
        self.mount("ws://", adapter)
        self.mount("wss://", adapter)
        self.headers.update({"user-agent": "testclient"})
        self.app = asgi_app
        self.base_url = base_url

    @contextlib.contextmanager
    def _portal_factory(
        self,
    ) -> typing.Generator[anyio.abc.BlockingPortal, None, None]:
        if self.portal is not None:
            yield self.portal
        else:
            with anyio.start_blocking_portal(**self.async_backend) as portal:
                yield portal

    def request(  # type: ignore
        self,
        method: str,
        url: str,
        params: Params = None,
        data: DataType = None,
        headers: typing.MutableMapping[str, str] = None,
        cookies: Cookies = None,
        files: FileType = None,
        auth: AuthType = None,
        timeout: TimeOut = None,
        allow_redirects: bool = None,
        proxies: typing.MutableMapping[str, str] = None,
        hooks: typing.Any = None,
        stream: bool = None,
        verify: typing.Union[bool, str] = None,
        cert: typing.Union[str, typing.Tuple[str, str]] = None,
        json: typing.Any = None,
    ) -> requests.Response:
        url = urljoin(self.base_url, url)
        return super().request(
            method,
            url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            files=files,
            auth=auth,
            timeout=timeout,
            allow_redirects=allow_redirects,
            proxies=proxies,
            hooks=hooks,
            stream=stream,
            verify=verify,
            cert=cert,
            json=json,
        )

    def websocket_connect(
        self, url: str, subprotocols: typing.Sequence[str] = None, **kwargs: typing.Any
    ) -> typing.Any:
        url = urljoin("ws://testserver", url)
        headers = kwargs.get("headers", {})
        headers.setdefault("connection", "upgrade")
        headers.setdefault("sec-websocket-key", "testserver==")
        headers.setdefault("sec-websocket-version", "13")
        if subprotocols is not None:
            headers.setdefault("sec-websocket-protocol", ", ".join(subprotocols))
        kwargs["headers"] = headers
        try:
            super().request("GET", url, **kwargs)
        except _Upgrade as exc:
            session = exc.session
        else:
            raise RuntimeError("Expected WebSocket upgrade")  # pragma: no cover

        return session

    def __enter__(self) -> "TestClient":
        with contextlib.ExitStack() as stack:
            self.portal = portal = stack.enter_context(
                anyio.start_blocking_portal(**self.async_backend)
            )

            @stack.callback
            def reset_portal() -> None:
                self.portal = None

            self.stream_send = StapledObjectStream(
                *anyio.create_memory_object_stream(math.inf)
            )
            self.stream_receive = StapledObjectStream(
                *anyio.create_memory_object_stream(math.inf)
            )
            self.task = portal.start_task_soon(self.lifespan)
            portal.call(self.wait_startup)

            @stack.callback
            def wait_shutdown() -> None:
                portal.call(self.wait_shutdown)

            self.exit_stack = stack.pop_all()

        return self

    def __exit__(self, *args: typing.Any) -> None:
        self.exit_stack.close()

    async def lifespan(self) -> None:
        scope = {"type": "lifespan"}
        try:
            await self.app(scope, self.stream_receive.receive, self.stream_send.send)
        finally:
            await self.stream_send.send(None)

    async def wait_startup(self) -> None:
        await self.stream_receive.send({"type": "lifespan.startup"})

        async def receive() -> typing.Any:
            message = await self.stream_send.receive()
            if message is None:
                self.task.result()
            return message

        message = await receive()
        assert message["type"] in (
            "lifespan.startup.complete",
            "lifespan.startup.failed",
        )
        if message["type"] == "lifespan.startup.failed":
            await receive()

    async def wait_shutdown(self) -> None:
        async def receive() -> typing.Any:
            message = await self.stream_send.receive()
            if message is None:
                self.task.result()
            return message

        async with self.stream_send:
            await self.stream_receive.send({"type": "lifespan.shutdown"})
            message = await receive()
            assert message["type"] in (
                "lifespan.shutdown.complete",
                "lifespan.shutdown.failed",
            )
            if message["type"] == "lifespan.shutdown.failed":
                await receive()
