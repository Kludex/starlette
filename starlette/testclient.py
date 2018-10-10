import asyncio
import http
import io
import json
import threading
import typing
import queue
from starlette.websockets import WebSocketDisconnect
from urllib.parse import unquote, urlparse, urljoin

import requests


class _HeaderDict(requests.packages.urllib3._collections.HTTPHeaderDict):
    def get_all(self, key, default):
        return self.getheaders(key)


class _MockOriginalResponse(object):
    """
    We have to jump through some hoops to present the response as if
    it was made using urllib3.
    """

    def __init__(self, headers):
        self.msg = _HeaderDict(headers)
        self.closed = False

    def isclosed(self):
        return self.closed


class _Upgrade(Exception):
    def __init__(self, session):
        self.session = session


def _get_reason_phrase(status_code):
    try:
        return http.HTTPStatus(status_code).phrase
    except ValueError:
        return ""


class _ASGIAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, app: typing.Callable, raise_server_exceptions=True) -> None:
        self.app = app
        self.raise_server_exceptions = raise_server_exceptions

    def send(self, request, *args, **kwargs):
        scheme, netloc, path, params, query, fragement = urlparse(request.url)
        if ":" in netloc:
            host, port = netloc.split(":", 1)
            port = int(port)
        else:
            host = netloc
            port = {"http": 80, "ws": 80, "https": 443, "wss": 443}[scheme]

        # Include the 'host' header.
        if "host" in request.headers:
            headers = []
        elif port == 80:
            headers = [[b"host", host.encode()]]
        else:
            headers = [[b"host", ("%s:%d" % (host, port)).encode()]]

        # Include other request headers.
        headers += [
            [key.lower().encode(), value.encode()]
            for key, value in request.headers.items()
        ]

        if scheme in {"ws", "wss"}:
            subprotocol = request.headers.get("sec-websocket-protocol", None)
            if subprotocol is None:
                subprotocols = []
            else:
                subprotocols = [value.strip() for value in subprotocol.split(",")]
            scope = {
                "type": "websocket",
                "path": unquote(path),
                "root_path": "",
                "scheme": scheme,
                "query_string": query.encode(),
                "headers": headers,
                "client": ["testclient", 50000],
                "server": [host, port],
                "subprotocols": subprotocols,
            }
            session = WebSocketTestSession(self.app, scope)
            raise _Upgrade(session)

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": request.method,
            "path": unquote(path),
            "root_path": "",
            "scheme": scheme,
            "query_string": query.encode(),
            "headers": headers,
            "client": ["testclient", 50000],
            "server": [host, port],
        }

        async def receive():
            body = request.body
            if isinstance(body, str):
                body_bytes = body.encode("utf-8")  # type: bytes
            elif body is None:
                body_bytes = b""
            else:
                body_bytes = body
            return {"type": "http.request", "body": body_bytes}

        async def send(message):
            nonlocal raw_kwargs, response_started, response_complete

            if message["type"] == "http.response.start":
                assert (
                    not response_started
                ), 'Received multiple "http.response.start" messages.'
                raw_kwargs["version"] = 11
                raw_kwargs["status"] = message["status"]
                raw_kwargs["reason"] = _get_reason_phrase(message["status"])
                raw_kwargs["headers"] = [
                    (key.decode(), value.decode()) for key, value in message["headers"]
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
                    not response_complete
                ), 'Received "http.response.body" after response completed.'
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                raw_kwargs["body"].write(body)
                if not more_body:
                    raw_kwargs["body"].seek(0)
                    response_complete = True

        response_started = False
        response_complete = False
        raw_kwargs = {"body": io.BytesIO()}

        loop = asyncio.get_event_loop()

        try:
            connection = self.app(scope)
            loop.run_until_complete(connection(receive, send))
        except BaseException as exc:
            if self.raise_server_exceptions:
                raise exc from None

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
        return self.build_response(request, raw)


class WebSocketTestSession:
    def __init__(self, app, scope):
        self.accepted_subprotocol = None
        self._loop = asyncio.new_event_loop()
        self._instance = app(scope)
        self._receive_queue = queue.Queue()
        self._send_queue = queue.Queue()
        self._thread = threading.Thread(target=self._run)
        self.send({"type": "websocket.connect"})
        self._thread.start()
        message = self.receive()
        self._raise_on_close(message)
        self.accepted_subprotocol = message.get("subprotocol", None)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close(1000)
        self._thread.join()
        while not self._send_queue.empty():
            message = self._send_queue.get()
            if isinstance(message, BaseException):
                raise message

    def _run(self):
        """
        The sub-thread in which the websocket session runs.
        """
        try:
            asgi = self._instance(self._asgi_receive, self._asgi_send)
            task = self._loop.create_task(asgi)
            self._loop.run_until_complete(task)
        except BaseException as exc:
            self._send_queue.put(exc)

    async def _asgi_receive(self):
        return self._receive_queue.get()

    async def _asgi_send(self, message):
        self._send_queue.put(message)

    def _raise_on_close(self, message):
        if message["type"] == "websocket.close":
            raise WebSocketDisconnect(message.get("code", 1000))

    def send(self, message):
        self._receive_queue.put(message)

    def send_text(self, data):
        self.send({"type": "websocket.receive", "text": data})

    def send_bytes(self, data):
        self.send({"type": "websocket.receive", "bytes": data})

    def send_json(self, data):
        encoded = json.dumps(data).encode("utf-8")
        self.send({"type": "websocket.receive", "bytes": encoded})

    def close(self, code=1000):
        self.send({"type": "websocket.disconnect", "code": code})

    def receive(self):
        message = self._send_queue.get()
        if isinstance(message, BaseException):
            raise message
        return message

    def receive_text(self):
        message = self.receive()
        self._raise_on_close(message)
        return message["text"]

    def receive_bytes(self):
        message = self.receive()
        self._raise_on_close(message)
        return message["bytes"]

    def receive_json(self):
        message = self.receive()
        self._raise_on_close(message)
        encoded = message["bytes"]
        return json.loads(encoded.decode("utf-8"))


class _TestClient(requests.Session):
    def __init__(
        self, app: typing.Callable, base_url: str, raise_server_exceptions=True
    ) -> None:
        super(_TestClient, self).__init__()
        adapter = _ASGIAdapter(app, raise_server_exceptions=raise_server_exceptions)
        self.mount("http://", adapter)
        self.mount("https://", adapter)
        self.mount("ws://", adapter)
        self.mount("wss://", adapter)
        self.headers.update({"user-agent": "testclient"})
        self.base_url = base_url

    def request(
        self,
        method: str,
        url: str,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=None,
        allow_redirects=True,
        proxies=None,
        hooks=None,
        stream=None,
        verify=None,
        cert=None,
        json=None,
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
        self, url: str, subprotocols=None, **kwargs
    ) -> WebSocketTestSession:
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


def TestClient(
    app: typing.Callable,
    base_url: str = "http://testserver",
    raise_server_exceptions=True,
) -> _TestClient:
    """
    We have to work around py.test discovery attempting to pick up
    the `TestClient` class, by declaring this as a function.
    """
    return _TestClient(app, base_url, raise_server_exceptions=raise_server_exceptions)
