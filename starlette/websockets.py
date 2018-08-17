from collections.abc import Mapping
from enum import Enum
from starlette.datastructures import URL, Headers, QueryParams
from urllib.parse import unquote
import enum
import json


class WebSocketState(enum.Enum):
    CONNECTING = 0
    CONNECTED = 1
    DISCONNECTED = 2


class WebSocketDisconnect(Exception):
    def __init__(self, code=1000):
        self.code = code


class WebSocketSession(Mapping):
    def __init__(self, scope, receive=None, send=None):
        assert scope["type"] == "websocket"
        self._scope = scope
        self._receive = receive
        self._send = send
        self.client_state = WebSocketState.CONNECTING
        self.application_state = WebSocketState.CONNECTING

    def __getitem__(self, key):
        return self._scope[key]

    def __iter__(self):
        return iter(self._scope)

    def __len__(self):
        return len(self._scope)

    @property
    def url(self) -> URL:
        if not hasattr(self, "_url"):
            scheme = self._scope["scheme"]
            host, port = self._scope["server"]
            path = self._scope.get("root_path", "") + self._scope["path"]
            query_string = self._scope["query_string"]

            if (scheme == "ws" and port != 80) or (scheme == "wss" and port != 443):
                url = "%s://%s:%s%s" % (scheme, host, port, path)
            else:
                url = "%s://%s%s" % (scheme, host, path)

            if query_string:
                url += "?" + unquote(query_string.decode())

            self._url = URL(url)
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

    async def receive(self):
        """
        Receive ASGI websocket messages, ensuring valid state transitions.
        """
        if self.client_state == WebSocketState.CONNECTING:
            message = await self._receive()
            message_type = message["type"]
            assert message_type == "websocket.connect"
            self.client_state = WebSocketState.CONNECTED
            return message
        elif self.client_state == WebSocketState.CONNECTED:
            message = await self._receive()
            message_type = message["type"]
            assert message_type in {"websocket.receive", "websocket.disconnect"}
            if message_type == "websocket.disconnect":
                self.client_state = WebSocketState.DISCONNECTED
            return message
        else:
            raise RuntimeError(
                'Cannot call "receive" once a disconnect message has been received.'
            )

    async def send(self, message):
        """
        Send ASGI websocket messages, ensuring valid state transitions.
        """
        if self.application_state == WebSocketState.CONNECTING:
            message_type = message["type"]
            assert message_type in {"websocket.accept", "websocket.close"}
            if message_type == "websocket.close":
                self.application_state = WebSocketState.DISCONNECTED
            else:
                self.application_state = WebSocketState.CONNECTED
            await self._send(message)
        elif self.application_state == WebSocketState.CONNECTED:
            message_type = message["type"]
            assert message_type in {"websocket.send", "websocket.close"}
            if message_type == "websocket.close":
                self.application_state = WebSocketState.DISCONNECTED
            await self._send(message)
        else:
            raise RuntimeError('Cannot call "send" once a close message has been sent.')

    async def accept(self, subprotocol=None):
        if self.client_state == WebSocketState.CONNECTING:
            # If we haven't yet seen the 'connect' message, then wait for it first.
            await self.receive()
        await self.send({"type": "websocket.accept", "subprotocol": subprotocol})

    def _raise_on_disconnect(self, message):
        if message["type"] == "websocket.disconnect":
            raise WebSocketDisconnect(message["code"])

    async def receive_text(self):
        assert self.application_state == WebSocketState.CONNECTED
        message = await self.receive()
        self._raise_on_disconnect(message)
        return message["text"]

    async def receive_bytes(self):
        assert self.application_state == WebSocketState.CONNECTED
        message = await self.receive()
        self._raise_on_disconnect(message)
        return message["bytes"]

    async def receive_json(self):
        assert self.application_state == WebSocketState.CONNECTED
        message = await self.receive()
        self._raise_on_disconnect(message)
        encoded = message["bytes"]
        return json.loads(encoded.decode("utf-8"))

    async def send_text(self, data):
        await self.send({"type": "websocket.send", "text": data})

    async def send_bytes(self, data):
        await self.send({"type": "websocket.send", "bytes": data})

    async def send_json(self, data):
        encoded = json.dumps(data).encode("utf-8")
        await self.send({"type": "websocket.send", "bytes": encoded})

    async def close(self, code=1000):
        await self.send({"type": "websocket.close", "code": code})
