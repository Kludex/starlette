import functools
import json
from base64 import b64decode, b64encode

import itsdangerous

from starlette.datastructures import MutableHeaders
from starlette.requests import Request
from starlette.types import ASGIApp, ASGIInstance, Message, Receive, Scope, Send


class SessionMiddleware:
    def __init__(
        self, app: ASGIApp, secret_key: str, session_cookie: str = "session"
    ) -> None:
        self.app = app
        self.signer = itsdangerous.Signer(secret_key)
        self.session_cookie = session_cookie

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] in ("http", "websocket"):
            request = Request(scope)
            if self.session_cookie in request.cookies:
                data = request.cookies[self.session_cookie].encode("utf-8")
                data = self.signer.unsign(data)
                scope["session"] = json.loads(b64decode(data))
            else:
                scope["session"] = {}
            return functools.partial(self.asgi, scope=scope)
        return self.app(scope)  # pragma: no cover

    async def asgi(self, receive: Receive, send: Send, scope: Scope) -> None:
        was_empty_session = not scope["session"]
        inner = self.app(scope)

        async def sender(message: Message) -> None:
            if message["type"] == "http.response.start":
                if scope["session"]:
                    # We have session data to persist.
                    data = b64encode(json.dumps(scope["session"]).encode("utf-8"))
                    data = self.signer.sign(data)
                    headers = MutableHeaders(scope=message)
                    header_value = "%s=%s" % (self.session_cookie, data.decode("utf-8"))
                    headers.append("Set-Cookie", header_value)
                elif not was_empty_session:
                    # The session has been cleared.
                    headers = MutableHeaders(scope=message)
                    header_value = "%s=%s" % (
                        self.session_cookie,
                        "null; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
                    )
                    headers.append("Set-Cookie", header_value)
            await send(message)

        await inner(receive, sender)
