from __future__ import annotations

from typing import cast

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY_SIZE_SCOPE_KEY = "starlette.max_body_size"
_BODY_LIMIT_RESPONDER_SCOPE_KEY = "starlette._body_limit_responder"


class _Missing:
    __slots__ = ()


_MISSING = _Missing()


class _RequestBodyTooLarge(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=413, detail="Content Too Large")


class _RequestBodyLimitResponseSent(Exception):
    pass


class RequestBodyLimitMiddleware:
    """Limit the total size of an HTTP request body."""

    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        responder = RequestBodyLimitResponder(self.app, self.max_body_size)
        await responder(scope, receive, send)


class RequestBodyLimitResponder:
    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        self.app = app
        self.max_body_size = max_body_size
        self._scope: Scope | None = None
        self._receive: Receive | None = None
        self._send: Send | None = None
        self.content_length: int | None = None
        self.total_size = 0
        self.response_started = False

    @property
    def scope(self) -> Scope:
        assert self._scope is not None
        return self._scope

    @property
    def receive(self) -> Receive:
        assert self._receive is not None
        return self._receive

    @property
    def send(self) -> Send:
        assert self._send is not None
        return self._send

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        previous_scope_limit = cast(int | _Missing, scope.get(MAX_BODY_SIZE_SCOPE_KEY, _MISSING))
        scope[MAX_BODY_SIZE_SCOPE_KEY] = self.max_body_size

        active_responder = cast(RequestBodyLimitResponder | None, scope.get(_BODY_LIMIT_RESPONDER_SCOPE_KEY))
        if active_responder is not None:
            active_responder.max_body_size = self.max_body_size
            if active_responder.total_size > active_responder.max_body_size:
                raise _RequestBodyTooLarge
            return await self.app(scope, receive, send)

        self._scope = scope
        self._receive = receive
        self._send = send
        self.content_length = _get_content_length(scope)
        scope[_BODY_LIMIT_RESPONDER_SCOPE_KEY] = self

        try:
            await self.app(scope, self.receive_with_limit, self.send_with_limit)
        except _RequestBodyTooLarge:
            if self.response_started:
                raise
            response = PlainTextResponse("Content Too Large", status_code=413)
            await response(scope, receive, send)
        except _RequestBodyLimitResponseSent:
            pass
        finally:
            scope.pop(_BODY_LIMIT_RESPONDER_SCOPE_KEY, None)
            if isinstance(previous_scope_limit, _Missing):
                scope.pop(MAX_BODY_SIZE_SCOPE_KEY, None)
            else:
                scope[MAX_BODY_SIZE_SCOPE_KEY] = previous_scope_limit

    async def receive_with_limit(self) -> Message:
        if self.content_length is not None and self.content_length > self.max_body_size:
            raise _RequestBodyTooLarge

        message = await self.receive()
        if message["type"] == "http.request":
            self.total_size += len(message.get("body", b""))
            if self.total_size > self.max_body_size:
                raise _RequestBodyTooLarge
        return message

    async def send_with_limit(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.response_started = True
            if self.content_length is not None and self.content_length > self.max_body_size:
                response = PlainTextResponse("Content Too Large", status_code=413)
                await response(self.scope, self.receive, self.send)
                raise _RequestBodyLimitResponseSent
        await self.send(message)


def _get_content_length(scope: Scope) -> int | None:
    content_length = Headers(scope=scope).get("content-length")
    if content_length is None:
        return None
    try:
        return int(content_length)
    except ValueError:
        return None
