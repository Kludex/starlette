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
        self.scope: Scope | None = None
        self.receive: Receive | None = None
        self.send: Send | None = None
        self.content_length: int | None = None
        self.total_size = 0
        self.response_started = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        previous_scope_limit = cast(int | _Missing, scope.get(MAX_BODY_SIZE_SCOPE_KEY, _MISSING))
        scope[MAX_BODY_SIZE_SCOPE_KEY] = self.max_body_size

        active_responder = cast(RequestBodyLimitResponder | None, scope.get(_BODY_LIMIT_RESPONDER_SCOPE_KEY))
        if active_responder is not None:
            active_responder.max_body_size = self.max_body_size
            if active_responder.total_size > active_responder.max_body_size:
                raise _RequestBodyTooLarge
            return await self.app(scope, receive, send)

        self.scope = scope
        self.receive = receive
        self.send = send
        content_length_header = Headers(scope=scope).get("content-length")
        if content_length_header is not None:
            try:
                self.content_length = int(content_length_header)
            except ValueError:
                pass
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

        assert self.receive is not None
        message = await self.receive()
        if message["type"] == "http.request":
            self.total_size += len(message.get("body", b""))
            if self.total_size > self.max_body_size:
                raise _RequestBodyTooLarge
        return message

    async def send_with_limit(self, message: Message) -> None:
        assert self.scope is not None
        assert self.receive is not None
        assert self.send is not None

        if message["type"] == "http.response.start":
            if self.content_length is not None and self.content_length > self.max_body_size:
                self.response_started = True
                response = PlainTextResponse("Content Too Large", status_code=413)
                await response(self.scope, self.receive, self.send)
                raise _RequestBodyLimitResponseSent
            self.response_started = True
        await self.send(message)
