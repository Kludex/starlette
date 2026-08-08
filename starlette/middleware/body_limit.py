from __future__ import annotations

from typing import Any, cast

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

MAX_BODY_SIZE_SCOPE_KEY = "starlette.max_body_size"
_BODY_SIZE_STATE_SCOPE_KEY = "starlette._body_size_state"
_MISSING = object()


class _RequestBodyTooLarge(HTTPException):
    def __init__(self) -> None:
        super().__init__(status_code=413, detail="Content Too Large")


class _RequestBodyLimitResponseSent(Exception):
    pass


class _BodySizeState:
    def __init__(self, content_length: int | None) -> None:
        self.content_length = content_length
        self.total_size = 0
        self.max_body_size = 0
        self.response_started = False


class RequestBodyLimitMiddleware:
    """Limit the total size of an HTTP request body."""

    def __init__(self, app: ASGIApp, max_body_size: int | None = None) -> None:
        if max_body_size is not None and max_body_size < 0:
            raise ValueError("max_body_size must be greater than or equal to zero")
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.max_body_size is None or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        previous_scope_limit: Any = scope.get(MAX_BODY_SIZE_SCOPE_KEY, _MISSING)
        scope[MAX_BODY_SIZE_SCOPE_KEY] = self.max_body_size

        state = cast(_BodySizeState | None, scope.get(_BODY_SIZE_STATE_SCOPE_KEY))
        is_outermost = state is None
        if is_outermost:
            content_length: int | None = None
            content_length_header = Headers(scope=scope).get("content-length")
            if content_length_header is not None:
                try:
                    content_length = int(content_length_header)
                except ValueError:
                    pass
            state = _BodySizeState(content_length)
            scope[_BODY_SIZE_STATE_SCOPE_KEY] = state

        assert state is not None

        state.max_body_size = self.max_body_size

        try:
            if state.total_size > state.max_body_size:
                raise _RequestBodyTooLarge

            if is_outermost:
                await self._run_with_limit(scope, receive, send, state)
            else:
                await self.app(scope, receive, send)
        except _RequestBodyTooLarge:
            if not is_outermost or state.response_started:
                raise
            response = PlainTextResponse("Content Too Large", status_code=413)
            await response(scope, receive, send)
        except _RequestBodyLimitResponseSent:
            if not is_outermost:
                raise
        finally:
            if is_outermost:
                scope.pop(_BODY_SIZE_STATE_SCOPE_KEY, None)
                if previous_scope_limit is _MISSING:
                    scope.pop(MAX_BODY_SIZE_SCOPE_KEY, None)
                else:
                    scope[MAX_BODY_SIZE_SCOPE_KEY] = previous_scope_limit

    async def _run_with_limit(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        state: _BodySizeState,
    ) -> None:
        async def limited_receive() -> Message:
            if state.content_length is not None and state.content_length > state.max_body_size:
                raise _RequestBodyTooLarge

            message = await receive()
            if message["type"] == "http.request":
                state.total_size += len(message.get("body", b""))
                if state.total_size > state.max_body_size:
                    raise _RequestBodyTooLarge
            return message

        async def tracked_send(message: Message) -> None:
            if message["type"] == "http.response.start":
                if state.content_length is not None and state.content_length > state.max_body_size:
                    state.response_started = True
                    response = PlainTextResponse("Content Too Large", status_code=413)
                    await response(scope, receive, send)
                    raise _RequestBodyLimitResponseSent
                state.response_started = True
            await send(message)

        await self.app(scope, limited_receive, tracked_send)
