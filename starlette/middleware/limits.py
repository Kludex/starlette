from __future__ import annotations

from typing import ClassVar

import anyio

from starlette.exceptions import HTTPException
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

DEFAULT_MAX_REQUEST_SIZE = 2_621_440  # 2.5MB, same as Django (https://docs.djangoproject.com/en/1.11/ref/settings/#data-upload-max-memory-size)


class _TooLarge(HTTPException):
    msg: ClassVar[str]

    def __init__(self, limit_bytes: int | None) -> None:
        self.limit = limit_bytes
        super().__init__(
            status_code=413,
            detail=(
                self.msg + f" Max allowed size is {limit_bytes} bytes."
                if limit_bytes
                else self.msg
            ),
        )


class RequestTooLarge(_TooLarge):
    """The request body exceeded the configured limit."""

    msg = "Request body is too large."


class ChunkTooLarge(_TooLarge):
    """A chunk exceeded the configured limit."""

    msg = "Chunk size is too large."


class RequestSizeLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        max_request_size: int | None = DEFAULT_MAX_REQUEST_SIZE,
        max_chunk_size: int | None = None,
        include_limits_in_error_responses: bool = True,
    ) -> None:
        self.app = app
        self.max_request_size = max_request_size
        self.max_chunk_size = max_chunk_size
        self.include_limits_in_error_responses = include_limits_in_error_responses

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        total_size = 0

        async def rcv() -> Message:
            nonlocal total_size
            message = await receive()
            chunk_size = len(message.get("body", b""))
            if self.max_chunk_size is not None and chunk_size > self.max_chunk_size:
                raise ChunkTooLarge(
                    self.max_chunk_size
                    if self.include_limits_in_error_responses
                    else None
                )
            total_size += chunk_size
            if self.max_request_size is not None and total_size > self.max_request_size:
                raise RequestTooLarge(
                    self.max_request_size
                    if self.include_limits_in_error_responses
                    else None
                )
            return message

        await self.app(scope, rcv, send)


class _Timeout(HTTPException):
    msg: ClassVar[str]

    def __init__(self, limit_seconds: float | None) -> None:
        self.limit = limit_seconds
        super().__init__(
            status_code=408,
            detail=(
                self.msg + f" Max allowed time is {limit_seconds} seconds."
                if limit_seconds
                else self.msg
            ),
        )


class ReceiveTimeout(_Timeout):
    """The receive exceeded the configured limit."""

    msg = "Client was too slow sending data."


class SendTimeout(_Timeout):
    """The send exceeded the configured limit."""

    msg = "Client was too slow receiving data."


class RequestTimeoutMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        request_timeout_seconds: float | None = None,
        receive_timeout_seconds: float | None = None,
        send_timeout_seconds: float | None = None,
        include_limits_in_error_responses: bool = True,
    ) -> None:
        self.app = app
        self.timeout_seconds = request_timeout_seconds
        self.receive_timeout_seconds = receive_timeout_seconds
        self.send_timeout_seconds = send_timeout_seconds
        self.include_limits_in_error_responses = include_limits_in_error_responses

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        send_with_timeout: Send
        if self.send_timeout_seconds:

            async def snd(message: Message) -> None:
                try:
                    with anyio.fail_after(self.send_timeout_seconds):
                        await send(message)
                except TimeoutError:
                    raise SendTimeout(
                        self.send_timeout_seconds
                        if self.include_limits_in_error_responses
                        else None
                    )

            send_with_timeout = snd
        else:
            send_with_timeout = send

        receive_with_timeout: Receive
        if self.receive_timeout_seconds:

            async def rcv() -> Message:
                try:
                    with anyio.fail_after(self.receive_timeout_seconds):
                        return await receive()
                except TimeoutError:
                    raise ReceiveTimeout(
                        self.receive_timeout_seconds
                        if self.include_limits_in_error_responses
                        else None
                    )

            receive_with_timeout = rcv
        else:
            receive_with_timeout = receive

        if self.timeout_seconds is not None:
            try:
                with anyio.fail_after(self.timeout_seconds):
                    await self.app(scope, receive_with_timeout, send_with_timeout)
            except TimeoutError:
                if self.include_limits_in_error_responses:
                    await PlainTextResponse(
                        content=f"Request exceeded the timeout of {self.timeout_seconds} seconds.",  # noqa: E501
                        status_code=408,
                    )(scope, receive, send)
                else:
                    await PlainTextResponse(
                        content="Request exceeded the timeout.",
                        status_code=408,
                    )(scope, receive, send)
        else:
            await self.app(scope, receive_with_timeout, send_with_timeout)
