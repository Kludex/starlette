from __future__ import annotations

from collections.abc import Awaitable, Callable

import anyio
import anyio.lowlevel

from starlette.datastructures import MutableHeaders
from starlette.middleware._compression_headers import CompressionPlan, compressible, prepare_response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

BODY_EVENTS = frozenset({"http.response.body", "http.response.pathsend", "http.response.zerocopysend"})
NOT_ACCEPTABLE_HEADERS = [
    (b"content-type", b"text/plain; charset=utf-8"),
    (b"content-length", b"14"),
    (b"vary", b"Accept-Encoding"),
]


class CompressionResponder:
    cancel_scope: anyio.CancelScope

    def __init__(
        self,
        app: ASGIApp,
        minimum_size: int,
        exclude_content_types: tuple[str, ...],
        *,
        encoding: str | None = "identity",
        compress: Callable[[bytes, bool], Awaitable[bytes]] | None = None,
        accepts: Callable[[str], bool] | None = None,
    ) -> None:
        self.app = app
        self.minimum_size = minimum_size
        self.exclude_content_types = exclude_content_types
        self.encoding = encoding
        self.compress = compress
        self.accepts = accepts
        self.initial_message: Message | None = None
        self.pending: list[Message] = []
        self.started = False
        self.rejected = False
        self.body_allowed = True
        self.eligible = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.scope = scope
        self.send = send
        if self.compress is not None and "http.response.zerocopysend" in scope.get("extensions", {}):
            scope = {**scope, "extensions": dict(scope["extensions"])}
            # A later file send cannot be mixed into an already-compressed body.
            del scope["extensions"]["http.response.zerocopysend"]
        if self.accepts is None:
            await self.app(scope, receive, self.send_response)
            return
        with anyio.CancelScope() as self.cancel_scope:
            await self.app(scope, receive, self.send_response)

    async def send_response(self, message: Message) -> None:
        if self.rejected:
            if message.get("more_body", False):
                # Stop a streaming response whose body can no longer be sent.
                self.cancel_scope.cancel()
                await anyio.lowlevel.checkpoint()
            return
        message_type = message["type"]
        if message_type == "http.response.start":
            self.initial_message = {**message, "headers": list(message.get("headers", []))}
            self.eligible = compressible(self.initial_message, self.exclude_content_types)
            if not self.eligible:
                # Nothing about the body can change the outcome, so do not hold back the response start.
                await self.start(self.initial_message, self.prepare(self.initial_message, None))
            return
        if message_type not in BODY_EVENTS:
            if self.initial_message is not None and not self.started:
                self.pending.append(message)
            else:
                await self.send(message)
            return
        if self.initial_message is None:
            raise RuntimeError("Response body received before response start")
        if not self.started:
            plan = self.prepare(self.initial_message, message)
            if self.compress is not None and plan.encoding not in (None, "identity") and plan.body_allowed:
                more_body = message.get("more_body", False)
                body = await self.compress(message.get("body", b""), more_body)
                headers = MutableHeaders(raw=self.initial_message["headers"])
                if more_body or self.initial_message.get("trailers", False):
                    del headers["content-length"]
                else:
                    headers["content-length"] = str(len(body))
                message = {**message, "body": body}
            await self.start(self.initial_message, plan)
            if self.rejected:
                await self.send_response(message)
                return
        elif self.compress is not None and message_type == "http.response.body":
            body = await self.compress(message.get("body", b""), message.get("more_body", False))
            message = {**message, "body": body}
        if not self.body_allowed:
            message = {"type": "http.response.body", "body": b"", "more_body": message.get("more_body", False)}
        await self.send(message)

    def prepare(self, initial_message: Message, message: Message | None) -> CompressionPlan:
        return prepare_response(
            initial_message, message, self.scope, self.eligible, self.encoding, self.minimum_size, self.accepts
        )

    async def start(self, initial_message: Message, plan: CompressionPlan) -> None:
        self.started = True
        self.body_allowed = plan.body_allowed
        if plan.encoding is None:
            self.rejected = True
            await self.send({"type": "http.response.start", "status": 406, "headers": list(NOT_ACCEPTABLE_HEADERS)})
            body = b"" if self.scope.get("method") == "HEAD" else b"Not Acceptable"
            await self.send({"type": "http.response.body", "body": body})
            return
        if plan.encoding == "identity" or not self.body_allowed:
            self.compress = None
        await self.send(initial_message)
        for event in self.pending:
            await self.send(event)
        self.pending.clear()
