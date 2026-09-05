from __future__ import annotations

from collections.abc import Awaitable, Callable

import anyio.lowlevel

from starlette.datastructures import MutableHeaders
from starlette.middleware._compression_headers import prepare_response
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class CompressionResponder:
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

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        initial_message: Message | None = None
        pending: list[Message] = []
        started = False
        rejected = False
        body_allowed = True
        compress = self.compress
        if compress is not None and "http.response.zerocopysend" in scope.get("extensions", {}):
            scope = {**scope, "extensions": dict(scope["extensions"])}
            # A later file send cannot be mixed into an already-compressed body.
            del scope["extensions"]["http.response.zerocopysend"]

        async def send_response(message: Message) -> None:
            nonlocal initial_message, started, rejected, body_allowed, compress
            message_type = message["type"]
            if rejected:
                return
            if message_type == "http.response.start":
                initial_message = {**message, "headers": list(message.get("headers", []))}
                return
            if message_type not in {"http.response.body", "http.response.pathsend", "http.response.zerocopysend"}:
                if initial_message is not None and not started:
                    pending.append(message)
                else:
                    await send(message)
                return
            assert initial_message is not None, "Response body received before response start"
            if not started:
                plan = prepare_response(
                    initial_message,
                    message,
                    scope,
                    self.encoding,
                    self.minimum_size,
                    self.exclude_content_types,
                    self.accepts,
                )
                started = True
                body_allowed = plan.body_allowed
                if plan.encoding is None:
                    rejected = True
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 406,
                            "headers": [
                                (b"content-type", b"text/plain; charset=utf-8"),
                                (b"content-length", b"14"),
                                (b"vary", b"Accept-Encoding"),
                            ],
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": b"" if scope.get("method") == "HEAD" else b"Not Acceptable",
                        }
                    )
                    cancel_scope.cancel()
                    await anyio.lowlevel.checkpoint()
                else:
                    if plan.encoding == "identity" or not body_allowed:
                        compress = None
                    if compress is not None:
                        body = await compress(message.get("body", b""), message.get("more_body", False))
                        headers = MutableHeaders(raw=initial_message["headers"])
                        headers["content-encoding"] = plan.encoding
                        if message.get("more_body", False):
                            del headers["content-length"]
                        else:
                            headers["content-length"] = str(len(body))
                        message = {**message, "body": body}
                    await send(initial_message)
                    for event in pending:
                        await send(event)
                    pending.clear()
            elif compress is not None and message_type == "http.response.body":
                message = {**message, "body": await compress(message.get("body", b""), message.get("more_body", False))}
            if not body_allowed:
                message = {"type": "http.response.body", "body": b"", "more_body": message.get("more_body", False)}
            await send(message)

        with anyio.CancelScope() as cancel_scope:
            await self.app(scope, receive, send_response)
