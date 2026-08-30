from __future__ import annotations

import asyncio

from starlette.types import ASGIApp, Message, Receive, Scope, Send


async def unreadable_receive() -> Message:
    raise AssertionError("The benchmark app must not receive a request body")


class ChunkedReceive:
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self.chunks = chunks
        self.index = 0

    async def __call__(self) -> Message:
        if self.index >= len(self.chunks):
            raise AssertionError("The benchmark app read beyond the request body")
        chunk = self.chunks[self.index]
        self.index += 1
        return {
            "type": "http.request",
            "body": chunk,
            "more_body": self.index < len(self.chunks),
        }


async def send_result(send: Send, status: int, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": []})
    await send({"type": "http.response.body", "body": body})


async def run_asgi(app: ASGIApp, scope: Scope, receive: Receive = unreadable_receive) -> list[Message]:
    messages: list[Message] = []

    async def send(message: Message) -> None:
        messages.append(message)

    await app(scope, receive, send)
    return messages


class ASGIRunner:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()

    def run(self, app: ASGIApp, scope: Scope, receive: Receive = unreadable_receive) -> list[Message]:
        return self.loop.run_until_complete(run_asgi(app, scope, receive))

    def close(self) -> None:
        self.loop.run_until_complete(self.loop.shutdown_asyncgens())
        self.loop.close()
