from __future__ import annotations

import json
from dataclasses import dataclass

import pytest
from pytest_codspeed.plugin import BenchmarkFixture

from benchmarks._utils import ASGIRunner
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocket

TEXT = "x" * 1024
BYTES = b"x" * 1024
JSON_CONTENT = {"items": [{"id": index, "name": f"item-{index}"} for index in range(25)]}
JSON_TEXT = json.dumps(JSON_CONTENT, ensure_ascii=False, separators=(",", ":"))


class TextEchoApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive, send)
        await websocket.accept()
        await websocket.send_text(await websocket.receive_text())
        await websocket.close()


class BytesEchoApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive, send)
        await websocket.accept()
        await websocket.send_bytes(await websocket.receive_bytes())
        await websocket.close()


class JSONEchoApp:
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        websocket = WebSocket(scope, receive, send)
        await websocket.accept()
        await websocket.send_json(await websocket.receive_json())
        await websocket.close()


@dataclass(frozen=True)
class BenchmarkCase:
    id: str
    app: ASGIApp
    incoming: Message
    outgoing: Message


CASES = (
    BenchmarkCase(
        "text", TextEchoApp(), {"type": "websocket.receive", "text": TEXT}, {"type": "websocket.send", "text": TEXT}
    ),
    BenchmarkCase(
        "bytes",
        BytesEchoApp(),
        {"type": "websocket.receive", "bytes": BYTES},
        {"type": "websocket.send", "bytes": BYTES},
    ),
    BenchmarkCase(
        "json",
        JSONEchoApp(),
        {"type": "websocket.receive", "text": JSON_TEXT},
        {"type": "websocket.send", "text": JSON_TEXT},
    ),
)


class WebSocketReceive:
    def __init__(self, incoming: Message) -> None:
        self.messages: tuple[Message, ...] = ({"type": "websocket.connect"}, incoming)
        self.index = 0

    async def __call__(self) -> Message:
        if self.index >= len(self.messages):
            raise AssertionError("The benchmark app read beyond the WebSocket message")
        message = self.messages[self.index]
        self.index += 1
        return message


def websocket_scope() -> Scope:
    return {
        "type": "websocket",
        "asgi": {"version": "3.0", "spec_version": "2.5"},
        "scheme": "ws",
        "path": "/",
        "raw_path": b"/",
        "root_path": "",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 80),
        "subprotocols": [],
    }


def dispatch(runner: ASGIRunner, case: BenchmarkCase) -> list[Message]:
    return runner.run(case.app, websocket_scope(), WebSocketReceive(case.incoming))


@pytest.fixture(scope="module", autouse=True)
def warm_websockets(asgi_runner: ASGIRunner) -> None:
    for case in CASES:
        for _ in range(100):
            dispatch(asgi_runner, case)


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
@pytest.mark.benchmark(max_time=0.5, max_rounds=20)
def test_websocket_echo(asgi_runner: ASGIRunner, benchmark: BenchmarkFixture, case: BenchmarkCase) -> None:
    messages = benchmark(dispatch, asgi_runner, case)

    assert messages == [
        {"type": "websocket.accept", "subprotocol": None, "headers": []},
        case.outgoing,
        {"type": "websocket.close", "code": 1000, "reason": ""},
    ]
    benchmark.extra_info["mode"] = case.id
