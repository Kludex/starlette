from __future__ import annotations

import anyio
import pytest

from starlette.types import Message, Receive, Scope, Send
from tests.types import TestClientFactory


@pytest.mark.parametrize(
    "messages, error",
    [
        ([{"type": "http.response.trailers"}], "without declaring trailers"),
        (
            [{"type": "http.response.start", "status": 200, "trailers": True}, {"type": "http.response.trailers"}],
            "before body completed",
        ),
        (
            [
                {"type": "http.response.start", "status": 200, "trailers": True},
                {"type": "http.response.body"},
                {"type": "http.response.body"},
            ],
            "after body completed",
        ),
        (
            [
                {"type": "http.response.start", "status": 200, "trailers": True},
                {"type": "http.response.body"},
                {"type": "http.response.trailers"},
                {"type": "http.response.trailers"},
            ],
            "after response completed",
        ),
        (
            [{"type": "http.response.start", "status": 200, "trailers": True}, {"type": "http.response.body"}],
            "without completing trailers",
        ),
        (
            [
                {"type": "http.response.start", "status": 200, "trailers": True},
                {"type": "http.response.body"},
                {"type": "http.response.trailers", "more_trailers": True},
            ],
            "without completing trailers",
        ),
    ],
)
def test_invalid_trailer_sequence(test_client_factory: TestClientFactory, messages: list[Message], error: str) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        for message in messages:
            await send(message)

    with pytest.raises(AssertionError, match=error):
        test_client_factory(app).get("/")


@pytest.mark.parametrize("empty", [True, False])
def test_capture_trailers(test_client_factory: TestClientFactory, empty: bool) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        assert "http.response.trailers" in scope["extensions"]
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        await anyio.lowlevel.checkpoint()
        headers = [] if empty else [(b"x-item", b"one"), (b"x-item", b"two")]
        await send({"type": "http.response.trailers", "headers": headers, "more_trailers": True})
        await send({"type": "http.response.trailers", "headers": []})

    response = test_client_factory(app).get("/", headers={"te": "trailers"})
    assert response.content == b"hello"
    assert response.extensions["http.response.trailers"] == (
        [] if empty else [(b"x-item", b"one"), (b"x-item", b"two")]
    )
    assert "x-item" not in response.headers


def test_incomplete_trailers_without_raising(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "trailers": True})
        await send({"type": "http.response.body", "body": b"hello"})
        await send({"type": "http.response.trailers", "headers": [(b"x-item", b"partial")], "more_trailers": True})
        raise ValueError("trailer production failed")

    response = test_client_factory(app, raise_server_exceptions=False).get("/")
    assert response.content == b"hello"
    assert response.extensions["http.response.trailers"] == [(b"x-item", b"partial")]
