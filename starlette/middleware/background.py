from __future__ import annotations

from typing import cast

from starlette.background import BackgroundTask
from starlette.types import ASGIApp, Receive, Scope, Send

_SCOPE_KEY = "starlette._background"


class BackgroundTaskMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"} or _SCOPE_KEY in scope:
            await self.app(scope, receive, send)
            return

        tasks: list[BackgroundTask] = []
        scope[_SCOPE_KEY] = tasks
        try:
            await self.app(scope, receive, send)
        finally:
            del scope[_SCOPE_KEY]

        for task in tasks:
            await task()


async def _run_background(scope: Scope, task: BackgroundTask | None) -> None:
    if task is None:
        return
    if _SCOPE_KEY in scope:
        cast("list[BackgroundTask]", scope[_SCOPE_KEY]).append(task)
    else:
        await task()
