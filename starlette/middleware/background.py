from typing import cast

from starlette.background import BackgroundTask
from starlette.types import ASGIApp, Receive, Scope, Send

# consider this a private implementation detail subject to change
# do not rely on this key
_SCOPE_KEY = "starlette._background"


_BackgroundTaskList = list[BackgroundTask]


def is_background_task_middleware_installed(scope: Scope) -> bool:
    return _SCOPE_KEY in scope


def add_tasks(scope: Scope, task: BackgroundTask, /) -> None:
    if _SCOPE_KEY not in scope:  # pragma: no cover
        raise RuntimeError("`add_tasks` can only be used if `BackgroundTaskMIddleware is installed")
    cast(_BackgroundTaskList, scope[_SCOPE_KEY]).append(task)


class BackgroundTaskMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        tasks: _BackgroundTaskList
        scope[_SCOPE_KEY] = tasks = []
        try:
            await self._app(scope, receive, send)
        finally:
            for task in tasks:
                await task()
