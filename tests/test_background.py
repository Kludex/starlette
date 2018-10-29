import asyncio

from starlette.background import BackgroundTask
from starlette.responses import Response
from starlette.testclient import TestClient


def test_async_task():
    TASK_COMPLETE = False

    async def async_task():
        nonlocal TASK_COMPLETE
        TASK_COMPLETE = True

    task = BackgroundTask(async_task)

    def app(scope):
        async def asgi(receive, send):
            response = Response(
                "task initiated", media_type="text/plain", background=task
            )
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "task initiated"
    assert TASK_COMPLETE


def test_sync_task():
    TASK_COMPLETE = False

    def sync_task():
        nonlocal TASK_COMPLETE
        TASK_COMPLETE = True

    task = BackgroundTask(sync_task)

    def app(scope):
        async def asgi(receive, send):
            response = Response(
                "task initiated", media_type="text/plain", background=task
            )
            await response(receive, send)

        return asgi

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "task initiated"
    assert TASK_COMPLETE
