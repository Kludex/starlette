import pytest

from starlette.testclient import TestClient


@pytest.fixture(
    params=[
        pytest.param(
            {"backend": "asyncio", "backend_options": {"use_uvloop": False}},
            id="asyncio",
        ),
        pytest.param({"backend": "trio", "backend_options": {}}, id="trio"),
    ],
    autouse=True,
)
def anyio_backend(request, monkeypatch):
    monkeypatch.setattr(TestClient, "async_backend", request.param)
    return request.param["backend"]


@pytest.fixture
def no_trio_support(request):
    if request.keywords.get("trio"):
        pytest.skip("Trio not supported (yet!)")
