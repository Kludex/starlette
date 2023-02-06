import os

import pytest

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route
from starlette.templating import Jinja2Templates


def test_templates(tmpdir, test_client_factory):
    path = os.path.join(tmpdir, "index.html")
    with open(path, "w") as file:
        file.write("<html>Hello, <a href='{{ url_for('homepage') }}'>world</a></html>")

    async def homepage(request):
        return templates.TemplateResponse("index.html", {"request": request})

    app = Starlette(
        debug=True,
        routes=[Route("/", endpoint=homepage)],
    )
    templates = Jinja2Templates(directory=str(tmpdir))

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "<html>Hello, <a href='http://testserver/'>world</a></html>"
    assert response.template.name == "index.html"
    assert set(response.context.keys()) == {"request"}


def test_template_response_requires_request(tmpdir):
    templates = Jinja2Templates(str(tmpdir))
    with pytest.raises(ValueError):
        templates.TemplateResponse("", {})


def test_calls_context_processors(tmp_path, test_client_factory):
    path = tmp_path / "index.html"
    path.write_text("<html>Hello {{ username }}</html>")

    async def homepage(request):
        return templates.TemplateResponse("index.html", {"request": request})

    def hello_world_processor(request):
        return {"username": "World"}

    app = Starlette(
        debug=True,
        routes=[Route("/", endpoint=homepage)],
    )
    templates = Jinja2Templates(
        directory=tmp_path,
        context_processors=[
            hello_world_processor,
        ],
    )

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "<html>Hello World</html>"
    assert response.template.name == "index.html"
    assert set(response.context.keys()) == {"request", "username"}


def test_template_with_middleware(tmpdir, test_client_factory):
    path = os.path.join(tmpdir, "index.html")
    with open(path, "w") as file:
        file.write("<html>Hello, <a href='{{ url_for('homepage') }}'>world</a></html>")

    async def homepage(request):
        return templates.TemplateResponse("index.html", {"request": request})

    class CustomMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            return await call_next(request)

    app = Starlette(
        debug=True,
        routes=[Route("/", endpoint=homepage)],
        middleware=[Middleware(CustomMiddleware)],
    )
    templates = Jinja2Templates(directory=str(tmpdir))

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "<html>Hello, <a href='http://testserver/'>world</a></html>"
    assert response.template.name == "index.html"
    assert set(response.context.keys()) == {"request"}
