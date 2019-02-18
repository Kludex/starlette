import os
import pytest

from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.templating import Jinja2Templates
from starlette.testclient import TestClient


def test_templates(tmpdir):
    path = os.path.join(tmpdir, "index.html")
    with open(path, "w") as file:
        file.write("<html>Hello, <a href='{{ url_for('homepage') }}'>world</a></html>")

    app = Starlette(debug=True)
    templates = Jinja2Templates(directory=str(tmpdir))

    @app.route("/")
    async def homepage(request):
        return templates.TemplateResponse("index.html", {"request": request})

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "<html>Hello, <a href='http://testserver/'>world</a></html>"
    assert response.template.name == "index.html"
    assert set(response.context.keys()) == {"request"}


def test_templates_legacy(tmpdir):
    path = os.path.join(tmpdir, "index.html")
    with open(path, "w") as file:
        file.write("<html>Hello, <a href='{{ url_for('homepage') }}'>world</a></html>")

    app = Starlette(debug=True, template_directory=str(tmpdir))

    @app.route("/")
    async def homepage(request):
        template = app.get_template("index.html")
        content = template.render(request=request)
        return HTMLResponse(content)

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "<html>Hello, <a href='http://testserver/'>world</a></html>"


def test_template_response_requires_request(tmpdir):
    templates = Jinja2Templates(str(tmpdir))
    with pytest.raises(ValueError):
        templates.TemplateResponse(None, {})
