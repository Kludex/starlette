import os

from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.testclient import TestClient


def test_templates(tmpdir):
    path = os.path.join(tmpdir, "index.html")
    with open(path, "w") as file:
        file.write("<html>Hello, <a href='{{ url_for('homepage') }}'>world</a></html>")

    app = Starlette(debug=True, template_directory=tmpdir)

    @app.route("/")
    async def homepage(request):
        template = app.get_template("index.html")
        content = template.render(request=request)
        return HTMLResponse(content)

    client = TestClient(app)
    response = client.get("/")
    assert response.text == "<html>Hello, <a href='http://testserver/'>world</a></html>"
