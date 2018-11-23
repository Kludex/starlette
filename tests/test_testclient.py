from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

mock_service = Starlette()


@mock_service.route("/")
def mock_service_endpoint(request):
    return JSONResponse({"mock": "example"})


app = Starlette()


@app.route("/")
def homepage(request):
    client = TestClient(mock_service)
    response = client.get("/")
    return JSONResponse(response.json())


def test_use_testclient_in_endpoint():
    """
    We should be able to use the test client within applications.

    This is useful if we need to mock out other services,
    during tests or in development.
    """
    client = TestClient(app)
    response = client.get("/")
    assert response.json() == {"mock": "example"}
