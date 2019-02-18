from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.schemas import OpenAPIResponse, SchemaGenerator
from starlette.testclient import TestClient

schemas = SchemaGenerator(
    {"openapi": "3.0.0", "info": {"title": "Example API", "version": "1.0"}}
)

app = Starlette()


@app.websocket_route("/ws")
def ws(session):
    """ws"""
    pass  # pragma: no cover


@app.route("/users", methods=["GET", "HEAD"])
def list_users(request):
    """
    responses:
      200:
        description: A list of users.
        examples:
          [{"username": "tom"}, {"username": "lucy"}]
    """
    pass  # pragma: no cover


@app.route("/users", methods=["POST"])
def create_user(request):
    """
    responses:
      200:
        description: A user.
        examples:
          {"username": "tom"}
    """
    pass  # pragma: no cover


@app.route("/orgs")
class OrganisationsEndpoint(HTTPEndpoint):
    def get(self, request):
        """
        responses:
          200:
            description: A list of organisations.
            examples:
              [{"name": "Foo Corp."}, {"name": "Acme Ltd."}]
        """
        pass  # pragma: no cover

    def post(self, request):
        """
        responses:
          200:
            description: An organisation.
            examples:
              {"name": "Foo Corp."}
        """
        pass  # pragma: no cover


@app.route("/schema", methods=["GET"], include_in_schema=False)
def schema(request):
    return schemas.OpenAPIResponse(request=request)


def test_schema_generation():
    schema = schemas.get_schema(routes=app.routes)
    assert schema == {
        "openapi": "3.0.0",
        "info": {"title": "Example API", "version": "1.0"},
        "paths": {
            "/orgs": {
                "get": {
                    "responses": {
                        200: {
                            "description": "A list of " "organisations.",
                            "examples": [{"name": "Foo Corp."}, {"name": "Acme Ltd."}],
                        }
                    }
                },
                "post": {
                    "responses": {
                        200: {
                            "description": "An organisation.",
                            "examples": {"name": "Foo Corp."},
                        }
                    }
                },
            },
            "/users": {
                "get": {
                    "responses": {
                        200: {
                            "description": "A list of users.",
                            "examples": [{"username": "tom"}, {"username": "lucy"}],
                        }
                    }
                },
                "post": {
                    "responses": {
                        200: {"description": "A user.", "examples": {"username": "tom"}}
                    }
                },
            },
        },
    }


def test_schema_generation_legacy():
    app.schema_generator = schemas
    assert app.schema == schemas.get_schema(routes=app.routes)


EXPECTED_SCHEMA = """
info:
  title: Example API
  version: '1.0'
openapi: 3.0.0
paths:
  /orgs:
    get:
      responses:
        200:
          description: A list of organisations.
          examples:
          - name: Foo Corp.
          - name: Acme Ltd.
    post:
      responses:
        200:
          description: An organisation.
          examples:
            name: Foo Corp.
  /users:
    get:
      responses:
        200:
          description: A list of users.
          examples:
          - username: tom
          - username: lucy
    post:
      responses:
        200:
          description: A user.
          examples:
            username: tom
"""


def test_schema_endpoint():
    client = TestClient(app)
    response = client.get("/schema")
    assert response.headers["Content-Type"] == "application/vnd.oai.openapi"
    assert response.text.strip() == EXPECTED_SCHEMA.strip()
