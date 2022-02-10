from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.schemas import SchemaGenerator

schemas = SchemaGenerator(
    {"openapi": "3.0.0", "info": {"title": "Example API", "version": "1.0"}}
)


def ws(session):
    """ws"""
    pass  # pragma: no cover


def list_users(request):
    """
    responses:
      200:
        description: A list of users.
        examples:
          [{"username": "tom"}, {"username": "lucy"}]
    """
    pass  # pragma: no cover


def create_user(request):
    """
    responses:
      200:
        description: A user.
        examples:
          {"username": "tom"}
    """
    pass  # pragma: no cover


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


def regular_docstring_and_schema(request):
    """
    This a regular docstring example (not included in schema)

    ---

    responses:
      200:
        description: This is included in the schema.
    """
    pass  # pragma: no cover


def regular_docstring(request):
    """
    This a regular docstring example (not included in schema)
    """
    pass  # pragma: no cover


def no_docstring(request):
    pass  # pragma: no cover


def subapp_endpoint(request):
    """
    responses:
      200:
        description: This endpoint is part of a subapp.
    """
    pass  # pragma: no cover


def schema(request):
    return schemas.OpenAPIResponse(request=request)


subapp = Starlette(
    routes=[
        Route("/subapp-endpoint", endpoint=subapp_endpoint),
    ]
)

app = Starlette(
    routes=[
        WebSocketRoute("/ws", endpoint=ws),
        Route("/users", endpoint=list_users, methods=["GET", "HEAD"]),
        Route("/users", endpoint=create_user, methods=["POST"]),
        Route("/orgs", endpoint=OrganisationsEndpoint),
        Route("/regular-docstring-and-schema", endpoint=regular_docstring_and_schema),
        Route("/regular-docstring", endpoint=regular_docstring),
        Route("/no-docstring", endpoint=no_docstring),
        Route("/schema", endpoint=schema, methods=["GET"], include_in_schema=False),
        Mount("/subapp", subapp),
    ]
)


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
            "/regular-docstring-and-schema": {
                "get": {
                    "responses": {
                        200: {"description": "This is included in the schema."}
                    }
                }
            },
            "/subapp/subapp-endpoint": {
                "get": {
                    "responses": {
                        200: {"description": "This endpoint is part of a subapp."}
                    }
                }
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
  /regular-docstring-and-schema:
    get:
      responses:
        200:
          description: This is included in the schema.
  /subapp/subapp-endpoint:
    get:
      responses:
        200:
          description: This endpoint is part of a subapp.
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


def test_schema_endpoint(test_client_factory):
    client = test_client_factory(app)
    response = client.get("/schema")
    assert response.headers["Content-Type"] == "application/vnd.oai.openapi"
    assert response.text.strip() == EXPECTED_SCHEMA.strip()
