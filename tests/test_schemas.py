from starlette.applications import Starlette
from starlette.endpoints import HTTPEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Host, Mount, Route, Router, WebSocketRoute
from starlette.schemas import SchemaGenerator
from starlette.websockets import WebSocket
from tests.types import TestClientFactory

schemas = SchemaGenerator({"openapi": "3.0.0", "info": {"title": "Example API", "version": "1.0"}})


def ws(session: WebSocket) -> None:
    """ws"""
    pass  # pragma: no cover


def get_user(request: Request) -> None:
    """
    responses:
        200:
            description: A user.
            examples:
                {"username": "tom"}
    """
    pass  # pragma: no cover


def list_users(request: Request) -> None:
    """
    responses:
      200:
        description: A list of users.
        examples:
          [{"username": "tom"}, {"username": "lucy"}]
    """
    pass  # pragma: no cover


def create_user(request: Request) -> None:
    """
    responses:
      200:
        description: A user.
        examples:
          {"username": "tom"}
    """
    pass  # pragma: no cover


class OrganisationsEndpoint(HTTPEndpoint):
    def get(self, request: Request) -> None:
        """
        responses:
          200:
            description: A list of organisations.
            examples:
              [{"name": "Foo Corp."}, {"name": "Acme Ltd."}]
        """
        pass  # pragma: no cover

    def post(self, request: Request) -> None:
        """
        responses:
          200:
            description: An organisation.
            examples:
              {"name": "Foo Corp."}
        """
        pass  # pragma: no cover


def regular_docstring_and_schema(request: Request) -> None:
    """
    This a regular docstring example (not included in schema)

    ---

    responses:
      200:
        description: This is included in the schema.
    """
    pass  # pragma: no cover


def regular_docstring(request: Request) -> None:
    """
    This a regular docstring example (not included in schema)
    """
    pass  # pragma: no cover


def no_docstring(request: Request) -> None:
    pass  # pragma: no cover


def subapp_endpoint(request: Request) -> None:
    """
    responses:
      200:
        description: This endpoint is part of a subapp.
    """
    pass  # pragma: no cover


def schema(request: Request) -> Response:
    return schemas.OpenAPIResponse(request=request)


subapp = Starlette(
    routes=[
        Route("/subapp-endpoint", endpoint=subapp_endpoint),
    ]
)

app = Starlette(
    routes=[
        WebSocketRoute("/ws", endpoint=ws),
        Route("/users/{id:int}", endpoint=get_user, methods=["GET"]),
        Route("/users", endpoint=list_users, methods=["GET", "HEAD"]),
        Route("/users", endpoint=create_user, methods=["POST"]),
        Route("/orgs", endpoint=OrganisationsEndpoint),
        Route("/regular-docstring-and-schema", endpoint=regular_docstring_and_schema),
        Route("/regular-docstring", endpoint=regular_docstring),
        Route("/no-docstring", endpoint=no_docstring),
        Route("/schema", endpoint=schema, methods=["GET"], include_in_schema=False),
        Mount("/subapp", subapp),
        Host("sub.domain.com", app=Router(routes=[Mount("/subapp2", subapp)])),
    ]
)


def test_schema_generation() -> None:
    schema = schemas.get_schema(routes=app.routes)
    assert schema == {
        "openapi": "3.0.0",
        "info": {"title": "Example API", "version": "1.0"},
        "paths": {
            "/orgs": {
                "get": {
                    "responses": {
                        200: {
                            "description": "A list of organisations.",
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
                "get": {"responses": {200: {"description": "This is included in the schema."}}}
            },
            "/subapp/subapp-endpoint": {
                "get": {"responses": {200: {"description": "This endpoint is part of a subapp."}}}
            },
            "/subapp2/subapp-endpoint": {
                "get": {"responses": {200: {"description": "This endpoint is part of a subapp."}}}
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
                "post": {"responses": {200: {"description": "A user.", "examples": {"username": "tom"}}}},
            },
            "/users/{id}": {
                "get": {
                    "responses": {
                        200: {
                            "description": "A user.",
                            "examples": {"username": "tom"},
                        }
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
  /subapp2/subapp-endpoint:
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
  /users/{id}:
    get:
      responses:
        200:
          description: A user.
          examples:
            username: tom
"""


def test_schema_endpoint(test_client_factory: TestClientFactory) -> None:
    client = test_client_factory(app)
    response = client.get("/schema")
    assert response.headers["Content-Type"] == "application/vnd.oai.openapi"
    assert response.text.strip() == EXPECTED_SCHEMA.strip()
