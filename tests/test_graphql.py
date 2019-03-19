import graphene
from graphql.execution.executors.asyncio import AsyncioExecutor

from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.graphql import GraphQLApp
from starlette.testclient import TestClient


class FakeAuthMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        headers = Headers(scope=scope)
        scope["user"] = "Jane" if headers.get("Authorization") == "Bearer 123" else None
        await self.app(scope, receive, send)


class Query(graphene.ObjectType):
    hello = graphene.String(name=graphene.String(default_value="stranger"))
    whoami = graphene.String()

    def resolve_hello(self, info, name):
        return "Hello " + name

    def resolve_whoami(self, info):
        return (
            "a mystery"
            if info.context["request"]["user"] is None
            else info.context["request"]["user"]
        )


schema = graphene.Schema(query=Query)
app = GraphQLApp(schema=schema, graphiql=True)
client = TestClient(app)


def test_graphql_get():
    response = client.get("/?query={ hello }")
    assert response.status_code == 200
    assert response.json() == {"data": {"hello": "Hello stranger"}, "errors": None}


def test_graphql_post():
    response = client.post("/?query={ hello }")
    assert response.status_code == 200
    assert response.json() == {"data": {"hello": "Hello stranger"}, "errors": None}


def test_graphql_post_json():
    response = client.post("/", json={"query": "{ hello }"})
    assert response.status_code == 200
    assert response.json() == {"data": {"hello": "Hello stranger"}, "errors": None}


def test_graphql_post_graphql():
    response = client.post(
        "/", data="{ hello }", headers={"content-type": "application/graphql"}
    )
    assert response.status_code == 200
    assert response.json() == {"data": {"hello": "Hello stranger"}, "errors": None}


def test_graphql_post_invalid_media_type():
    response = client.post("/", data="{ hello }", headers={"content-type": "dummy"})
    assert response.status_code == 415
    assert response.text == "Unsupported Media Type"


def test_graphql_put():
    response = client.put("/", json={"query": "{ hello }"})
    assert response.status_code == 405
    assert response.text == "Method Not Allowed"


def test_graphql_no_query():
    response = client.get("/")
    assert response.status_code == 400
    assert response.text == "No GraphQL query found in the request"


def test_graphql_invalid_field():
    response = client.post("/", json={"query": "{ dummy }"})
    assert response.status_code == 400
    assert response.json() == {
        "data": None,
        "errors": [
            {
                "locations": [{"column": 3, "line": 1}],
                "message": 'Cannot query field "dummy" on type "Query".',
            }
        ],
    }


def test_graphiql_get():
    response = client.get("/", headers={"accept": "text/html"})
    assert response.status_code == 200
    assert "<!DOCTYPE html>" in response.text


def test_graphiql_not_found():
    app = GraphQLApp(schema=schema, graphiql=False)
    client = TestClient(app)
    response = client.get("/", headers={"accept": "text/html"})
    assert response.status_code == 404
    assert response.text == "Not Found"


def test_add_graphql_route():
    app = Starlette()
    app.add_route("/", GraphQLApp(schema=schema))
    client = TestClient(app)
    response = client.get("/?query={ hello }")
    assert response.status_code == 200
    assert response.json() == {"data": {"hello": "Hello stranger"}, "errors": None}


def test_graphql_context():
    app = Starlette()
    app.add_middleware(FakeAuthMiddleware)
    app.add_route("/", GraphQLApp(schema=schema))
    client = TestClient(app)
    response = client.post(
        "/", json={"query": "{ whoami }"}, headers={"Authorization": "Bearer 123"}
    )
    assert response.status_code == 200
    assert response.json() == {"data": {"whoami": "Jane"}, "errors": None}


class ASyncQuery(graphene.ObjectType):
    hello = graphene.String(name=graphene.String(default_value="stranger"))

    async def resolve_hello(self, info, name):
        return "Hello " + name


async_schema = graphene.Schema(query=ASyncQuery)
async_app = GraphQLApp(schema=async_schema, executor_class=AsyncioExecutor)


def test_graphql_async():
    client = TestClient(async_app)
    response = client.get("/?query={ hello }")
    assert response.status_code == 200
    assert response.json() == {"data": {"hello": "Hello stranger"}, "errors": None}


async_schema = graphene.Schema(query=ASyncQuery)
old_style_async_app = GraphQLApp(schema=async_schema, executor=AsyncioExecutor())


def test_graphql_async_old_style_executor():
    # See https://github.com/encode/starlette/issues/242
    client = TestClient(old_style_async_app)
    response = client.get("/?query={ hello }")
    assert response.status_code == 200
    assert response.json() == {"data": {"hello": "Hello stranger"}, "errors": None}
