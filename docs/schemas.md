Starlette supports generating API schemas, such as the widely used [OpenAPI
specification][openapi]. (Formerly known as "Swagger".)

Schema generation works by inspecting the routes on the application through
`app.routes`, and using the docstrings or other attributes on the endpoints
in order to determine a complete API schema.

Starlette is not tied to any particular schema generation or validation tooling,
but includes a simple implementation that generates OpenAPI schemas based on
the docstrings.

```python
from starlette.applications import Starlette
from starlette.schemas import SchemaGenerator


schemas = SchemaGenerator(
    {"openapi": "3.0.0", "info": {"title": "Example API", "version": "1.0"}}
)
app = Starlette()


@app.route("/users", methods=["GET"])
def list_users(request):
    """
    responses:
      200:
        description: A list of users.
        examples:
          [{"username": "tom"}, {"username": "lucy"}]
    """
    raise NotImplementedError()


@app.route("/users", methods=["POST"])
def create_user(request):
    """
    responses:
      200:
        description: A user.
        examples:
          {"username": "tom"}
    """
    raise NotImplementedError()


@app.route("/schema", methods=["GET"], include_in_schema=False)
def openapi_schema(request):
    return schemas.OpenAPIResponse(request=request)
```

We can now access an OpenAPI schema at the "/schema" endpoint.

You can generate the API Schema directly with `.get_schema(routes)`:

```python
schema = schemas.get_schema(routes=app.routes)
assert schema == {
    "openapi": "3.0.0",
    "info": {"title": "Example API", "version": "1.0"},
    "paths": {
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
```

You might also want to be able to print out the API schema, so that you can
use tooling such as generating API documentation.

```python
if __name__ == '__main__':
    assert sys.argv[-1] in ("run", "schema"), "Usage: example.py [run|schema]"

    if sys.argv[-1] == "run":
        uvicorn.run(app, host='0.0.0.0', port=8000)
    elif sys.arvg[-1] == "schema":
        schema = schemas.get_schema(routes=app.routes)
        print(yaml.dump(schema, default_flow_style=False))
```

### Third party packages

#### [starlette-apispec][starlette-apispec]

Easy APISpec integration for Starlette, which supports some object serialization libraries.

[openapi]: https://github.com/OAI/OpenAPI-Specification
[starlette-apispec]: https://github.com/Woile/starlette-apispec
