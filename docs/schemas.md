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
from starlette.schemas import SchemaGenerator, OpenAPIResponse

app = Starlette()
app.schema_generator = SchemaGenerator(
    {"openapi": "3.0.0", "info": {"title": "Example API", "version": "1.0"}}
)


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
def schema(request):
    return OpenAPIResponse(app.schema)
```

We can now access an OpenAPI schema at the "/schema" endpoint.

You can inspect the API Schema directly by accessing `app.schema`:

```python
assert app.schema == {
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
        print(yaml.dumps(app.schema, default_flow_style=False))
```

[openapi]: https://github.com/OAI/OpenAPI-Specification
