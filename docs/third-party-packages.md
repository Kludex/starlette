
Starlette has a rapidly growing community of developers, building tools that integrate into Starlette, tools that depend on Starlette, etc.

Here are some of those third party packages:

## Plugins

### Starlette APISpec

Link: <a href="https://github.com/Woile/starlette-apispec" target="_blank">https://github.com/Woile/starlette-apispec</a>

Easy APISpec integration for Starlette.

Document your REST API built with Starlette by declaring OpenAPI (Swagger) schemas in YAML format in your endpoints' docstrings.

### Starlette API

Link: <a href="https://github.com/PeRDy/starlette-api" target="_blank">https://github.com/PeRDy/starlette-api</a>

That library aims to bring a layer on top of Starlette framework to provide useful mechanism for building APIs. It's 
based on API Star, inheriting some nice ideas like:

* **Schema system** based on [Marshmallow](https://github.com/marshmallow-code/marshmallow/) that allows to **declare**
the inputs and outputs of endpoints and provides a reliable way of **validate** data against those schemas.
* **Dependency Injection** that ease the process of managing parameters needed in endpoints.
* **Components** as the base of the plugin ecosystem, allowing you to create custom or use those already defined in 
your endpoints, injected as parameters.
* **Starlette ASGI** objects like `Request`, `Response`, `Session` and so on are defined as components and ready to be 
injected in your endpoints.
* **Auto generated API schema** using OpenAPI standard. It uses the schema system of your endpoints to extract all the 
necessary information to generate your API Schema.
* **Auto generated docs** providing a [Swagger UI](https://swagger.io/tools/swagger-ui/) or 
[ReDocs](https://rebilly.github.io/ReDoc/) endpoint.


```python
from marshmallow import Schema, fields, validate
from starlette_api.applications import Starlette


# Data Schema
class Puppy(Schema):
    id = fields.Integer()
    name = fields.String()
    age = fields.Integer(validate=validate.Range(min=0))


# Database
puppies = [
    {"id": 1, "name": "Canna", "age": 6},
    {"id": 2, "name": "Sandy", "age": 12},
]


# Application
app = Starlette(
    components=[],      # Without custom components
    title="Foo",        # API title
    version="0.1",      # API version
    description="Bar",  # API description
    schema="/schema/",  # Path to expose OpenAPI schema
    docs="/docs/",      # Path to expose Swagger UI docs
    redoc="/redoc/",    # Path to expose ReDoc docs
)


# Views
@app.route("/", methods=["GET"])
def list_puppies(name: str = None) -> Puppy(many=True):
    """
    List the puppies collection. There is an optional query parameter that 
    specifies a name for filtering the collection based on it.
    
    Request example:
    GET http://example.com/?name=Sandy
    
    Response example:
    200
    [
        {"id": 2, "name": "Sandy", "age": 12}
    ]
    """
    return [puppy for puppy in puppies if puppy["name"] == name]
```

### webargs-starlette

Link: <a href="https://github.com/sloria/webargs-starlette" target="_blank">https://github.com/sloria/webargs-starlette</a>

Declarative request parsing and validation for Starlette, built on top
of [webargs](https://github.com/marshmallow-code/webargs).

Allows you to parse querystring, JSON, form, headers, and cookies using
type annotations.

```python
import uvicorn
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from webargs_starlette import use_annotations

app = Starlette()


@app.route("/")
@use_annotations(locations=("query",))
async def index(request, name: str = "World"):
    return JSONResponse({"Hello": name})


if __name__ == "__main__":
    uvicorn.run(app, port=5000)

# curl 'http://localhost:5000/'
# {"Hello": "World"}
# curl 'http://localhost:5000/?name=Ada'
# {"Hello": "Ada"}
```

### Mangum

Link: <a href="https://github.com/erm/mangum" target="_blank">https://github.com/erm/mangum</a>

Serverless ASGI adapter for AWS Lambda & API Gateway.

```Python
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from mangum import Mangum


app = Starlette()


@app.route("/")
def homepage(request):
    return PlainTextResponse("Hello, world!")


handler = Mangum(app)  # optionally set debug=True
```

### Nejma ⭐

Link: <a href="https://github.com/taoufik07/nejma" target="_blank">https://github.com/taoufik07/nejma</a>

Helps you manage and send messages to groups of channels.

```python

from nejma.ext.starlette import WebSocketEndpoint

@app.websocket_route("/ws")
class Chat(WebSocketEndpoint):
    encoding = "json"

    async def on_receive(self, websocket, data):
        room_id = data['room_id']
        message = data['message']
        username = data['username']

        if message.strip():
            group = f"group_{room_id}"

            self.channel_layer.add(group, self.channel)

            payload = {
                "username": username,
                "message": message,
                "room_id": room_id
            }
            await self.channel_layer.group_send(group, payload)
```
Checkout <a href="https://github.com/taoufik07/nejma-chat" target="_blank">nejma-chat</a>, a simple chat application built using `nejma` and `starlette`.

## Frameworks

### Responder

Link: <a href="https://github.com/kennethreitz/responder" target="_blank">https://github.com/kennethreitz/responder</a>

A familiar HTTP Service Framework for Python.

* Flask-style route expression, with new capabilities -- all while using Python 3.6+'s new f-string syntax.
* Falcon's "every request and response is passed into to each view and mutated" methodology.
* Support for YAML by default.
* Several of Starlette's optional dependencies pre-installed, like:
    * Production static file server.
    * Uvicorn server.
    * GraphQL support, via Graphene.

```Python
import responder

api = responder.API()

@api.route("/{greeting}")
async def greet_world(req, resp, *, greeting):
    resp.text = f"{greeting}, world!"

if __name__ == '__main__':
    api.run()
```

### FastAPI

Link: <a href="https://github.com/tiangolo/fastapi" target="_blank">https://github.com/tiangolo/fastapi</a>

High performance, easy to learn, fast to code, ready for production.

An API framework inspired by **APIStar**'s previous server system with type declarations for route parameters, based on the OpenAPI specification version 3.0.0+ (with JSON Schema), powered by **Pydantic** for the data handling.

Use standard Python 3.6+ types as parameters to get:

* Autocomplete everywhere.
* Data conversion.
* Data validation.
* Automatic documentation with OpenAPI (and JSON Schema), based on the same Python types.

Includes:

* A simple but powerful **dependency injection** system.
* Automatic interactive documentation (based on Swagger UI and ReDoc).
* Security utilities, including **OAuth2** with **JWT tokens**.

```Python
from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/items/{item_id}")
def read_item(item_id: int, q: str = None):
    return {"item_id": item_id, "q": q}
```

This code declares a path `/`, and a path `/items/{item_id}`.

The path for `/items/{item_id}` has:

* A path parameter `item_id` that will be validated as an `int`, with automatic errors when invalid.
* An optional (by default `None`) query parameter `q` of type `str`.

Calling `http://example.com/items/2?q=myquery` will return:

```JSON
{"item_id": 2, "q": "myquery"}
```

The same way you can declare JSON body schemas, headers, etc.

### Bocadillo

Link: <a href="https://bocadilloproject.github.io" target="_blank">https://bocadilloproject.github.io</a>

A modern Python web framework filled with asynchronous salsa.

Bocadillo is **async-first** and designed with productivity and simplicity in mind. It is not meant to be minimal: a **carefully chosen set of included batteries** helps you build performant web apps and services with minimal setup.

Key features include:

* Simple, powerful and familiar views and routing, inspired by the greatest (Flask, Falcon).
* First-class support for both HTTP / REST and WebSocket.
* Built-in CORS, HSTS, GZip, HTTP streaming, Jinja2 templates, background tasks, static files…

… and more ahead, as depicted in the <a href="https://github.com/bocadilloproject/bocadillo/blob/master/ROADMAP.md" target="_blank">Roadmap</a>.

The example below demonstrates a simple WebSocket echo server.

```python
from bocadillo import API, WebSocket

api = API()

@api.websocket_route("/echo")
async def echo(ws: WebSocket):
    async with ws:
        async for message in ws:
            await ws.send(message)

if __name__ == "__main__":
    api.run()
```
