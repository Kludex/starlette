
Starlette has a rapidly growing community of developers, building tools that integrate into Starlette, tools that depend on Starlette, etc.

Here are some of those third party packages:

## Plugins

### Starlette APISpec

Link: <a href="https://github.com/Woile/starlette-apispec" target="_blank">https://github.com/Woile/starlette-apispec</a>

Easy APISpec integration for Starlette.

Document your REST API built with Starlette by declaring OpenAPI (Swagger) schemas in YAML format in your endpoints' docstrings.

### Starlette API

Link: <a href="https://github.com/PeRDy/starlette-api" target="_blank">https://github.com/PeRDy/starlette-api</a>

That library aims to bring a layer on top of Starlette framework to provide useful mechanism for building APIs. It's based on API Star, inheriting some nice ideas like:

* **Schema system** based on Marshmallow that allows to declare the inputs and outputs of endpoints and provides a reliable way of validate data against those schemas.
* **Dependency Injection** that ease the process of managing parameters needed in endpoints.
* **Components** as the base of the plugin ecosystem, allowing you to create custom or use those already defined in your endpoints, injected as parameters.
* **Starlette ASGI** objects like `Request`, `Response`, `Session` and so on are defined as components and ready to be injected in your endpoints.

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

A library for using any ASGI application with FaaS platforms.

It includes:

* Adapter classes for **AWS Lambda & API Gateway** and **Azure Functions**.
* CLI tools (experimental) for generating, packaging, and validating AWS deployment configurations.

```Python
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from mangum.platforms.aws.adapter import AWSLambdaAdapter
# from mangum.platforms.azure.adapter import AzureFunctionAdapter


app = Starlette()


@app.route("/")
def homepage(request):
    return PlainTextResponse("Hello, world!")


handler = AWSLambdaAdapter(app)  # optionally set debug=True
# handler = AzureFunctionAdapter(app)
```


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

@app.get('/')
def read_root():
    return {'hello': 'world'}
```

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
