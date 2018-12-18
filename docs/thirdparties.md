
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
