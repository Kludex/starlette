
Starlette has a rapidly growing community of developers, building tools that integrate into Starlette, tools that depend on Starlette, etc.

Here are some of those third party packages:

## Backports

### Python 3.5 port

<a href="https://github.com/em92/starlette" target="_blank">GitHub</a>

## Plugins

### Authlib

<a href="https://github.com/lepture/Authlib" target="_blank">GitHub</a> |
<a href="https://docs.authlib.org/en/latest/" target="_blank">Documentation</a>

The ultimate Python library in building OAuth and OpenID Connect clients and servers. Check out how to integrate with [Starlette](https://docs.authlib.org/en/latest/client/starlette.html).

### ChannelBox

<a href="https://github.com/Sobolev5/channel-box" target="_blank">GitHub</a>

Another solution for websocket broadcast. Send messages to channel groups from any part of your code.
Checkout <a href="https://channel-box.andrey-sobolev.ru/" target="_blank">MySimpleChat</a>, a simple chat application built using `channel-box` and `starlette`.

### Imia

<a href="https://github.com/alex-oleshkevich/imia" target="_blank">GitHub</a>

An authentication framework for Starlette with pluggable authenticators and login/logout flow.

### Mangum

<a href="https://github.com/erm/mangum" target="_blank">GitHub</a>

Serverless ASGI adapter for AWS Lambda & API Gateway.

### Nejma

<a href="https://github.com/taoufik07/nejma" target="_blank">GitHub</a>

Manage and send messages to groups of channels using websockets.
Checkout <a href="https://github.com/taoufik07/nejma-chat" target="_blank">nejma-chat</a>, a simple chat application built using `nejma` and `starlette`.

### Scout APM

<a href="https://github.com/scoutapp/scout_apm_python" target="_blank">GitHub</a>

An APM (Application Performance Monitoring) solution that can
instrument your application to find performance bottlenecks.

### SpecTree

<a href="https://github.com/0b01001001/spectree" target="_blank">GitHub</a>

Generate OpenAPI spec document and validate request & response with Python annotations. Less boilerplate code(no need for YAML).

### Starlette APISpec

<a href="https://github.com/Woile/starlette-apispec" target="_blank">GitHub</a>

Simple APISpec integration for Starlette.
Document your REST API built with Starlette by declaring OpenAPI (Swagger)
schemas in YAML format in your endpoint's docstrings.

### Starlette Context

<a href="https://github.com/tomwojcik/starlette-context" target="_blank">GitHub</a>

Middleware for Starlette that allows you to store and access the context data of a request.
Can be used with logging so logs automatically use request headers such as x-request-id or x-correlation-id.

### Starlette Cramjam

<a href="https://github.com/developmentseed/starlette-cramjam" target="_blank">GitHub</a>

A Starlette middleware that allows **brotli**, **gzip** and **deflate** compression algorithm with a minimal requirements.

### Starlette OAuth2 API

<a href="https://gitlab.com/jorgecarleitao/starlette-oauth2-api" target="_blank">GitLab</a>

A starlette middleware to add authentication and authorization through JWTs.
It relies solely on an auth provider to issue access and/or id tokens to clients.

### Starlette Prometheus

<a href="https://github.com/perdy/starlette-prometheus" target="_blank">GitHub</a>

A plugin for providing an endpoint that exposes [Prometheus](https://prometheus.io/) metrics based on its [official python client](https://github.com/prometheus/client_python).

### Starlette WTF

<a href="https://github.com/muicss/starlette-wtf" target="_blank">GitHub</a>

A simple tool for integrating Starlette and WTForms. It is modeled on the excellent Flask-WTF library.

### Starsessions

<a href="https://github.com/alex-oleshkevich/starsessions" target="_blank">GitHub</a>

An alternate session support implementation with customizable storage backends.

### webargs-starlette

<a href="https://github.com/sloria/webargs-starlette" target="_blank">GitHub</a>

Declarative request parsing and validation for Starlette, built on top
of [webargs](https://github.com/marshmallow-code/webargs).

Allows you to parse querystring, JSON, form, headers, and cookies using
type annotations.

## Frameworks

### FastAPI

<a href="https://github.com/tiangolo/fastapi" target="_blank">GitHub</a> |
<a href="https://fastapi.tiangolo.com/" target="_blank">Documentation</a>

High performance, easy to learn, fast to code, ready for production web API framework.
Inspired by **APIStar**'s previous server system with type declarations for route parameters, based on the OpenAPI specification version 3.0.0+ (with JSON Schema), powered by **Pydantic** for the data handling.

### Flama

<a href="https://github.com/perdy/flama/" target="_blank">GitHub</a> |
<a href="https://flama.perdy.io/" target="_blank">Documentation</a>

Formerly Starlette API.

Flama aims to bring a layer on top of Starlette to provide an **easy to learn** and **fast to develop** approach for building **highly performant** GraphQL and REST APIs. In the same way of Starlette is, Flama is a perfect option for developing **asynchronous** and **production-ready** services.

### Greppo

<a href="https://github.com/greppo-io/greppo" target="_blank">GitHub</a> |
<a href="https://docs.greppo.io/" target="_blank">Documentation</a>

A Python framework for building geospatial dashboards and web-applications.

Greppo is an open-source Python framework that makes it easy to build geospatial dashboards and web-applications. It provides a toolkit to quickly integrate data, algorithms, visualizations and UI for interactivity. It provides APIs to the update the variables in the backend, recompute the logic, and reflect the changes in the frontend (data mutation hook).

### Responder

<a href="https://github.com/taoufik07/responder" target="_blank">GitHub</a> |
<a href="https://python-responder.org/en/latest/" target="_blank">Documentation</a>

Async web service framework. Some Features: flask-style route expression,
yaml support, OpenAPI schema generation, background tasks, graphql.

### Starlette-apps

Roll your own framework with a simple app system, like [Django-GDAPS](https://gdaps.readthedocs.io/en/latest/) or [CakePHP](https://cakephp.org/).

<a href="https://github.com/yourlabs/starlette-apps" target="_blank">GitHub</a>

### Dark Star

A simple framework to help minimise the code needed to get HTML to the browser. Changes your file paths into Starlette routes and puts your view code right next to your template. Includes support for [htmx](https://htmx.org) to help enhance your frontend.

<a href="https://lllama.github.io/dark-star" target="_blank">Docs</a>
<a href="https://github.com/lllama/dark-star" target="_blank">GitHub</a>
