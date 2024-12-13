
Starlette has a rapidly growing community of developers, building tools that integrate into Starlette, tools that depend on Starlette, etc.

Here are some of those third party packages:

## Plugins

### Apitally

<a href="https://github.com/apitally/apitally-py" target="_blank">GitHub</a> |
<a href="https://docs.apitally.io/frameworks/starlette" target="_blank">Documentation</a>

Analytics, request logging and monitoring for REST APIs built with Starlette (and other frameworks).

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

### Starlette Compress

<a href="https://github.com/Zaczero/starlette-compress" target="_blank">GitHub</a>

Starlette-Compress is a fast and simple middleware for compressing responses in Starlette.
It adds ZStd, Brotli, and GZip compression support with sensible default configuration.

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

### Starlette-Login

<a href="https://github.com/jockerz/Starlette-Login" target="_blank">GitHub</a> |
<a href="https://starlette-login.readthedocs.io/en/stable/" target="_blank">Documentation</a>

User session management for Starlette.
It handles the common tasks of logging in, logging out, and remembering your users' sessions over extended periods of time.


### Starsessions

<a href="https://github.com/alex-oleshkevich/starsessions" target="_blank">GitHub</a>

An alternate session support implementation with customizable storage backends.

### webargs-starlette

<a href="https://github.com/sloria/webargs-starlette" target="_blank">GitHub</a>

Declarative request parsing and validation for Starlette, built on top
of [webargs](https://github.com/marshmallow-code/webargs).

Allows you to parse querystring, JSON, form, headers, and cookies using
type annotations.

### DecoRouter

<a href="https://github.com/MrPigss/DecoRouter" target="_blank">GitHub</a>

FastAPI style routing for Starlette.

Allows you to use decorators to generate routing tables.

### Starception

<a href="https://github.com/alex-oleshkevich/starception" target="_blank">GitHub</a>

Beautiful exception page for Starlette apps.

### Starlette-Admin

<a href="https://github.com/jowilf/starlette-admin" target="_blank">GitHub</a> |
<a href="https://jowilf.github.io/starlette-admin" target="_blank">Documentation</a>

Simple and extensible admin interface framework.

Built with [Tabler](https://tabler.io/) and [Datatables](https://datatables.net/), it allows you
to quickly generate fully customizable admin interface for your models. You can export your data to many formats (*CSV*, *PDF*,
*Excel*, etc), filter your data with complex query including `AND` and `OR` conditions,  upload files, ...

### Vellox

<a href="https://github.com/junah201/vellox" target="_blank">GitHub</a>

Serverless ASGI adapter for GCP Cloud Functions.

## Starlette Bridge

<a href="https://github.com/tarsil/starlette-bridge" target="_blank">GitHub</a> |
<a href="https://starlette-bridge.tarsild.io/" target="_blank">Documentation</a>

With the deprecation of `on_startup` and `on_shutdown`, Starlette Bridge makes sure you can still
use the old ways of declaring events with a particularity that internally, in fact, creates the
`lifespan` for you. This way backwards compatibility is assured for the existing packages out there
while maintaining the integrity of the newly `lifespan` events of `Starlette`.

## Frameworks

### FastAPI

<a href="https://github.com/tiangolo/fastapi" target="_blank">GitHub</a> |
<a href="https://fastapi.tiangolo.com/" target="_blank">Documentation</a>

High performance, easy to learn, fast to code, ready for production web API framework.
Inspired by **APIStar**'s previous server system with type declarations for route parameters, based on the OpenAPI specification version 3.0.0+ (with JSON Schema), powered by **Pydantic** for the data handling.

### Flama

<a href="https://github.com/vortico/flama" target="_blank">GitHub</a> |
<a href="https://flama.dev/" target="_blank">Documentation</a>

Flama is a **data-science oriented framework** to rapidly build modern and robust **machine learning** (ML) APIs. The main aim of the framework is to make ridiculously simple the deployment of ML APIs. With Flama, data scientists can now quickly turn their ML models into asynchronous, auto-documented APIs with just a single line of code. All in just few seconds!

Flama comes with an intuitive CLI, and provides an easy-to-learn philosophy to speed up the building of **highly performant** GraphQL, REST, and ML APIs. Besides, it comprises an ideal solution for the development of asynchronous and **production-ready** services, offering **automatic deployment** for ML models.

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

### Xpresso

A flexible and extendable web framework built on top of Starlette, Pydantic and [di](https://github.com/adriangb/di).

<a href="https://github.com/adriangb/xpresso" target="_blank">GitHub</a> |
<a href=https://xpresso-api.dev/" target="_blank">Documentation</a>

### Ellar

<a href="https://github.com/eadwinCode/ellar" target="_blank">GitHub</a> |
<a href="https://eadwincode.github.io/ellar/" target="_blank">Documentation</a>

Ellar is an ASGI web framework for building fast, efficient and scalable RESTAPIs and server-side applications. It offers a high level of abstraction in building server-side applications and combines elements of OOP (Object Oriented Programming), and FP (Functional Programming) - Inspired by Nestjs.

It is built on 3 core libraries **Starlette**, **Pydantic**, and **injector**.

### Apiman

An extension to integrate Swagger/OpenAPI document easily for Starlette project and provide [SwaggerUI](http://swagger.io/swagger-ui/) and [RedocUI](https://rebilly.github.io/ReDoc/).

<a href="https://github.com/strongbugman/apiman" target="_blank">GitHub</a>

### Starlette-Babel

Provides translations, localization, and timezone support via Babel integration.

<a href="https://github.com/alex-oleshkevich/starlette_babel" target="_blank">GitHub</a>

### Starlette-StaticResources

<a href="https://github.com/DavidVentura/starlette-static-resources" target="_blank">GitHub</a>

Allows mounting [package resources](https://docs.python.org/3/library/importlib.resources.html#module-importlib.resources) for static data, similar to [StaticFiles](https://www.starlette.io/staticfiles/).

### Sentry

<a href="https://github.com/getsentry/sentry-python" target="_blank">GitHub</a> |
<a href="https://docs.sentry.io/platforms/python/guides/starlette/" target="_blank">Documentation</a>

Sentry is a software error detection tool. It offers actionable insights for resolving performance issues and errors, allowing users to diagnose, fix, and optimize Python debugging. Additionally, it integrates seamlessly with Starlette for Python application development. Sentry's capabilities include error tracking, performance insights, contextual information, and alerts/notifications.

### Shiny

<a href="https://github.com/posit-dev/py-shiny" target="_blank">GitHub</a> |
<a href="https://shiny.posit.co/py/" target="_blank">Documentation</a>

Leveraging Starlette and asyncio, Shiny allows developers to create effortless Python web applications using the power of reactive programming. Shiny eliminates the hassle of manual state management, automatically determining the best execution path for your app at runtime while simultaneously minimizing re-rendering. This means that Shiny can support everything from the simplest dashboard to full-featured web apps.   