[English](https://github.com/Kludex/starlette/blob/main/README.md) | 简体中文

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Kludex/starlette/main/docs/img/starlette_dark.svg" width="420px">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Kludex/starlette/main/docs/img/starlette.svg" width="420px">
    <img alt="starlette-logo" src="https://raw.githubusercontent.com/Kludex/starlette/main/docs/img/starlette.svg">
  </picture>
</p>

<p align="center">
    <em>✨ 小巧而闪亮的 ASGI 框架 ✨</em>
</p>

---

[![Build Status](https://github.com/Kludex/starlette/workflows/Test%20Suite/badge.svg)](https://github.com/Kludex/starlette/actions)
[![Package version](https://badge.fury.io/py/starlette.svg)](https://pypi.python.org/pypi/starlette)
[![Supported Python Version](https://img.shields.io/pypi/pyversions/starlette.svg?color=%2334D058)](https://pypi.org/project/starlette)
[![Discord](https://img.shields.io/discord/1051468649518616576?logo=discord&logoColor=ffffff&color=7389D8&labelColor=6A7EC2)](https://discord.gg/RxKUF5JuHs)

---

**文档**：<a href="https://starlette.dev/" target="_blank">https://starlette.dev</a>

**源代码**：<a href="https://github.com/Kludex/starlette" target="_blank">https://github.com/Kludex/starlette</a>

---

# Starlette

Starlette 是一个轻量级的 [ASGI][asgi] 框架／工具集，非常适合用 Python 构建异步 Web 服务。

它已经可以用于生产环境，提供以下能力：

* 轻量、低复杂度的 HTTP Web 框架。
* 支持 WebSocket。
* 进程内后台任务。
* 启动与关闭事件。
* 基于 `httpx2` 的测试客户端。
* CORS、GZip、静态文件、流式响应。
* 支持 Session 和 Cookie。
* 100% 测试覆盖率。
* 100% 类型标注的代码库。
* 硬依赖很少。
* 兼容 `asyncio` 和 `trio` 后端。
* 在[独立基准测试][techempower]中整体性能出色。

## 安装

```shell
$ pip install starlette
```

你还需要安装一个 ASGI 服务器，比如 [uvicorn](https://uvicorn.dev)，或者其他任意一种 [ASGI 服务器实现](https://asgi.readthedocs.io/en/latest/implementations.html#servers)。

```shell
$ pip install uvicorn
```

## 示例

```python title="main.py"
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route


async def homepage(request):
    return JSONResponse({'hello': 'world'})

routes = [
    Route("/", endpoint=homepage)
]

app = Starlette(debug=True, routes=routes)
```

然后用 Uvicorn 运行这个应用：

```shell
$ uvicorn main:app
```

## 依赖

Starlette 只依赖 `anyio`，以下依赖都是可选的：

* [`httpx2`][httpx2] - 想使用 `TestClient` 时需要。
* [`jinja2`][jinja2] - 想使用 `Jinja2Templates` 时需要。
* [`opentelemetry-api`][opentelemetry-api] - 使用 `OpenTelemetryMiddleware` 时需要。
* [`python-multipart`][python-multipart] - 想支持表单解析（`request.form()`）时需要。
* [`itsdangerous`][itsdangerous] - 使用 `SessionMiddleware` 时需要。
* [`pyyaml`][pyyaml] - 使用 `SchemaGenerator` 时需要。

可以用 `pip install starlette[full]` 一次性安装以上全部依赖。

## 框架与工具集

Starlette 既可以作为完整的框架使用，也可以当作 ASGI 工具集使用。它的各个组件都可以单独使用。

```python
from starlette.responses import PlainTextResponse


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = PlainTextResponse('Hello, world!')
    await response(scope, receive, send)
```

把 `app` 应用保存为 `example.py` 后运行：

```shell
$ uvicorn example:app
INFO: Started server process [11509]
INFO: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

给 uvicorn 加上 `--reload`，即可在代码变更时自动重载。

## 模块化

Starlette 的模块化设计鼓励构建可复用的组件，让它们可以在任意 ASGI 框架之间共享。这有助于形成一个由共享中间件和可挂载应用构成的生态。

清晰的 API 划分也意味着每个组件更容易被单独理解。

---

<p align="center"><i>Starlette 是 <a href="https://github.com/Kludex/starlette/blob/main/LICENSE.md">BSD 许可</a>的代码。<br/>用心设计与打磨。</i></br>&mdash; ⭐️ &mdash;</p>

[asgi]: https://asgi.readthedocs.io/en/latest/
[httpx2]: https://pypi.org/project/httpx2/
[jinja2]: https://jinja.palletsprojects.com/
[opentelemetry-api]: https://opentelemetry.io/docs/languages/python/api/
[python-multipart]: https://multipart.fastapiexpert.com/
[itsdangerous]: https://itsdangerous.palletsprojects.com/
[sqlalchemy]: https://www.sqlalchemy.org
[pyyaml]: https://pyyaml.org/wiki/PyYAMLDocumentation
[techempower]: https://github.com/TechEmpower/FrameworkBenchmarks
