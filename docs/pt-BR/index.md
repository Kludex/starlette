<p align="center">
  <img width="400px" src="/img/starlette.svg#only-light" alt="starlette"/>
  <img width="400px" src="/img/starlette_dark.svg#only-dark" alt="starlette"/>
</p>
<p align="center">
    <em>✨ Um pequeno framework ASGI que se destaca. ✨</em>
</p>
<p align="center">
<a href="https://github.com/Kludex/starlette/actions">
    <img src="https://github.com/Kludex/starlette/workflows/Test%20Suite/badge.svg" alt="Build Status">
</a>
<a href="https://pypi.org/project/starlette/">
    <img src="https://badge.fury.io/py/starlette.svg" alt="Package version">
</a>
<a href="https://pypi.org/project/starlette" target="_blank">
    <img src="https://img.shields.io/pypi/pyversions/starlette.svg?color=%2334D058" alt="Supported Python versions">
</a>
</p>

---

**Documentação**: <a href="https://www.starlette.io/" target="_blank">https://www.starlette.io</a>

**Código fonte:**: <a href="https://github.com/Kludex/starlette" target="_blank">https://github.com/Kludex/starlette</a>

---

# Introdução

Starlette é um framework/kit de ferramentas [ASGI][asgi] leve,
ideal para criar serviços web assíncronos em Python.

Ele já está pronto para produção e oferece os seguintes recursos:

* Uma leve estrutura web HTTP e de baixa complexidade.
* Suporte a WebSocket.
* Processos de tarefas em segundo plano.
* Eventos de inicialização e desligamento.
* Cliente de teste desenvolvido em `httpx`.
* CORS, GZip, Arquivos Estáticos, Transmissão.
* Suporte a sessões e cookies.
* 100% de testes cobertos.
* Base de código 100% anotada por tipo.
* Poucas dependências rígidas
* Compatível com os backends `asyncio` e `trio`.
* Excelente desempenho geral [em comparação com benchmarks independentes][techempower].


## Patrocinadores

O Starlette é um projeto de código aberto que depende do apoio da comunidade. Você pode nos ajudar a manter e melhorar a estrutura [tornando-se um patrocinador](sponsorship.md).

<div style="text-align: center; margin: 2rem 0;">
    <h4 style="color: #ffd700; margin-bottom: 1rem;">🏆 Patrocinadores Ouro.</h4>
    <a href="https://fastapi.tiangolo.com" style="text-decoration: none;">
        <div style="width: 200px; background: #f6f8fa; border-radius: 8px; padding: 1rem; text-align: center; margin: 0 auto;">
            <div style="height: 100px; display: flex; align-items: center; justify-content: center; margin-bottom: 0.75rem;">
                <img src="https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png" alt="FastAPI" style="max-width: 100%; max-height: 100%; object-fit: contain;">
            </div>
            <p style="margin: 0; color: #57606a; font-size: 0.9em;">Estrutura web moderna e rápida para criar APIs com Python 3.8+</p>
        </div>
    </a>
</div>



## Instalação

```shell
pip install starlette
```

Você também necessitará de um servidor ASGI, como: [uvicorn](https://www.uvicorn.org/), [daphne](https://github.com/django/daphne/), or [hypercorn](https://hypercorn.readthedocs.io/en/latest/).

```shell
pip install uvicorn
```

## Exemplo

```python title="main.py"
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route


async def homepage(request):
    return JSONResponse({'Olá': 'Mundo'})


app = Starlette(debug=True, routes=[
    Route('/', homepage),
])
```

Então rode a aplicação...

```shell
uvicorn main:app
```

## Dependências

Starlette só necessita da `anyio`, e todas as outras dependências são opcionais.

* [`httpx`][httpx] - Necessária se você for usar `TestClient`.
* [`jinja2`][jinja2] - Necessária se você for usar `Jinja2Templates`.
* [`python-multipart`][python-multipart] - Necessário se você deseja oferecer suporte à formulários, com `request.form()`.
* [`itsdangerous`][itsdangerous] - Necessária se você for suportar `SessionMiddleware`.
* [`pyyaml`][pyyaml] - Necessária para o suporte à `SchemaGenerator`.

Você pode instalar todas elas com: `pip install starlette[full]`.

## Framework e Ferramentas

Starlette is designed to be used either as a complete framework, or as
an ASGI toolkit. You can use any of its components independently.

```python title="main.py"
from starlette.responses import PlainTextResponse


async def app(scope, receive, send):
    assert scope['type'] == 'http'
    response = PlainTextResponse('Hello, world!')
    await response(scope, receive, send)
```

Run the `app` application in `main.py`:

```shell
$ uvicorn main:app
INFO: Started server process [11509]
INFO: Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Run uvicorn with `--reload` to enable auto-reloading on code changes.

## Modularity

The modularity that Starlette is designed on promotes building re-usable
components that can be shared between any ASGI framework. This should enable
an ecosystem of shared middleware and mountable applications.

The clean API separation also means it's easier to understand each component
in isolation.

---

<p align="center"><i>Starlette is <a href="https://github.com/Kludex/starlette/blob/main/LICENSE.md">BSD licensed</a> code.<br/>Designed & crafted with care.</i></br>&mdash; ⭐️ &mdash;</p>

[asgi]: https://asgi.readthedocs.io/en/latest/
[httpx]: https://www.python-httpx.org/
[jinja2]: https://jinja.palletsprojects.com/
[python-multipart]: https://multipart.fastapiexpert.com/
[itsdangerous]: https://itsdangerous.palletsprojects.com/
[sqlalchemy]: https://www.sqlalchemy.org
[pyyaml]: https://pyyaml.org/wiki/PyYAMLDocumentation
[techempower]: https://www.techempower.com/benchmarks/#hw=ph&test=fortune&l=zijzen-sf
