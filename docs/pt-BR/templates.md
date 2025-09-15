Starlette is not _strictly_ coupled to any particular templating engine, but
Jinja2 provides an excellent choice.

### Jinja2Templates

Signature: `Jinja2Templates(directory, context_processors=None, **env_options)`

* `directory` - A string, [os.Pathlike][pathlike] or a list of strings or [os.Pathlike][pathlike] denoting a directory path.
* `context_processors` - A list of functions that return a dictionary to add to the template context.
* `**env_options` - Additional keyword arguments to pass to the Jinja2 environment.

Starlette provides a simple way to get `jinja2` configured. This is probably
what you want to use by default.

```python
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.templating import Jinja2Templates
from starlette.staticfiles import StaticFiles


templates = Jinja2Templates(directory='templates')

async def homepage(request):
    return templates.TemplateResponse(request, 'index.html')

routes = [
    Route('/', endpoint=homepage),
    Mount('/static', StaticFiles(directory='static'), name='static')
]

app = Starlette(debug=True, routes=routes)
```

Note that the incoming `request` instance must be included as part of the
template context.

The Jinja2 template context will automatically include a `url_for` function,
so we can correctly hyperlink to other pages within the application.

For example, we can link to static files from within our HTML templates:

```html
<link href="{{ url_for('static', path='/css/bootstrap.min.css') }}" rel="stylesheet" />
```

If you want to use [custom filters][jinja2], you will need to update the `env`
property of `Jinja2Templates`:

```python
from commonmark import commonmark
from starlette.templating import Jinja2Templates

def marked_filter(text):
    return commonmark(text)

templates = Jinja2Templates(directory='templates')
templates.env.filters['marked'] = marked_filter
```


## Using custom jinja2.Environment instance

Starlette also accepts a preconfigured [`jinja2.Environment`](https://jinja.palletsprojects.com/en/3.0.x/api/#api) instance. 


```python
import jinja2
from starlette.templating import Jinja2Templates

env = jinja2.Environment(...)
templates = Jinja2Templates(env=env)
```


## Context processors

A context processor is a function that returns a dictionary to be merged into a template context.
Every function takes only one argument `request` and must return a dictionary to add to the context.

A common use case of template processors is to extend the template context with shared variables.

```python
import typing
from starlette.requests import Request

def app_context(request: Request) -> typing.Dict[str, typing.Any]:
    return {'app': request.app}
```

### Registering context templates

Pass context processors to `context_processors` argument of the `Jinja2Templates` class.

```python
import typing

from starlette.requests import Request
from starlette.templating import Jinja2Templates

def app_context(request: Request) -> typing.Dict[str, typing.Any]:
    return {'app': request.app}

templates = Jinja2Templates(
    directory='templates', context_processors=[app_context]
)
```

!!! info
    Asynchronous functions as context processors are not supported.

## Testing template responses

When using the test client, template responses include `.template` and `.context`
attributes.

```python
from starlette.testclient import TestClient


def test_homepage():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.template.name == 'index.html'
    assert "request" in response.context
```

## Customizing Jinja2 Environment

`Jinja2Templates` accepts all options supported by Jinja2 `Environment`.
This will allow more control over the `Environment` instance created by Starlette.

For the list of options available to `Environment` you can check Jinja2 documentation [here](https://jinja.palletsprojects.com/en/3.0.x/api/#jinja2.Environment)

```python
from starlette.templating import Jinja2Templates


templates = Jinja2Templates(directory='templates', autoescape=False, auto_reload=True)
```

## Asynchronous template rendering

Jinja2 supports async template rendering, however as a general rule
we'd recommend that you keep your templates free from logic that invokes
database lookups, or other I/O operations.

Instead we'd recommend that you ensure that your endpoints perform all I/O,
for example, strictly evaluate any database queries within the view and
include the final results in the context.

[jinja2]: https://jinja.palletsprojects.com/en/3.0.x/api/?highlight=environment#writing-filters
[pathlike]: https://docs.python.org/3/library/os.html#os.PathLike
