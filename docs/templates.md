Starlette is not *strictly* coupled to any particular templating engine, but
Jinja2 provides an excellent choice.

Starlette provides a simple way to get `jinja2` configured. This is probably
what you want to use by default.

```python
from starlette.applications import Starlette
from starlette.templating import Jinja2Templates


templates = Jinja2Templates(directory='templates')

app = Starlette(debug=True)
app.mount('/static', StaticFiles(directory='statics'), name='static')


@app.route('/')
async def homepage(request):
    return templates.TemplateResponse('index.html', {'request': request})
```

The Jinja2 environment sets up a global `url_for` included, which allows us to
use `url_for` inside our templates. We always need to pass the incoming `request`
instance as part of the template context.

We can now link to static files from within our HTML templates. For example:

```html
<link href="{{ url_for('static', path='/css/bootstrap.min.css') }}" rel="stylesheet">
```

## Testing template responses

When using the test client, template responses include `.template` and `.context`
attributes.

```python
def test_homepage():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.template.name == 'index.html'
    assert "request" in response.context
```

## Asynchronous template rendering

Jinja2 supports async template rendering, however as a general rule
we'd recommend that you keep your templates free from logic that invokes
database lookups, or other I/O operations.

Instead we'd recommend that you ensure that your views perform all I/O,
for example, strictly evaluate any database queries within the view and
include the final results in the context.
