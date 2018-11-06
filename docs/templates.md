Starlette is not coupled to any particular templating engine, but Jinja2
provides an excellent choice.

Here we're going to take a look at a complete example of how you can configure
a Jinja2 environment together with Starlette.

```python
from starlette.applications import Starlette
from starlette.staticfiles import StaticFiles
from starlette.responses import HTMLResponse


def setup_jinja2(template_dir):
    @jinja2.contextfunction
    def url_for(context, name, **path_params):
        request = context['request']
        return request.url_for(name, **path_params)

    loader = jinja2.FileSystemLoader(template_dir)
    env = jinja2.Environment(loader=loader, autoescape=True)
    env.globals['url_for'] = url_for
    return env


env = setup_jinja2('templates')
app = Starlette(debug=True)
app.mount('/static', StaticFiles(directory='statics'), name='static')


@app.route('/')
async def homepage(request):
    template = env.get_template('index.html')
    content = template.render(request=request)
    return HTMLResponse(content)
```

The important parts to note from the above example are:

* The StaticFiles app has been mounted with `name='static'`, meaning we can use `app.url_path_for('static', path=...)` or `request.url_for('static', path=...)`.
* The Jinja2 environment has a global `url_for` included, which allows us to use `url_for`
inside our templates. We always need to pass the incoming `request` instance
in our context in order to be able to use the `url_for` function.

We can now link to static files from within our HTML templates. For example:

```html
<link href="{{ url_for('static', path='/css/bootstrap.min.css') }}" rel="stylesheet">
```

## Asynchronous template rendering

Jinja2 supports async template rendering, however as a general rule
we'd recommend that you keep your templates free from logic that invokes
database lookups, or other I/O operations.

Instead we'd recommend that you ensure that your views perform all I/O,
for example, strictly evaluate any database queries within the view and
include the final results in the context.
