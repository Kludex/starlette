
Starlette includes a `Router` class which is an ASGI application that
dispatches incoming requests to endpoints or submounted applications.

```python
from starlette.routing import Mount, Route, Router
from myproject import Homepage, SubMountedApp


app = Router([
    Route('/', endpoint=Homepage, methods=['GET']),
    Mount('/mount', app=SubMountedApp)
])
```

Paths can use URI templating style to capture path components.

```python
Route('/users/{username}', endpoint=User, methods=['GET'])
```

Convertors for `int`, `float`, and `path` are also available:

```python
Route('/users/{user_id:int}', endpoint=User, methods=['GET'])
```

Path parameters are made available in the request, as the `request.path_params`
dictionary.

Because the target of a `Mount` is an ASGI instance itself, routers
allow for easy composition. For example:

```python
app = Router([
    Route('/', endpoint=Homepage, methods=['GET']),
    Mount('/users', app=Router([
        Route('/', endpoint=Users, methods=['GET', 'POST']),
        Route('/{username}', endpoint=User, methods=['GET']),
    ]))
])
```

The router will respond with "404 Not found" or "405 Method not allowed"
responses for requests which do not match.
