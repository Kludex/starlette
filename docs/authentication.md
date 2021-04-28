Starlette offers a simple but powerful interface for handling authentication
and permissions. Once you've installed `AuthenticationMiddleware` with an
appropriate authentication backend the `request.user` and `request.auth`
interfaces will be available in your endpoints.


```python
from starlette.applications import Starlette
from starlette.authentication import (
    AuthenticationBackend, AuthenticationError, SimpleUser, UnauthenticatedUser,
    AuthCredentials
)
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
import base64
import binascii


class BasicAuthBackend(AuthenticationBackend):
    async def authenticate(self, request):
        if "Authorization" not in request.headers:
            return

        auth = request.headers["Authorization"]
        try:
            scheme, credentials = auth.split()
            if scheme.lower() != 'basic':
                return
            decoded = base64.b64decode(credentials).decode("ascii")
        except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
            raise AuthenticationError('Invalid basic auth credentials')

        username, _, password = decoded.partition(":")
        # TODO: You'd want to verify the username and password here.
        return AuthCredentials(["authenticated"]), SimpleUser(username)


async def homepage(request):
    if request.user.is_authenticated:
        return PlainTextResponse('Hello, ' + request.user.display_name)
    return PlainTextResponse('Hello, you')

routes = [
    Route("/", endpoint=homepage)
]

middleware = [
    Middleware(AuthenticationMiddleware, backend=BasicAuthBackend())
]

app = Starlette(routes=routes, middleware=middleware)
```

## Users

Once `AuthenticationMiddleware` is installed the `request.user` interface
will be available to endpoints or other middleware.

This interface should subclass `BaseUser`, which provides two properties,
as well as whatever other information your user model includes.

* `.is_authenticated`
* `.display_name`

Starlette provides two built-in user implementations: `UnauthenticatedUser()`,
and `SimpleUser(username)`.

## AuthCredentials

It is important that authentication credentials are treated as separate concept
from users. An authentication scheme should be able to restrict or grant
particular privileges independently of the user identity.

The `AuthCredentials` class provides the basic interface that `request.auth`
exposes:

* `.scopes`

## Permissions

Permissions are implemented as an endpoint decorator, that enforces that the
incoming request includes the required authentication scopes.

```python
from starlette.authentication import requires


@requires('authenticated')
async def dashboard(request):
    ...
```

You can include either one or multiple required scopes:

```python
from starlette.authentication import requires


@requires(['authenticated', 'admin'])
async def dashboard(request):
    ...
```

By default 403 responses will be returned when permissions are not granted.
In some cases you might want to customize this, for example to hide information
about the URL layout from unauthenticated users.

```python
from starlette.authentication import requires


@requires(['authenticated', 'admin'], status_code=404)
async def dashboard(request):
    ...
```

Alternatively you might want to redirect unauthenticated users to a different
page.

```python
from starlette.authentication import requires


async def homepage(request):
    ...


@requires('authenticated', redirect='homepage')
async def dashboard(request):
    ...
```

For class-based endpoints, you should wrap the decorator
around a method on the class.

```python
class Dashboard(HTTPEndpoint):
    @requires("authenticated")
    async def get(self, request):
        ...
```

## Custom authentication error responses

You can customise the error response sent when a `AuthenticationError` is
raised by an auth backend:

```python
def on_auth_error(request: Request, exc: Exception):
    return JSONResponse({"error": str(exc)}, status_code=401)

app.add_middleware(AuthenticationMiddleware, backend=BasicAuthBackend(), on_error=on_auth_error)
```
