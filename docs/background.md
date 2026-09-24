
Starlette includes a `BackgroundTask` class for in-process background tasks.

A background task should be attached to a response, and will run only once
the response has been sent.

### Background Task

Used to add a single background task to a response.

Signature: `BackgroundTask(func, *args, **kwargs)`

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.background import BackgroundTask


...

async def signup(request):
    data = await request.json()
    username = data['username']
    email = data['email']
    task = BackgroundTask(send_welcome_email, to_address=email)
    message = {'status': 'Signup successful'}
    return JSONResponse(message, background=task)

async def send_welcome_email(to_address):
    ...


routes = [
    ...
    Route('/user/signup', endpoint=signup, methods=['POST'])
]

app = Starlette(routes=routes)
```

### BackgroundTasks

Used to add multiple background tasks to a response.

Signature: `BackgroundTasks(tasks=[])`

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.background import BackgroundTasks

async def signup(request):
    data = await request.json()
    username = data['username']
    email = data['email']
    tasks = BackgroundTasks()
    tasks.add_task(send_welcome_email, to_address=email)
    tasks.add_task(send_admin_notification, username=username)
    message = {'status': 'Signup successful'}
    return JSONResponse(message, background=tasks)

async def send_welcome_email(to_address):
    ...

async def send_admin_notification(username):
    ...

routes = [
    Route('/user/signup', endpoint=signup, methods=['POST'])
]

app = Starlette(routes=routes)
```

!!! important
    The tasks are executed in order. In case one of the tasks raises
    an exception, the following tasks will not get the opportunity to be executed.

### Middleware and task execution

Starlette automatically installs `BackgroundTaskMiddleware` outside the middleware
you pass to `Starlette(middleware=...)`. If you wrap the application yourself,
place `BackgroundTaskMiddleware` outside wrappers that buffer or replace responses:

```python
from pathlib import Path

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware.background import BackgroundTaskMiddleware
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp


def record_request(path: Path) -> None:
    with path.open("a") as file:
        file.write("Request completed\n")


async def homepage(request: Request) -> Response:
    task = BackgroundTask(record_request, Path("requests.log"))
    return PlainTextResponse("Hello", background=task)


async def passthrough(request: Request, call_next: RequestResponseEndpoint) -> Response:
    return await call_next(request)


app: ASGIApp = Starlette(routes=[Route("/", homepage)])
app = BaseHTTPMiddleware(app, dispatch=passthrough)
app = BackgroundTaskMiddleware(app)
```

Responses register their tasks after their sends finish. The outermost
`BackgroundTaskMiddleware` collects tasks for the request and runs them after the
wrapped application returns. Mounted applications share this collection. This
keeps tasks from starting while an outer middleware is still forwarding the body.

Tasks run sequentially in registration order. Within a `BackgroundTasks` instance,
this is the order of your `add_task()` calls. Separate responses in concurrent
middleware can register their tasks in a different order.

The middleware still awaits the tasks before returning to the ASGI server. It
does not create a separate worker or guarantee that the client has received the
response. ASGI sends flush data into the server's send buffer.

!!! warning "Create resources inside background tasks"
    Tasks run after the inner middleware and endpoint cleanup have finished.
    Open resources such as database sessions inside the task. Do not pass resources
    that request cleanup will close. Context variable changes made inside
    `BaseHTTPMiddleware`'s inner task do not propagate to the task runner.

!!! important "Failures stop deferred work"
    If the wrapped application or a response send raises an exception, deferred
    tasks do not run. If a background task raises, the exception propagates and
    the remaining tasks do not run. An already sent response cannot be replaced
    by an error response.

When you use a response directly without `BackgroundTaskMiddleware`, it continues
to run its background task immediately after its own sends finish.
