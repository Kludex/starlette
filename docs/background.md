
Starlette includes a `BackgroundTask` class for in-process background tasks.

A background task should be attached to a response, and will run only once
the response has been sent.

### Background Task

Used to add a single background task to a response.

Signature: `BackgroundTask(func, *args, **kwargs)`

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.background import BackgroundTask

app = Starlette()

@app.route('/user/signup', methods=['POST'])
async def signup(request):
    data = await request.json()
    username = data['username']
    email = data['email']
    task = BackgroundTask(send_welcome_email, to_address=email)
    message = {'status': 'Signup successful'}
    return JSONResponse(message, background=task)

async def send_welcome_email(to_address):
    ...
```

### BackgroundTasks

Used to add multiple background tasks to a response.

Signature: `BackgroundTasks(tasks=[])`

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.background import BackgroundTasks

app = Starlette()

@app.route('/user/signup', methods=['POST'])
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

```
