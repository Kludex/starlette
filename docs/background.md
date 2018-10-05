
Starlette includes a `BackgroundTask` class for in-process background tasks.

A background task should be attached to a response, and will run only once
the response has been sent.

### Background Task

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
