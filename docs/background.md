
Starlette includes a `BackgroundTask` class for tasks that do not need to be completed before the response is sent.

### Background Task

Signature: `BackgroundTask(func, *args, **kwargs)

```python
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.background import BackgroundTask
from email.mime.text import MIMEText

app = Starlette()

@app.route('/user/signup', methods=['POST'])
async def create_new_user(request):
    user = await request.json()
    # Do stuff here
    task = BackgroundTask(send_welcome_email, user)
    return JSONResponse(
        {'msg': 'User successfully created'},
        background=task
    )

async def send_welcome_email(info):
    # Do stuff here
    message = MIMEText(f"Thank you for registering, {info['name']}")
    message['To'] = info['email']
    await send_message(message)
```