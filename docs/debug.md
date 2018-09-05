
You can use Starlette's `DebugMiddleware` to display simple error tracebacks in the browser.

```python
from starlette.debug import DebugMiddleware


class App:
    def __init__(self, scope):
        self.scope = scope

    async def __call__(self, receive, send):
        raise RuntimeError('Something went wrong')


app = DebugMiddleware(App)
```

For a mode complete handling of exception cases you may wish to use Starlette's
[`ExceptionMiddleware`](../exceptions/) class instead, which also includes
optional debug handling.
