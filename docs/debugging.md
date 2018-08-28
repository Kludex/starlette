
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


<p align="center">&mdash; ⭐️ &mdash;</p>
<p align="center"><i>Starlette is <a href="https://github.com/tomchristie/starlette/blob/master/LICENSE.md">BSD licensed</a> code. Designed & built in Brighton, England.</i></p>
