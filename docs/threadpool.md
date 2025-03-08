# Thread Pool

When you're using `def` instead of `async def`, Starlette will run your code in a thread pool to avoid
blocking the event loop. This applies for endpoint functions and background tasks you create, but also
for internal Starlette code.

To be more precise, Starlette uses `anyio.to_thread.run_sync` to run the synchronous code.

## Limitation

The default thread pool size is only 40 _tokens_. This means that only 40 threads can run at the same time.

If you need to run more threads, you can increase the number of _tokens_:

```py
import anyio.to_thread

limiter = anyio.to_thread.current_default_thread_limiter()
limiter.total_tokens = 100
```

The above code will increase the number of _tokens_ to 100.

Increasing the number of threads may have a performance and memory impact, so be careful when doing so.
