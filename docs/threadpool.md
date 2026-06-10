# Thread Pool

Starlette uses a thread pool in several scenarios to avoid blocking the event loop:

- When you create a synchronous endpoint using `def` instead of `async def`
- When serving files with [`FileResponse`](responses.md#fileresponse)
- When handling file uploads with [`UploadFile`](requests.md#request-files)
- When running synchronous background tasks with [`BackgroundTask`](background.md)
- And some other scenarios that may not be documented...

Starlette will run your code in a thread pool to avoid blocking the event loop.
This applies for endpoint functions and background tasks you create, but also for internal Starlette code.

To be more precise, Starlette uses `anyio.to_thread.run_sync` to run the synchronous code.

## Concurrency Limitations

The default thread pool size is only 40 _tokens_. This means that only 40 threads can run at the same time.
This limit is shared with other libraries: for example FastAPI also uses `anyio` to run sync dependencies, which also uses up thread capacity.

If you need to run more threads, you can increase the number of _tokens_:

```py
import anyio.to_thread

limiter = anyio.to_thread.current_default_thread_limiter()
limiter.total_tokens = 100
```

The above code will increase the number of _tokens_ to 100.

Increasing the number of threads may have a performance and memory impact, so be careful when doing so.
