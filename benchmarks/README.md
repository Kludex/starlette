# Benchmarks

The gzip benchmark exercises Starlette's `GZipMiddleware` through its ASGI
interface with deterministic payloads representing valid JSON, repetitive
text, and incompressible bytes.

It compares levels 1 through 9 at 1 MiB. It also compares representative levels
1, 6, and 9 at 32 KiB, 256 KiB, 5 MiB, and 10 MiB. This keeps the suite useful
for detecting payload-size regressions without running the full Cartesian
product of every level and large size.

Run it locally with:

```console
uv run pytest benchmarks/gzip_benchmark.py --codspeed
```

Payload construction, middleware configuration, and decompression validation
are outside the measured region. The measured call includes responder
construction, fresh mutable ASGI message containers, header handling,
compression, and resource cleanup. Recreating the message containers prevents
CodSpeed warmups from mutating the response used by the measured invocation.
Each case creates only one input payload, so the largest case does not leave all
benchmark inputs resident in memory. CodSpeed CI records simulated CPU
performance, peak heap usage, and allocation counts.

The end-to-end bypass benchmarks run the complete `GZipMiddleware` ASGI path
for responses below `minimum_size`, responses with an existing
`Content-Encoding`, `text/event-stream` responses, and
`http.response.pathsend`. Their response payloads are also constructed outside
the measured region, isolating middleware allocation overhead.
