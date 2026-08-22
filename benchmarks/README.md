# Benchmarks

## Minimal response dispatch

The response benchmark measures a two-byte response through progressively larger
parts of the public stack: raw ASGI, a prebuilt `Response`, a newly constructed
`Response`, a single `Route`, and a complete `Starlette` application. The raw
ASGI case is the control for event-loop and message-capture overhead.

Each dispatch receives a fresh ASGI scope. The application cases are warmed
before measurement so lazy middleware construction and interpreter specialization
are not attributed to every request.

Run it locally with:

```console
uv run pytest benchmarks/response_benchmark.py --codspeed
```

## Request bodies

The request benchmark compares `Request.body()` with `Request.stream()` for
1 KiB, 1 MiB, and 10 MiB payloads. The larger payloads are delivered both as a
single ASGI message and in 64 KiB chunks to separate byte volume from
per-message overhead.

Payload and chunk construction happen outside the measured region. Every
dispatch creates a fresh `Request`, ASGI scope, and receive callable. The
response reports the consumed byte count, which is validated after measurement.

Run it locally with:

```console
uv run pytest benchmarks/request_benchmark.py --codspeed
```

## Routing

The routing benchmark exercises `Router` dispatch through its ASGI interface
against a synthetic REST-style route table (120 routes as 30 resource groups
of four routes each, plus a 20-route variant for small applications).

The scenarios pin down the cases that scale differently with table size:
a static hit on an early route, a static and a parameterized hit on the last
routes, a full miss, and a wrong-method request (`405`). Each measured call
dispatches one request through the router, with a fresh ASGI scope built per
dispatch so CodSpeed warmup runs cannot pollute the measured one; response
status is validated on the benchmark's return value, outside the measured
region.

Run it locally with:

```console
uv run pytest benchmarks/routing_benchmark.py --codspeed
```

## GZip

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

The responsiveness benchmark schedules a 10 MiB JSON response immediately
before a tiny response that bypasses compression. CodSpeed measures the work
needed for the tiny response to complete, then drains and validates the large
response outside the measured region. This provides a stable CPU-simulation
benchmark for detecting event-loop starvation without relying on wall-clock
timing or concurrent request storms. The existing `json-10MiB-level-9`
compression case separately measures the large response's total completion.
