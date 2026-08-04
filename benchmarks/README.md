# Benchmarks

The gzip benchmark exercises Starlette's `GZipResponder` with deterministic
payloads representing valid JSON, repetitive text, and incompressible bytes.

It compares levels 1 through 9 at 1 MiB. It also compares representative levels
1, 6, and 9 at 32 KiB, 256 KiB, 5 MiB, and 10 MiB. This keeps the suite useful
for detecting payload-size regressions without running the full Cartesian
product of every level and large size.

Run it locally with:

```console
uv run pytest benchmarks/gzip_benchmark.py --codspeed
```

Payload construction and decompression validation are outside the measured
region. Each case creates only one input payload, so the largest case does not
leave all benchmark inputs resident in memory. CodSpeed CI records simulated
CPU performance, peak heap usage, and allocation counts.
