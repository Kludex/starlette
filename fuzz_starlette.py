#!/usr/bin/env python3
"""Fuzz harness for Starlette — ASGI framework (9 GHSA advisories)."""
import sys
import atheris

with atheris.instrument_imports():
    from starlette.datastructures import URL, Headers, QueryParams


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # 1. URL parsing
    try:
        url_str = fdp.ConsumeString(256)
        URL(url_str)
    except Exception:
        pass

    # 2. Headers parsing
    try:
        items = [(fdp.ConsumeString(16), fdp.ConsumeString(64)) for _ in range(5)]
        Headers(items)
    except Exception:
        pass

    # 3. Query params
    try:
        qs = fdp.ConsumeString(128)
        QueryParams(qs)
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
