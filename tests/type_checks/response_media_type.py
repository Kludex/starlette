"""Regression for https://github.com/Kludex/starlette/issues/3754.

Checked with ``mypy --allow-redefinition-new`` via ``scripts/check``.
"""

from starlette.responses import HTMLResponse, PlainTextResponse, Response


class CustomResponse(Response):
    media_type = "application/custom"


def _accept_media_type(media_type: str | None) -> None:
    pass


_accept_media_type(Response.media_type)

# Built-in subclasses rely on ``Response.media_type`` being ``str | None``.
assert HTMLResponse.media_type == "text/html"
assert PlainTextResponse.media_type == "text/plain"
assert CustomResponse.media_type == "application/custom"
