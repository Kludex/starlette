import typing

from starlette.requests import Request
from starlette.responses import RedirectResponse


def test_url_with_double_slash_path_without_netloc_stays_path_relative() -> None:
    scope: dict[str, typing.Any] = {
        "type": "http",
        "scheme": "http",
        "path": "//evil.example/x",
        "query_string": b"a=1",
        "headers": [],
        "server": None,
    }
    url = Request(scope).url
    assert url.netloc == ""
    assert url.path == "/%2Fevil.example/x"
    assert str(url) == "/%2Fevil.example/x?a=1"
    assert RedirectResponse(url).headers["location"] == "/%2Fevil.example/x?a=1"
