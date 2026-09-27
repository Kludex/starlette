from starlette.requests import Request

def test_url_no_netloc():
    scope = {
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
