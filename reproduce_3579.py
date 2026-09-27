from starlette.requests import Request
from starlette.responses import RedirectResponse

scope = {
    "type": "http",
    "scheme": "http",
    "path": "//evil.example/x",
    "query_string": b"a=1",
    "headers": [],
    "server": None,
}

url = Request(scope).url
print(str(url), url.netloc)
print(RedirectResponse(url).headers["location"])
