from __future__ import annotations

import sys
from collections.abc import Iterator
from typing import Any

import anyio
import pytest

from starlette.applications import Starlette
from starlette.datastructures import URL, Address, State, UploadFile
from starlette.exceptions import HTTPException
from starlette.formparsers import MultiPartSizeException
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route
from starlette.types import Message, Receive, Scope, Send
from tests.types import TestClientFactory


def test_request_url(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        data = {"method": request.method, "url": str(request.url)}
        response = JSONResponse(data)
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/123?a=abc")
    assert response.json() == {"method": "GET", "url": "http://testserver/123?a=abc"}

    response = client.get("https://example.org:123/")
    assert response.json() == {"method": "GET", "url": "https://example.org:123/"}


def test_request_query_params(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        params = dict(request.query_params)
        response = JSONResponse({"params": params})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/?a=123&b=456")
    assert response.json() == {"params": {"a": "123", "b": "456"}}


@pytest.mark.skipif(
    any(module in sys.modules for module in ("brotli", "brotlicffi")),
    reason='urllib3 includes "br" to the "accept-encoding" headers.',
)
def test_request_headers(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        headers = dict(request.headers)
        response = JSONResponse({"headers": headers})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/", headers={"host": "example.org"})
    assert response.json() == {
        "headers": {
            "host": "example.org",
            "user-agent": "testclient",
            "accept-encoding": "gzip, deflate",
            "accept": "*/*",
            "connection": "keep-alive",
        }
    }


@pytest.mark.parametrize(
    "scope,expected_client",
    [
        ({"client": ["client", 42]}, Address("client", 42)),
        ({"client": None}, None),
        ({}, None),
    ],
)
def test_request_client(scope: Scope, expected_client: Address | None) -> None:
    scope.update({"type": "http"})  # required by Request's constructor
    client = Request(scope).client
    assert client == expected_client


def test_request_body(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        body = await request.body()
        response = JSONResponse({"body": body.decode()})
        await response(scope, receive, send)

    client = test_client_factory(app)

    response = client.get("/")
    assert response.json() == {"body": ""}

    response = client.post("/", json={"a": "123"})
    assert response.json() == {"body": '{"a":"123"}'}

    response = client.post("/", data="abc")  # type: ignore
    assert response.json() == {"body": "abc"}


def test_request_stream(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        body = b""
        async for chunk in request.stream():
            body += chunk
        response = JSONResponse({"body": body.decode()})
        await response(scope, receive, send)

    client = test_client_factory(app)

    response = client.get("/")
    assert response.json() == {"body": ""}

    response = client.post("/", json={"a": "123"})
    assert response.json() == {"body": '{"a":"123"}'}

    response = client.post("/", data="abc")  # type: ignore
    assert response.json() == {"body": "abc"}


def test_request_form_urlencoded(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        form = await request.form()
        response = JSONResponse({"form": dict(form)})
        await response(scope, receive, send)

    client = test_client_factory(app)

    response = client.post("/", data={"abc": "123 @"})
    assert response.json() == {"form": {"abc": "123 @"}}


def test_request_form_context_manager(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        async with request.form() as form:
            response = JSONResponse({"form": dict(form)})
            await response(scope, receive, send)

    client = test_client_factory(app)

    response = client.post("/", data={"abc": "123 @"})
    assert response.json() == {"form": {"abc": "123 @"}}


def test_request_body_then_stream(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        body = await request.body()
        chunks = b""
        async for chunk in request.stream():
            chunks += chunk
        response = JSONResponse({"body": body.decode(), "stream": chunks.decode()})
        await response(scope, receive, send)

    client = test_client_factory(app)

    response = client.post("/", data="abc")  # type: ignore
    assert response.json() == {"body": "abc", "stream": "abc"}


def test_request_stream_then_body(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        chunks = b""
        async for chunk in request.stream():  # pragma: no branch
            chunks += chunk
        try:
            body = await request.body()
        except RuntimeError:
            body = b"<stream consumed>"
        response = JSONResponse({"body": body.decode(), "stream": chunks.decode()})
        await response(scope, receive, send)

    client = test_client_factory(app)

    response = client.post("/", data="abc")  # type: ignore
    assert response.json() == {"body": "<stream consumed>", "stream": "abc"}


def test_request_json(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        data = await request.json()
        response = JSONResponse({"json": data})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.post("/", json={"a": "123"})
    assert response.json() == {"json": {"a": "123"}}


def test_request_scope_interface() -> None:
    """
    A Request can be instantiated with a scope, and presents a `Mapping`
    interface.
    """
    request = Request({"type": "http", "method": "GET", "path": "/abc/"})
    assert request["method"] == "GET"
    assert dict(request) == {"type": "http", "method": "GET", "path": "/abc/"}
    assert len(request) == 3


def test_request_raw_path(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        path = request.scope["path"]
        raw_path = request.scope["raw_path"]
        response = PlainTextResponse(f"{path}, {raw_path}")
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/he%2Fllo")
    assert response.text == "/he/llo, b'/he%2Fllo'"


def test_request_without_setting_receive(
    test_client_factory: TestClientFactory,
) -> None:
    """
    If Request is instantiated without the receive channel, then .body()
    is not available.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope)
        try:
            data = await request.json()
        except RuntimeError:
            data = "Receive channel not available"
        response = JSONResponse({"json": data})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.post("/", json={"a": "123"})
    assert response.json() == {"json": "Receive channel not available"}


def test_request_disconnect(
    anyio_backend_name: str,
    anyio_backend_options: dict[str, Any],
) -> None:
    """
    If a client disconnect occurs while reading request body
    then ClientDisconnect should be raised.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        await request.body()

    async def receiver() -> Message:
        return {"type": "http.disconnect"}

    scope = {"type": "http", "method": "POST", "path": "/"}
    with pytest.raises(ClientDisconnect):
        anyio.run(
            app,  # type: ignore
            scope,
            receiver,
            None,
            backend=anyio_backend_name,
            backend_options=anyio_backend_options,
        )


def test_request_is_disconnected(test_client_factory: TestClientFactory) -> None:
    """
    If a client disconnect occurs after reading request body
    then request will be set disconnected properly.
    """
    disconnected_after_response = None

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        nonlocal disconnected_after_response

        request = Request(scope, receive)
        body = await request.body()
        disconnected = await request.is_disconnected()
        response = JSONResponse({"body": body.decode(), "disconnected": disconnected})
        await response(scope, receive, send)
        disconnected_after_response = await request.is_disconnected()

    client = test_client_factory(app)
    response = client.post("/", content="foo")
    assert response.json() == {"body": "foo", "disconnected": False}
    assert disconnected_after_response


def test_request_state_object() -> None:
    scope = {"state": {"old": "foo"}}

    s = State(scope["state"])

    s.new = "value"
    assert s.new == "value"

    del s.new

    with pytest.raises(AttributeError):
        s.new

    # Test dictionary-style methods
    # Test __setitem__
    s["dict_key"] = "dict_value"
    assert s["dict_key"] == "dict_value"
    assert s.dict_key == "dict_value"

    # Test __iter__
    s["another_key"] = "another_value"
    keys = list(s)
    assert "old" in keys
    assert "dict_key" in keys
    assert "another_key" in keys

    # Test __len__
    assert len(s) == 3

    # Test __delitem__
    del s["dict_key"]
    assert len(s) == 2
    with pytest.raises(KeyError):
        s["dict_key"]


def test_request_state(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        request.state.example = 123
        response = JSONResponse({"state.example": request.state.example})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/123?a=abc")
    assert response.json() == {"state.example": 123}


def test_request_cookies(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        mycookie = request.cookies.get("mycookie")
        if mycookie:
            response = Response(mycookie, media_type="text/plain")
        else:
            response = Response("Hello, world!", media_type="text/plain")
            response.set_cookie("mycookie", "Hello, cookies!")

        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.text == "Hello, world!"
    response = client.get("/")
    assert response.text == "Hello, cookies!"


def test_cookie_lenient_parsing(test_client_factory: TestClientFactory) -> None:
    """
    The following test is based on a cookie set by Okta, a well-known authorization
    service. It turns out that it's common practice to set cookies that would be
    invalid according to the spec.
    """
    tough_cookie = (
        "provider-oauth-nonce=validAsciiblabla; "
        'okta-oauth-redirect-params={"responseType":"code","state":"somestate",'
        '"nonce":"somenonce","scopes":["openid","profile","email","phone"],'
        '"urls":{"issuer":"https://subdomain.okta.com/oauth2/authServer",'
        '"authorizeUrl":"https://subdomain.okta.com/oauth2/authServer/v1/authorize",'
        '"userinfoUrl":"https://subdomain.okta.com/oauth2/authServer/v1/userinfo"}}; '
        "importantCookie=importantValue; sessionCookie=importantSessionValue"
    )
    expected_keys = {
        "importantCookie",
        "okta-oauth-redirect-params",
        "provider-oauth-nonce",
        "sessionCookie",
    }

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        response = JSONResponse({"cookies": request.cookies})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/", headers={"cookie": tough_cookie})
    result = response.json()
    assert len(result["cookies"]) == 4
    assert set(result["cookies"].keys()) == expected_keys


# These test cases copied from Tornado's implementation
@pytest.mark.parametrize(
    "set_cookie,expected",
    [
        ("chips=ahoy; vienna=finger", {"chips": "ahoy", "vienna": "finger"}),
        # all semicolons are delimiters, even within quotes
        (
            'keebler="E=mc2; L=\\"Loves\\"; fudge=\\012;"',
            {"keebler": '"E=mc2', "L": '\\"Loves\\"', "fudge": "\\012", "": '"'},
        ),
        # Illegal cookies that have an '=' char in an unquoted value.
        ("keebler=E=mc2", {"keebler": "E=mc2"}),
        # Cookies with ':' character in their name.
        ("key:term=value:term", {"key:term": "value:term"}),
        # Cookies with '[' and ']'.
        ("a=b; c=[; d=r; f=h", {"a": "b", "c": "[", "d": "r", "f": "h"}),
        # Cookies that RFC6265 allows.
        ("a=b; Domain=example.com", {"a": "b", "Domain": "example.com"}),
        # parse_cookie() keeps only the last cookie with the same name.
        ("a=b; h=i; a=c", {"a": "c", "h": "i"}),
    ],
)
def test_cookies_edge_cases(
    set_cookie: str,
    expected: dict[str, str],
    test_client_factory: TestClientFactory,
) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        response = JSONResponse({"cookies": request.cookies})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/", headers={"cookie": set_cookie})
    result = response.json()
    assert result["cookies"] == expected


@pytest.mark.parametrize(
    "set_cookie,expected",
    [
        # Chunks without an equals sign appear as unnamed values per
        # https://bugzilla.mozilla.org/show_bug.cgi?id=169091
        (
            "abc=def; unnamed; django_language=en",
            {"": "unnamed", "abc": "def", "django_language": "en"},
        ),
        # Even a double quote may be an unamed value.
        ('a=b; "; c=d', {"a": "b", "": '"', "c": "d"}),
        # Spaces in names and values, and an equals sign in values.
        ("a b c=d e = f; gh=i", {"a b c": "d e = f", "gh": "i"}),
        # More characters the spec forbids.
        ('a   b,c<>@:/[]?{}=d  "  =e,f g', {"a   b,c<>@:/[]?{}": 'd  "  =e,f g'}),
        # Unicode characters. The spec only allows ASCII.
        # ("saint=André Bessette", {"saint": "André Bessette"}),
        # Browsers don't send extra whitespace or semicolons in Cookie headers,
        # but cookie_parser() should parse whitespace the same way
        # document.cookie parses whitespace.
        ("  =  b  ;  ;  =  ;   c  =  ;  ", {"": "b", "c": ""}),
    ],
)
def test_cookies_invalid(
    set_cookie: str,
    expected: dict[str, str],
    test_client_factory: TestClientFactory,
) -> None:
    """
    Cookie strings that are against the RFC6265 spec but which browsers will send if set
    via document.cookie.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        response = JSONResponse({"cookies": request.cookies})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/", headers={"cookie": set_cookie})
    result = response.json()
    assert result["cookies"] == expected


def test_multiple_cookie_headers(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        scope["headers"] = [(b"cookie", b"a=abc"), (b"cookie", b"b=def"), (b"cookie", b"c=ghi")]
        request = Request(scope, receive)
        response = JSONResponse({"cookies": request.cookies})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    result = response.json()
    assert result["cookies"] == {"a": "abc", "b": "def", "c": "ghi"}


def test_chunked_encoding(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        body = await request.body()
        response = JSONResponse({"body": body.decode()})
        await response(scope, receive, send)

    client = test_client_factory(app)

    def post_body() -> Iterator[bytes]:
        yield b"foo"
        yield b"bar"

    response = client.post("/", data=post_body())  # type: ignore
    assert response.json() == {"body": "foobar"}


def test_request_send_push_promise(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        # the server is push-enabled
        scope["extensions"]["http.response.push"] = {}

        request = Request(scope, receive, send)
        await request.send_push_promise("/style.css")

        response = JSONResponse({"json": "OK"})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.json() == {"json": "OK"}


def test_request_send_push_promise_without_push_extension(
    test_client_factory: TestClientFactory,
) -> None:
    """
    If server does not support the `http.response.push` extension,
    .send_push_promise() does nothing.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope)
        await request.send_push_promise("/style.css")

        response = JSONResponse({"json": "OK"})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.json() == {"json": "OK"}


def test_request_send_push_promise_without_setting_send(
    test_client_factory: TestClientFactory,
) -> None:
    """
    If Request is instantiated without the send channel, then
    .send_push_promise() is not available.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        # the server is push-enabled
        scope["extensions"]["http.response.push"] = {}

        data = "OK"
        request = Request(scope)
        try:
            await request.send_push_promise("/style.css")
        except RuntimeError:
            data = "Send channel not available"
        response = JSONResponse({"json": data})
        await response(scope, receive, send)

    client = test_client_factory(app)
    response = client.get("/")
    assert response.json() == {"json": "Send channel not available"}


@pytest.mark.parametrize(
    "messages",
    [
        [{"body": b"123", "more_body": True}, {"body": b""}],
        [{"body": b"", "more_body": True}, {"body": b"123"}],
        [{"body": b"12", "more_body": True}, {"body": b"3"}],
        [
            {"body": b"123", "more_body": True},
            {"body": b"", "more_body": True},
            {"body": b""},
        ],
    ],
)
@pytest.mark.anyio
async def test_request_rcv(messages: list[Message]) -> None:
    messages = messages.copy()

    async def rcv() -> Message:
        return {"type": "http.request", **messages.pop(0)}

    request = Request({"type": "http"}, rcv)

    body = await request.body()

    assert body == b"123"


@pytest.mark.anyio
async def test_request_stream_called_twice() -> None:
    messages: list[Message] = [
        {"type": "http.request", "body": b"1", "more_body": True},
        {"type": "http.request", "body": b"2", "more_body": True},
        {"type": "http.request", "body": b"3"},
    ]

    async def rcv() -> Message:
        return messages.pop(0)

    request = Request({"type": "http"}, rcv)

    s1 = request.stream()
    s2 = request.stream()

    msg = await s1.__anext__()
    assert msg == b"1"

    msg = await s2.__anext__()
    assert msg == b"2"

    msg = await s1.__anext__()
    assert msg == b"3"

    # at this point we've consumed the entire body
    # so we should not wait for more body (which would hang us forever)
    msg = await s1.__anext__()
    assert msg == b""
    msg = await s2.__anext__()
    assert msg == b""

    # and now both streams are exhausted
    with pytest.raises(StopAsyncIteration):
        assert await s2.__anext__()
    with pytest.raises(StopAsyncIteration):
        await s1.__anext__()


def test_request_url_outside_starlette_context(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        request.url_for("index")

    client = test_client_factory(app)
    with pytest.raises(
        RuntimeError,
        match="The `url_for` method can only be used inside a Starlette application or with a router.",
    ):
        client.get("/")


def test_request_url_starlette_context(test_client_factory: TestClientFactory) -> None:
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.routing import Route
    from starlette.types import ASGIApp

    url_for = None

    async def homepage(request: Request) -> Response:
        return PlainTextResponse("Hello, world!")

    class CustomMiddleware:
        def __init__(self, app: ASGIApp) -> None:
            self.app = app

        async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
            nonlocal url_for
            request = Request(scope, receive)
            url_for = request.url_for("homepage")
            await self.app(scope, receive, send)

    app = Starlette(routes=[Route("/home", homepage)], middleware=[Middleware(CustomMiddleware)])

    client = test_client_factory(app)
    client.get("/home")
    assert url_for == URL("http://testserver/home")


def test_request_stream_max_body_size_via_route(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        body = b""
        async for chunk in request.stream():
            body += chunk
        return JSONResponse({"body": body.decode()})

    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_body_size=10)])
    client = test_client_factory(app)

    # Body within limit should work
    response = client.post("/", data="abc")  # type: ignore
    assert response.json() == {"body": "abc"}

    # Body exceeding limit should return 413
    response = client.post("/", data="a" * 100)  # type: ignore
    assert response.status_code == 413


def test_request_stream_max_body_size_content_length_via_route(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        body = b""
        async for chunk in request.stream():
            body += chunk  # pragma: no cover
        return JSONResponse({"body": body.decode()})  # pragma: no cover

    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_body_size=10)])
    client = test_client_factory(app)

    # Content-Length exceeding limit should return 413 without reading the body
    response = client.post("/", content="a" * 100)
    assert response.status_code == 413


def test_request_body_max_body_size_via_route(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"body": body.decode()})

    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_body_size=10)])
    client = test_client_factory(app)

    # Body within limit should work
    response = client.post("/", data="abc")  # type: ignore
    assert response.json() == {"body": "abc"}

    # Body exceeding limit should return 413
    response = client.post("/", data="a" * 100)  # type: ignore
    assert response.status_code == 413


def test_request_json_max_body_size_via_route(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        data = await request.json()
        return JSONResponse(data)

    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_body_size=50)])
    client = test_client_factory(app)

    # Body within limit should work
    response = client.post("/", json={"a": "123"})
    assert response.json() == {"a": "123"}

    # Body exceeding limit should return 413
    response = client.post("/", json={"a": "x" * 100})
    assert response.status_code == 413


def test_request_form_urlencoded_max_body_size_via_route(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        form = await request.form()
        return JSONResponse({"form": dict(form)})

    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_body_size=10)])
    client = test_client_factory(app)

    # Small form within limit should work
    response = client.post("/", data={"a": "1"})
    assert response.json() == {"form": {"a": "1"}}

    # Large form exceeding limit should return 413
    response = client.post("/", data={"abc": "x" * 100})
    assert response.status_code == 413


def test_request_max_body_size_via_starlette(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"body": body.decode()})

    app = Starlette(
        routes=[Route("/", endpoint=endpoint, methods=["POST"])],
        max_body_size=10,
    )
    client = test_client_factory(app)

    # Body within limit should work
    response = client.post("/", data="abc")  # type: ignore
    assert response.json() == {"body": "abc"}

    # Body exceeding limit should return 413
    response = client.post("/", data="a" * 100)  # type: ignore
    assert response.status_code == 413


def test_request_max_body_size_via_mount(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"body": body.decode()})

    app = Starlette(
        routes=[
            Mount(
                "/api",
                routes=[Route("/upload", endpoint=endpoint, methods=["POST"])],
                max_body_size=10,
            )
        ]
    )
    client = test_client_factory(app)

    # Body within limit should work
    response = client.post("/api/upload", data="abc")  # type: ignore
    assert response.json() == {"body": "abc"}

    # Body exceeding limit should return 413
    response = client.post("/api/upload", data="a" * 100)  # type: ignore
    assert response.status_code == 413


def test_request_max_body_size_route_overrides_router(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"body": body.decode()})

    app = Starlette(
        routes=[
            Route("/small", endpoint=endpoint, methods=["POST"], max_body_size=5),
            Route("/large", endpoint=endpoint, methods=["POST"]),
        ],
        max_body_size=1000,
    )
    client = test_client_factory(app)

    # /small route has its own max_body_size=5, should override router's 1000
    response = client.post("/small", data="a" * 10)  # type: ignore
    assert response.status_code == 413

    # /large route uses router's max_body_size=1000
    response = client.post("/large", data="a" * 10)  # type: ignore
    assert response.json() == {"body": "a" * 10}


def test_request_max_body_size_in_scope(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        scope["max_body_size"] = 10
        request = Request(scope, receive)
        try:
            body = b""
            async for chunk in request.stream():
                body += chunk
            response = JSONResponse({"body": body.decode()})
        except HTTPException as exc:
            response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        await response(scope, receive, send)

    client = test_client_factory(app)

    # Body within limit should work
    response = client.post("/", data="abc")  # type: ignore
    assert response.json() == {"body": "abc"}

    # Body exceeding limit should return 413
    response = client.post("/", data="a" * 100)  # type: ignore
    assert response.status_code == 413
    assert response.json() == {"detail": "Content Too Large"}


def test_request_body_max_body_size_cached_body(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        # First call without max_body_size caches the body
        await request.body()
        # Now set it in scope and call again -- should check the cached body
        scope["max_body_size"] = 5
        try:
            await request.body()
            response = JSONResponse({"status": "ok"})  # pragma: no cover
        except HTTPException as exc:
            response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        await response(scope, receive, send)

    client = test_client_factory(app)

    # Body exceeding limit should return 413 even when cached
    response = client.post("/", data="a" * 100)  # type: ignore
    assert response.status_code == 413
    assert response.json() == {"detail": "Content Too Large"}


def test_request_stream_max_body_size_cached_body(test_client_factory: TestClientFactory) -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        request = Request(scope, receive)
        # First call caches the body
        await request.body()
        # Now set max_body_size in scope and call stream()
        scope["max_body_size"] = 5
        try:
            chunks = b""
            async for chunk in request.stream():
                chunks += chunk  # pragma: no cover
            response = JSONResponse({"body": chunks.decode()})  # pragma: no cover
        except HTTPException as exc:
            response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        await response(scope, receive, send)

    client = test_client_factory(app)

    # Body exceeding limit should return 413 even when cached
    response = client.post("/", data="a" * 100)  # type: ignore
    assert response.status_code == 413
    assert response.json() == {"detail": "Content Too Large"}


@pytest.mark.anyio
async def test_request_stream_max_body_size_no_content_length() -> None:
    messages: list[Message] = [
        {"type": "http.request", "body": b"a" * 20, "more_body": True},
        {"type": "http.request", "body": b"b" * 20},
    ]

    async def rcv() -> Message:
        return messages.pop(0)

    # No content-length header, max_body_size set in scope
    request = Request({"type": "http", "headers": [], "max_body_size": 10}, rcv)
    with pytest.raises(HTTPException) as exc_info:
        async for _ in request.stream():
            pass  # pragma: no cover
    assert exc_info.value.status_code == 413


@pytest.mark.anyio
async def test_request_stream_max_body_size_cached_no_content_length() -> None:
    messages: list[Message] = [
        {"type": "http.request", "body": b"a" * 20},
    ]

    async def rcv() -> Message:
        return messages.pop(0)

    # No content-length header, no max_body_size yet
    request = Request({"type": "http", "headers": []}, rcv)
    # Cache the body first
    await request.body()
    # Now set max_body_size in scope and stream should check the cached body
    request.scope["max_body_size"] = 10
    with pytest.raises(HTTPException) as exc_info:
        async for _ in request.stream():
            pass  # pragma: no cover
    assert exc_info.value.status_code == 413


@pytest.mark.anyio
async def test_request_stream_max_body_size_bogus_content_length() -> None:
    messages: list[Message] = [
        {"type": "http.request", "body": b"abc"},
    ]

    async def rcv() -> Message:
        return messages.pop(0)

    request = Request({"type": "http", "headers": [(b"content-length", b"bogus")], "max_body_size": 100}, rcv)
    body = b""
    async for chunk in request.stream():
        body += chunk
    assert body == b"abc"


def test_request_max_upload_size_via_route(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        async with request.form() as form:
            file = form["file"]
            assert isinstance(file, UploadFile)
            content = await file.read()
        return JSONResponse({"size": len(content)})

    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_upload_size=10)])
    client = test_client_factory(app)

    # Small file within limit should work
    response = client.post("/", files={"file": ("small.txt", b"abc")})
    assert response.json() == {"size": 3}

    # File exceeding limit should return 413
    response = client.post("/", files={"file": ("large.txt", b"a" * 100)})
    assert response.status_code == 413


def test_request_max_upload_size_multiple_files(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        async with request.form() as form:
            total = 0
            for key in form:
                upload_file = form[key]
                assert isinstance(upload_file, UploadFile)
                content = await upload_file.read()
                total += len(content)
        return JSONResponse({"total": total})

    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_upload_size=50)])
    client = test_client_factory(app)

    # Multiple small files within total limit should work
    response = client.post("/", files=[("f1", ("a.txt", b"a" * 10)), ("f2", ("b.txt", b"b" * 10))])
    assert response.json() == {"total": 20}

    # Multiple files exceeding total limit should return 413
    response = client.post("/", files=[("f1", ("a.txt", b"a" * 30)), ("f2", ("b.txt", b"b" * 30))])
    assert response.status_code == 413


def test_request_max_upload_size_via_starlette(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        async with request.form() as form:
            file = form["file"]
            assert isinstance(file, UploadFile)
            content = await file.read()
        return JSONResponse({"size": len(content)})

    app = Starlette(
        routes=[Route("/", endpoint=endpoint, methods=["POST"])],
        max_upload_size=10,
    )
    client = test_client_factory(app)

    # Small file within limit should work
    response = client.post("/", files={"file": ("small.txt", b"abc")})
    assert response.json() == {"size": 3}

    # File exceeding limit should return 413
    response = client.post("/", files={"file": ("large.txt", b"a" * 100)})
    assert response.status_code == 413


def test_request_max_upload_size_via_mount(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        async with request.form() as form:
            file = form["file"]
            assert isinstance(file, UploadFile)
            content = await file.read()
        return JSONResponse({"size": len(content)})

    app = Starlette(
        routes=[
            Mount(
                "/api",
                routes=[Route("/upload", endpoint=endpoint, methods=["POST"])],
                max_upload_size=10,
            )
        ]
    )
    client = test_client_factory(app)

    # Small file within limit should work
    response = client.post("/api/upload", files={"file": ("small.txt", b"abc")})
    assert response.json() == {"size": 3}

    # File exceeding limit should return 413
    response = client.post("/api/upload", files={"file": ("large.txt", b"a" * 100)})
    assert response.status_code == 413


def test_request_max_body_size_does_not_affect_multipart(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        async with request.form() as form:
            file = form["file"]
            assert isinstance(file, UploadFile)
            content = await file.read()
        return JSONResponse({"size": len(content)})

    # max_body_size=10 should NOT block a multipart upload of 100 bytes
    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_body_size=10)])
    client = test_client_factory(app)

    response = client.post("/", files={"file": ("file.txt", b"a" * 100)})
    assert response.status_code == 200
    assert response.json() == {"size": 100}


def test_request_max_upload_size_does_not_affect_body(test_client_factory: TestClientFactory) -> None:
    async def endpoint(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"size": len(body)})

    # max_upload_size=10 should NOT block a regular body of 100 bytes
    app = Starlette(routes=[Route("/", endpoint=endpoint, methods=["POST"], max_upload_size=10)])
    client = test_client_factory(app)

    response = client.post("/", data="a" * 100)  # type: ignore
    assert response.status_code == 200
    assert response.json() == {"size": 100}


def test_request_max_body_size_and_max_upload_size_together(test_client_factory: TestClientFactory) -> None:
    async def body_endpoint(request: Request) -> Response:
        body = await request.body()
        return JSONResponse({"size": len(body)})

    async def upload_endpoint(request: Request) -> Response:
        async with request.form() as form:
            file = form["file"]
            assert isinstance(file, UploadFile)
            content = await file.read()
        return JSONResponse({"size": len(content)})

    app = Starlette(
        routes=[
            Route("/body", endpoint=body_endpoint, methods=["POST"]),
            Route("/upload", endpoint=upload_endpoint, methods=["POST"]),
        ],
        max_body_size=10,
        max_upload_size=1000,
    )
    client = test_client_factory(app)

    # Regular body within max_body_size should work
    response = client.post("/body", data="abc")  # type: ignore
    assert response.status_code == 200
    assert response.json() == {"size": 3}

    # Regular body over max_body_size should be rejected
    response = client.post("/body", data="a" * 100)  # type: ignore
    assert response.status_code == 413

    # File upload within max_upload_size should work (not limited by max_body_size)
    response = client.post("/upload", files={"file": ("file.txt", b"a" * 100)})
    assert response.status_code == 200
    assert response.json() == {"size": 100}

    # File upload over max_upload_size should be rejected
    response = client.post("/upload", files={"file": ("file.txt", b"a" * 2000)})
    assert response.status_code == 413


@pytest.mark.anyio
async def test_request_max_upload_size_outside_app_context() -> None:
    """MultiPartSizeException is raised directly when not inside a Starlette app."""

    async def receive() -> Message:
        boundary = b"--testboundary"
        body = (
            boundary + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="big.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\n"
            + b"a" * 100 + b"\r\n"
            + boundary + b"--\r\n"
        )
        return {"type": "http.request", "body": body}

    scope: Scope = {
        "type": "http",
        "method": "POST",
        "headers": [(b"content-type", b"multipart/form-data; boundary=testboundary")],
        "max_upload_size": 10,
    }
    request = Request(scope, receive)
    with pytest.raises(MultiPartSizeException):
        await request.form()
