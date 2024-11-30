from __future__ import annotations

import sys
from typing import Any, Iterator

import anyio
import pytest

from starlette.datastructures import URL, Address, State
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
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
        async for chunk in request.stream():
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
