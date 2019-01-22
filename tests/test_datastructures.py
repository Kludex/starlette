import io

from starlette.datastructures import (
    URL,
    CommaSeparatedStrings,
    DatabaseURL,
    FormData,
    Headers,
    MutableHeaders,
    QueryParams,
)


def test_url():
    u = URL("https://example.org:123/path/to/somewhere?abc=123#anchor")
    assert u.scheme == "https"
    assert u.hostname == "example.org"
    assert u.port == 123
    assert u.netloc == "example.org:123"
    assert u.username is None
    assert u.password is None
    assert u.path == "/path/to/somewhere"
    assert u.query == "abc=123"
    assert u.params == ""
    assert u.fragment == "anchor"

    new = u.replace(scheme="http")
    assert new == "http://example.org:123/path/to/somewhere?abc=123#anchor"
    assert new.scheme == "http"

    new = u.replace(port=None)
    assert new == "https://example.org/path/to/somewhere?abc=123#anchor"
    assert new.port is None

    new = u.replace(hostname="example.com")
    assert new == "https://example.com:123/path/to/somewhere?abc=123#anchor"
    assert new.hostname == "example.com"


def test_hidden_password():
    u = URL("https://example.org/path/to/somewhere")
    assert repr(u) == "URL('https://example.org/path/to/somewhere')"

    u = URL("https://username@example.org/path/to/somewhere")
    assert repr(u) == "URL('https://username@example.org/path/to/somewhere')"

    u = URL("https://username:password@example.org/path/to/somewhere")
    assert repr(u) == "URL('https://username:********@example.org/path/to/somewhere')"


def test_database_url():
    u = DatabaseURL("postgresql://username:password@localhost/mydatabase")
    u = u.replace(database="test_" + u.database)
    assert u.database == "test_mydatabase"
    assert str(u) == "postgresql://username:password@localhost/test_mydatabase"

    u = DatabaseURL("postgresql://localhost/mydatabase")
    assert u.dialect == "postgresql"
    assert u.driver == ""

    u = DatabaseURL("postgresql+asyncpg://localhost/mydatabase")
    assert u.dialect == "postgresql"
    assert u.driver == "asyncpg"


def test_csv():
    csv = CommaSeparatedStrings('"localhost", "127.0.0.1", 0.0.0.0')
    assert list(csv) == ["localhost", "127.0.0.1", "0.0.0.0"]
    assert repr(csv) == "CommaSeparatedStrings(['localhost', '127.0.0.1', '0.0.0.0'])"
    assert str(csv) == "'localhost', '127.0.0.1', '0.0.0.0'"
    assert csv[0] == "localhost"
    assert len(csv) == 3

    csv = CommaSeparatedStrings("'localhost', '127.0.0.1', 0.0.0.0")
    assert list(csv) == ["localhost", "127.0.0.1", "0.0.0.0"]
    assert repr(csv) == "CommaSeparatedStrings(['localhost', '127.0.0.1', '0.0.0.0'])"
    assert str(csv) == "'localhost', '127.0.0.1', '0.0.0.0'"

    csv = CommaSeparatedStrings("localhost, 127.0.0.1, 0.0.0.0")
    assert list(csv) == ["localhost", "127.0.0.1", "0.0.0.0"]
    assert repr(csv) == "CommaSeparatedStrings(['localhost', '127.0.0.1', '0.0.0.0'])"
    assert str(csv) == "'localhost', '127.0.0.1', '0.0.0.0'"

    csv = CommaSeparatedStrings(["localhost", "127.0.0.1", "0.0.0.0"])
    assert list(csv) == ["localhost", "127.0.0.1", "0.0.0.0"]
    assert repr(csv) == "CommaSeparatedStrings(['localhost', '127.0.0.1', '0.0.0.0'])"
    assert str(csv) == "'localhost', '127.0.0.1', '0.0.0.0'"


def test_url_from_scope():
    u = URL(
        scope={"path": "/path/to/somewhere", "query_string": b"abc=123", "headers": []}
    )
    assert u == "/path/to/somewhere?abc=123"
    assert repr(u) == "URL('/path/to/somewhere?abc=123')"

    u = URL(
        scope={
            "scheme": "https",
            "server": ("example.org", 123),
            "path": "/path/to/somewhere",
            "query_string": b"abc=123",
            "headers": [],
        }
    )
    assert u == "https://example.org:123/path/to/somewhere?abc=123"
    assert repr(u) == "URL('https://example.org:123/path/to/somewhere?abc=123')"

    u = URL(
        scope={
            "scheme": "https",
            "server": ("example.org", 443),
            "path": "/path/to/somewhere",
            "query_string": b"abc=123",
            "headers": [],
        }
    )
    assert u == "https://example.org/path/to/somewhere?abc=123"
    assert repr(u) == "URL('https://example.org/path/to/somewhere?abc=123')"


def test_headers():
    h = Headers(raw=[(b"a", b"123"), (b"a", b"456"), (b"b", b"789")])
    assert "a" in h
    assert "A" in h
    assert "b" in h
    assert "B" in h
    assert "c" not in h
    assert h["a"] == "123"
    assert h.get("a") == "123"
    assert h.get("nope", default=None) is None
    assert h.getlist("a") == ["123", "456"]
    assert h.keys() == ["a", "a", "b"]
    assert h.values() == ["123", "456", "789"]
    assert h.items() == [("a", "123"), ("a", "456"), ("b", "789")]
    assert list(h) == ["a", "a", "b"]
    assert dict(h) == {"a": "123", "b": "789"}
    assert repr(h) == "Headers(raw=[(b'a', b'123'), (b'a', b'456'), (b'b', b'789')])"
    assert h == Headers(raw=[(b"a", b"123"), (b"b", b"789"), (b"a", b"456")])
    assert h != [(b"a", b"123"), (b"A", b"456"), (b"b", b"789")]

    h = Headers({"a": "123", "b": "789"})
    assert h["A"] == "123"
    assert h["B"] == "789"
    assert h.raw == [(b"a", b"123"), (b"b", b"789")]
    assert repr(h) == "Headers({'a': '123', 'b': '789'})"


def test_mutable_headers():
    h = MutableHeaders()
    assert dict(h) == {}
    h["a"] = "1"
    assert dict(h) == {"a": "1"}
    h["a"] = "2"
    assert dict(h) == {"a": "2"}
    h.setdefault("a", "3")
    assert dict(h) == {"a": "2"}
    h.setdefault("b", "4")
    assert dict(h) == {"a": "2", "b": "4"}
    del h["a"]
    assert dict(h) == {"b": "4"}
    assert h.raw == [(b"b", b"4")]


def test_headers_mutablecopy():
    h = Headers(raw=[(b"a", b"123"), (b"a", b"456"), (b"b", b"789")])
    c = h.mutablecopy()
    assert c.items() == [("a", "123"), ("a", "456"), ("b", "789")]
    c["a"] = "abc"
    assert c.items() == [("a", "abc"), ("b", "789")]


def test_queryparams():
    q = QueryParams(query_string="a=123&a=456&b=789")
    assert "a" in q
    assert "A" not in q
    assert "c" not in q
    assert q["a"] == "456"
    assert q.get("a") == "456"
    assert q.get("nope", default=None) is None
    assert q.getlist("a") == ["123", "456"]
    assert q.keys() == ["a", "b"]
    assert q.values() == ["456", "789"]
    assert q.items() == [("a", "456"), ("b", "789")]
    assert len(q) == 2
    assert list(q) == ["a", "b"]
    assert dict(q) == {"a": "456", "b": "789"}
    assert str(q) == "a=123&a=456&b=789"
    assert repr(q) == "QueryParams(query_string='a=123&a=456&b=789')"
    assert QueryParams({"a": "123", "b": "456"}) == QueryParams(
        items=[("a", "123"), ("b", "456")]
    )
    assert QueryParams({"a": "123", "b": "456"}) == QueryParams(
        query_string="a=123&b=456"
    )
    assert QueryParams({"a": "123", "b": "456"}) == QueryParams(
        {"b": "456", "a": "123"}
    )
    assert QueryParams() == QueryParams({})
    assert QueryParams(items=[("a", "123"), ("a", "456")]) == QueryParams(
        query_string="a=123&a=456"
    )
    assert QueryParams({"a": "123", "b": "456"}) != "invalid"

    q = QueryParams(items=[("a", "123"), ("a", "456")])
    assert QueryParams(q) == q


def test_formdata():
    upload = io.BytesIO(b"test")
    form = FormData(items=[("a", "123"), ("a", "456"), ("b", upload)])
    assert "a" in form
    assert "A" not in form
    assert "c" not in form
    assert form["a"] == "456"
    assert form.get("a") == "456"
    assert form.get("nope", default=None) is None
    assert form.getlist("a") == ["123", "456"]
    assert form.keys() == ["a", "b"]
    assert form.values() == ["456", upload]
    assert form.items() == [("a", "456"), ("b", upload)]
    assert len(form) == 2
    assert list(form) == ["a", "b"]
    assert dict(form) == {"a": "456", "b": upload}
    assert (
        repr(form)
        == "FormData(items=[('a', '123'), ('a', '456'), ('b', " + repr(upload) + ")])"
    )
    assert FormData(form) == form
    assert FormData({"a": "123", "b": "789"}) == FormData(
        items=[("a", "123"), ("b", "789")]
    )
    assert FormData({"a": "123", "b": "789"}) != {"a": "123", "b": "789"}
