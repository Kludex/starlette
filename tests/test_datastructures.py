import io
from tempfile import SpooledTemporaryFile
from typing import BinaryIO

import pytest

from starlette.datastructures import (
    URL,
    CommaSeparatedStrings,
    FormData,
    Headers,
    MultiDict,
    MutableHeaders,
    QueryParams,
    UploadFile,
)


def test_url() -> None:
    u = URL("https://example.org:123/path/to/somewhere?abc=123#anchor")
    assert u.scheme == "https"
    assert u.hostname == "example.org"
    assert u.port == 123
    assert u.netloc == "example.org:123"
    assert u.username is None
    assert u.password is None
    assert u.path == "/path/to/somewhere"
    assert u.query == "abc=123"
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

    ipv6_url = URL("https://[fe::2]:12345")
    new = ipv6_url.replace(port=8080)
    assert new == "https://[fe::2]:8080"

    new = ipv6_url.replace(username="username", password="password")
    assert new == "https://username:password@[fe::2]:12345"
    assert new.netloc == "username:password@[fe::2]:12345"

    ipv6_url = URL("https://[fe::2]")
    new = ipv6_url.replace(port=123)
    assert new == "https://[fe::2]:123"

    url = URL("http://u:p@host/")
    assert url.replace(hostname="bar") == URL("http://u:p@bar/")

    url = URL("http://u:p@host:80")
    assert url.replace(port=88) == URL("http://u:p@host:88")

    url = URL("http://host:80")
    assert url.replace(username="u") == URL("http://u@host:80")


def test_url_query_params() -> None:
    u = URL("https://example.org/path/?page=3")
    assert u.query == "page=3"
    u = u.include_query_params(page=4)
    assert str(u) == "https://example.org/path/?page=4"
    u = u.include_query_params(search="testing")
    assert str(u) == "https://example.org/path/?page=4&search=testing"
    u = u.replace_query_params(order="name")
    assert str(u) == "https://example.org/path/?order=name"
    u = u.remove_query_params("order")
    assert str(u) == "https://example.org/path/"
    u = u.include_query_params(page=4, search="testing")
    assert str(u) == "https://example.org/path/?page=4&search=testing"
    u = u.remove_query_params(["page", "search"])
    assert str(u) == "https://example.org/path/"


def test_hidden_password() -> None:
    u = URL("https://example.org/path/to/somewhere")
    assert repr(u) == "URL('https://example.org/path/to/somewhere')"

    u = URL("https://username@example.org/path/to/somewhere")
    assert repr(u) == "URL('https://username@example.org/path/to/somewhere')"

    u = URL("https://username:password@example.org/path/to/somewhere")
    assert repr(u) == "URL('https://username:********@example.org/path/to/somewhere')"


def test_csv() -> None:
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


def test_url_from_scope() -> None:
    u = URL(scope={"path": "/path/to/somewhere", "query_string": b"abc=123", "headers": []})
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

    u = URL(
        scope={
            "scheme": "http",
            "path": "/some/path",
            "query_string": b"query=string",
            "headers": [
                (b"content-type", b"text/html"),
                (b"host", b"example.com:8000"),
                (b"accept", b"text/html"),
            ],
        }
    )
    assert u == "http://example.com:8000/some/path?query=string"
    assert repr(u) == "URL('http://example.com:8000/some/path?query=string')"


def test_headers() -> None:
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


def test_mutable_headers() -> None:
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


def test_mutable_headers_merge() -> None:
    h = MutableHeaders()
    h = h | MutableHeaders({"a": "1"})
    assert isinstance(h, MutableHeaders)
    assert dict(h) == {"a": "1"}
    assert h.items() == [("a", "1")]
    assert h.raw == [(b"a", b"1")]


def test_mutable_headers_merge_dict() -> None:
    h = MutableHeaders()
    h = h | {"a": "1"}
    assert isinstance(h, MutableHeaders)
    assert dict(h) == {"a": "1"}
    assert h.items() == [("a", "1")]
    assert h.raw == [(b"a", b"1")]


def test_mutable_headers_update() -> None:
    h = MutableHeaders()
    h |= MutableHeaders({"a": "1"})
    assert isinstance(h, MutableHeaders)
    assert dict(h) == {"a": "1"}
    assert h.items() == [("a", "1")]
    assert h.raw == [(b"a", b"1")]


def test_mutable_headers_update_dict() -> None:
    h = MutableHeaders()
    h |= {"a": "1"}
    assert isinstance(h, MutableHeaders)
    assert dict(h) == {"a": "1"}
    assert h.items() == [("a", "1")]
    assert h.raw == [(b"a", b"1")]


def test_mutable_headers_merge_not_mapping() -> None:
    h = MutableHeaders()
    with pytest.raises(TypeError):
        h |= {"not_mapping"}  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        h | {"not_mapping"}  # type: ignore[operator]


def test_headers_mutablecopy() -> None:
    h = Headers(raw=[(b"a", b"123"), (b"a", b"456"), (b"b", b"789")])
    c = h.mutablecopy()
    assert c.items() == [("a", "123"), ("a", "456"), ("b", "789")]
    c["a"] = "abc"
    assert c.items() == [("a", "abc"), ("b", "789")]


def test_mutable_headers_from_scope() -> None:
    # "headers" in scope must not necessarily be a list
    h = MutableHeaders(scope={"headers": ((b"a", b"1"),)})
    assert dict(h) == {"a": "1"}
    h.update({"b": "2"})
    assert dict(h) == {"a": "1", "b": "2"}
    assert list(h.items()) == [("a", "1"), ("b", "2")]
    assert list(h.raw) == [(b"a", b"1"), (b"b", b"2")]


def test_url_blank_params() -> None:
    q = QueryParams("a=123&abc&def&b=456")
    assert "a" in q
    assert "abc" in q
    assert "def" in q
    assert "b" in q
    val = q.get("abc")
    assert val is not None
    assert len(val) == 0
    assert len(q["a"]) == 3
    assert list(q.keys()) == ["a", "abc", "def", "b"]


def test_queryparams() -> None:
    q = QueryParams("a=123&a=456&b=789")
    assert "a" in q
    assert "A" not in q
    assert "c" not in q
    assert q["a"] == "456"
    assert q.get("a") == "456"
    assert q.get("nope", default=None) is None
    assert q.getlist("a") == ["123", "456"]
    assert list(q.keys()) == ["a", "b"]
    assert list(q.values()) == ["456", "789"]
    assert list(q.items()) == [("a", "456"), ("b", "789")]
    assert len(q) == 2
    assert list(q) == ["a", "b"]
    assert dict(q) == {"a": "456", "b": "789"}
    assert str(q) == "a=123&a=456&b=789"
    assert repr(q) == "QueryParams('a=123&a=456&b=789')"
    assert QueryParams({"a": "123", "b": "456"}) == QueryParams([("a", "123"), ("b", "456")])
    assert QueryParams({"a": "123", "b": "456"}) == QueryParams("a=123&b=456")
    assert QueryParams({"a": "123", "b": "456"}) == QueryParams({"b": "456", "a": "123"})
    assert QueryParams() == QueryParams({})
    assert QueryParams([("a", "123"), ("a", "456")]) == QueryParams("a=123&a=456")
    assert QueryParams({"a": "123", "b": "456"}) != "invalid"

    q = QueryParams([("a", "123"), ("a", "456")])
    assert QueryParams(q) == q


@pytest.mark.anyio
async def test_upload_file_file_input() -> None:
    """Test passing file/stream into the UploadFile constructor"""
    stream = io.BytesIO(b"data")
    file = UploadFile(filename="file", file=stream, size=4)
    assert await file.read() == b"data"
    assert file.size == 4
    await file.write(b" and more data!")
    assert await file.read() == b""
    assert file.size == 19
    await file.seek(0)
    assert await file.read() == b"data and more data!"


@pytest.mark.anyio
async def test_upload_file_without_size() -> None:
    """Test passing file/stream into the UploadFile constructor without size"""
    stream = io.BytesIO(b"data")
    file = UploadFile(filename="file", file=stream)
    assert await file.read() == b"data"
    assert file.size is None
    await file.write(b" and more data!")
    assert await file.read() == b""
    assert file.size is None
    await file.seek(0)
    assert await file.read() == b"data and more data!"


@pytest.mark.anyio
@pytest.mark.parametrize("max_size", [1, 1024], ids=["rolled", "unrolled"])
async def test_uploadfile_rolling(max_size: int) -> None:
    """Test that we can r/w to a SpooledTemporaryFile
    managed by UploadFile before and after it rolls to disk
    """
    stream: BinaryIO = SpooledTemporaryFile(  # type: ignore[assignment]
        max_size=max_size
    )
    file = UploadFile(filename="file", file=stream, size=0)
    assert await file.read() == b""
    assert file.size == 0
    await file.write(b"data")
    assert await file.read() == b""
    assert file.size == 4
    await file.seek(0)
    assert await file.read() == b"data"
    await file.write(b" more")
    assert await file.read() == b""
    assert file.size == 9
    await file.seek(0)
    assert await file.read() == b"data more"
    assert file.size == 9
    await file.close()


def test_formdata() -> None:
    stream = io.BytesIO(b"data")
    upload = UploadFile(filename="file", file=stream, size=4)
    form = FormData([("a", "123"), ("a", "456"), ("b", upload)])
    assert "a" in form
    assert "A" not in form
    assert "c" not in form
    assert form["a"] == "456"
    assert form.get("a") == "456"
    assert form.get("nope", default=None) is None
    assert form.getlist("a") == ["123", "456"]
    assert list(form.keys()) == ["a", "b"]
    assert list(form.values()) == ["456", upload]
    assert list(form.items()) == [("a", "456"), ("b", upload)]
    assert len(form) == 2
    assert list(form) == ["a", "b"]
    assert dict(form) == {"a": "456", "b": upload}
    assert repr(form) == "FormData([('a', '123'), ('a', '456'), ('b', " + repr(upload) + ")])"
    assert FormData(form) == form
    assert FormData({"a": "123", "b": "789"}) == FormData([("a", "123"), ("b", "789")])
    assert FormData({"a": "123", "b": "789"}) != {"a": "123", "b": "789"}


@pytest.mark.anyio
async def test_upload_file_repr() -> None:
    stream = io.BytesIO(b"data")
    file = UploadFile(filename="file", file=stream, size=4)
    assert repr(file) == "UploadFile(filename='file', size=4, headers=Headers({}))"


@pytest.mark.anyio
async def test_upload_file_repr_headers() -> None:
    stream = io.BytesIO(b"data")
    file = UploadFile(filename="file", file=stream, headers=Headers({"foo": "bar"}))
    assert repr(file) == "UploadFile(filename='file', size=None, headers=Headers({'foo': 'bar'}))"


def test_multidict() -> None:
    q = MultiDict([("a", "123"), ("a", "456"), ("b", "789")])
    assert "a" in q
    assert "A" not in q
    assert "c" not in q
    assert q["a"] == "456"
    assert q.get("a") == "456"
    assert q.get("nope", default=None) is None
    assert q.getlist("a") == ["123", "456"]
    assert list(q.keys()) == ["a", "b"]
    assert list(q.values()) == ["456", "789"]
    assert list(q.items()) == [("a", "456"), ("b", "789")]
    assert len(q) == 2
    assert list(q) == ["a", "b"]
    assert dict(q) == {"a": "456", "b": "789"}
    assert str(q) == "MultiDict([('a', '123'), ('a', '456'), ('b', '789')])"
    assert repr(q) == "MultiDict([('a', '123'), ('a', '456'), ('b', '789')])"
    assert MultiDict({"a": "123", "b": "456"}) == MultiDict([("a", "123"), ("b", "456")])
    assert MultiDict({"a": "123", "b": "456"}) == MultiDict({"b": "456", "a": "123"})
    assert MultiDict() == MultiDict({})
    assert MultiDict({"a": "123", "b": "456"}) != "invalid"

    q = MultiDict([("a", "123"), ("a", "456")])
    assert MultiDict(q) == q

    q = MultiDict([("a", "123"), ("a", "456")])
    q["a"] = "789"
    assert q["a"] == "789"
    assert q.get("a") == "789"
    assert q.getlist("a") == ["789"]

    q = MultiDict([("a", "123"), ("a", "456")])
    del q["a"]
    assert q.get("a") is None
    assert repr(q) == "MultiDict([])"

    q = MultiDict([("a", "123"), ("a", "456"), ("b", "789")])
    assert q.pop("a") == "456"
    assert q.get("a", None) is None
    assert repr(q) == "MultiDict([('b', '789')])"

    q = MultiDict([("a", "123"), ("a", "456"), ("b", "789")])
    item = q.popitem()
    assert q.get(item[0]) is None

    q = MultiDict([("a", "123"), ("a", "456"), ("b", "789")])
    assert q.poplist("a") == ["123", "456"]
    assert q.get("a") is None
    assert repr(q) == "MultiDict([('b', '789')])"

    q = MultiDict([("a", "123"), ("a", "456"), ("b", "789")])
    q.clear()
    assert q.get("a") is None
    assert repr(q) == "MultiDict([])"

    q = MultiDict([("a", "123")])
    q.setlist("a", ["456", "789"])
    assert q.getlist("a") == ["456", "789"]
    q.setlist("b", [])
    assert "b" not in q

    q = MultiDict([("a", "123")])
    assert q.setdefault("a", "456") == "123"
    assert q.getlist("a") == ["123"]
    assert q.setdefault("b", "456") == "456"
    assert q.getlist("b") == ["456"]
    assert repr(q) == "MultiDict([('a', '123'), ('b', '456')])"

    q = MultiDict([("a", "123")])
    q.append("a", "456")
    assert q.getlist("a") == ["123", "456"]
    assert repr(q) == "MultiDict([('a', '123'), ('a', '456')])"

    q = MultiDict([("a", "123"), ("b", "456")])
    q.update({"a": "789"})
    assert q.getlist("a") == ["789"]
    assert q == MultiDict([("a", "789"), ("b", "456")])

    q = MultiDict([("a", "123"), ("b", "456")])
    q.update(q)
    assert repr(q) == "MultiDict([('a', '123'), ('b', '456')])"

    q = MultiDict([("a", "123"), ("a", "456")])
    q.update([("a", "123")])
    assert q.getlist("a") == ["123"]
    q.update([("a", "456")], a="789", b="123")
    assert q == MultiDict([("a", "456"), ("a", "789"), ("b", "123")])
