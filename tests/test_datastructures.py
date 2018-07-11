from starlette.datastructures import Headers, MutableHeaders, QueryParams, URL


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


def test_headers():
    h = Headers([(b"a", b"123"), (b"a", b"456"), (b"b", b"789")])
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
    assert list(h) == [("a", "123"), ("a", "456"), ("b", "789")]
    assert dict(h) == {"a": "123", "b": "789"}
    assert repr(h) == "Headers([('a', '123'), ('a', '456'), ('b', '789')])"
    assert h == Headers([(b"a", b"123"), (b"b", b"789"), (b"a", b"456")])
    assert h != [(b"a", b"123"), (b"A", b"456"), (b"b", b"789")]


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


def test_queryparams():
    q = QueryParams([("a", "123"), ("a", "456"), ("b", "789")])
    assert "a" in q
    assert "A" not in q
    assert "c" not in q
    assert q["a"] == "123"
    assert q.get("a") == "123"
    assert q.get("nope", default=None) is None
    assert q.getlist("a") == ["123", "456"]
    assert q.keys() == ["a", "a", "b"]
    assert q.values() == ["123", "456", "789"]
    assert q.items() == [("a", "123"), ("a", "456"), ("b", "789")]
    assert list(q) == [("a", "123"), ("a", "456"), ("b", "789")]
    assert dict(q) == {"a": "123", "b": "789"}
    assert repr(q) == "QueryParams([('a', '123'), ('a', '456'), ('b', '789')])"
    assert QueryParams({"a": "123", "b": "456"}) == QueryParams(
        [("a", "123"), ("b", "456")]
    )
    assert QueryParams({"a": "123", "b": "456"}) == {"b": "456", "a": "123"}
    assert QueryParams({"a": "123", "b": "456"}) == [("b", "456"), ("a", "123")]
    assert {"b": "456", "a": "123"} == QueryParams({"a": "123", "b": "456"})
    assert [("b", "456"), ("a", "123")] == QueryParams({"a": "123", "b": "456"})
    assert QueryParams() == {}
