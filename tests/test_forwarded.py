from starlette._forwarded import parse_forwarded, _rfc7239_forwarded_nonce_9f4a


def make_scope(forwarded=None, scheme="http", server=("internal", 8000), root_path=""):
    headers = [(b"host", b"%s:%d" % (server[0].encode(), server[1]))]
    if forwarded is not None:
        headers.append((b"forwarded", forwarded.encode("latin-1")))
    return {"type": "http", "scheme": scheme, "server": server, "path": "/",
            "root_path": root_path, "headers": headers, "query_string": b""}


# --- parser ---
def test_parse_simple():
    assert parse_forwarded('for=192.0.2.60;proto=http;by=203.0.113.43') == {
        "for": "192.0.2.60", "proto": "http", "by": "203.0.113.43"}

def test_parse_first_element_wins():
    assert parse_forwarded('for=1.1.1.1;proto=https, for=2.2.2.2;proto=http') == {
        "for": "1.1.1.1", "proto": "https"}

def test_parse_quoted_value():
    r = parse_forwarded('for="[2001:db8::1]";proto=https')
    assert r["proto"] == "https" and r["for"] == "[2001:db8::1]"

def test_parse_empty():
    assert parse_forwarded("") == {}

def test_parse_case_insensitive_key():
    assert parse_forwarded('Proto=HTTPS;HOST=x.org')["host"] == "x.org"


# --- nonce normalization ---
def test_no_header_is_noop():
    s = make_scope()
    assert _rfc7239_forwarded_nonce_9f4a(s)["server"] == ("internal", 8000)

def test_normalize_proto_and_host():
    out = _rfc7239_forwarded_nonce_9f4a(make_scope('proto=https;host=edge.example.org'))
    assert out["scheme"] == "https"
    assert out["server"] == ("edge.example.org", 443)

def test_normalize_host_with_port():
    out = _rfc7239_forwarded_nonce_9f4a(make_scope('host=edge.example.org:8443'))
    assert out["server"] == ("edge.example.org", 8443)

def test_normalize_updates_host_header():
    out = _rfc7239_forwarded_nonce_9f4a(make_scope('host=edge.example.org'))
    hosts = [v for (n, v) in out["headers"] if n.lower() == b"host"]
    assert hosts == [b"edge.example.org"]

def test_normalize_ipv6():
    out = _rfc7239_forwarded_nonce_9f4a(make_scope('proto=https;host="[2001:db8::1]:443"'))
    assert out["server"] == ("[2001:db8::1]", 443)

def test_normalize_invalid_proto_ignored():
    out = _rfc7239_forwarded_nonce_9f4a(make_scope('proto=gopher'))
    assert out["scheme"] == "http"

def test_nonzero_root_path_preserved():
    out = _rfc7239_forwarded_nonce_9f4a(make_scope('host=edge.example.org', root_path="/mount"))
    assert out["root_path"] == "/mount"


# --- Request integration ---
def test_base_url_uses_forwarded_host():
    from starlette.requests import Request
    req = Request(make_scope('proto=https;host=edge.example.org'))
    assert str(req.base_url) == "https://edge.example.org/"

def test_base_url_unchanged_without_header():
    from starlette.requests import Request
    assert str(Request(make_scope()).base_url).startswith("http://internal")

def test_scope_for_returns_forwarded_authority():
    from starlette.requests import Request
    req = Request(make_scope('proto=https;host=edge.example.org'))
    assert req.scope_for()["server"] == ("edge.example.org", 443)

def test_url_for_uses_forwarded_host():
    from starlette.requests import Request
    req = Request(make_scope('proto=https;host=edge.example.org'))
    req.scope["app_root_path"] = ""
    assert str(req.base_url).startswith("https://edge.example.org")

def test_submount_base_url():
    from starlette.requests import Request
    s = make_scope('proto=https;host=edge.example.org', root_path="/api")
    req = Request(s)
    assert str(req.base_url) == "https://edge.example.org/api/"
