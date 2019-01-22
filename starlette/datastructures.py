import typing
from collections import namedtuple
from collections.abc import Sequence
from shlex import shlex
from urllib.parse import ParseResult, parse_qsl, urlencode, urlparse

from starlette.types import Scope

Address = namedtuple("Address", ["host", "port"])


class URL:
    def __init__(
        self, url: str = "", scope: Scope = None, **components: typing.Any
    ) -> None:
        if scope is not None:
            assert not url, 'Cannot set both "url" and "scope".'
            assert not components, 'Cannot set both "scope" and "**components".'
            scheme = scope.get("scheme", "http")
            server = scope.get("server", None)
            path = scope.get("root_path", "") + scope["path"]
            query_string = scope["query_string"]

            host_header = None
            for key, value in scope["headers"]:
                if key == b"host":
                    host_header = value.decode("latin-1")
                    break

            if host_header is not None:
                url = f"{scheme}://{host_header}{path}"
            elif server is None:
                url = path
            else:
                host, port = server
                default_port = {"http": 80, "https": 443, "ws": 80, "wss": 443}[scheme]
                if port == default_port:
                    url = f"{scheme}://{host}{path}"
                else:
                    url = f"{scheme}://{host}:{port}{path}"

            if query_string:
                url += "?" + query_string.decode()
        elif components:
            assert not url, 'Cannot set both "scope" and "**components".'
            url = URL("").replace(**components).components.geturl()

        self._url = url

    @property
    def components(self) -> ParseResult:
        if not hasattr(self, "_components"):
            self._components = urlparse(self._url)
        return self._components

    @property
    def scheme(self) -> str:
        return self.components.scheme

    @property
    def netloc(self) -> str:
        return self.components.netloc

    @property
    def path(self) -> str:
        return self.components.path

    @property
    def params(self) -> str:
        return self.components.params

    @property
    def query(self) -> str:
        return self.components.query

    @property
    def fragment(self) -> str:
        return self.components.fragment

    @property
    def username(self) -> typing.Union[None, str]:
        return self.components.username

    @property
    def password(self) -> typing.Union[None, str]:
        return self.components.password

    @property
    def hostname(self) -> typing.Union[None, str]:
        return self.components.hostname

    @property
    def port(self) -> typing.Optional[int]:
        return self.components.port

    @property
    def is_secure(self) -> bool:
        return self.scheme in ("https", "wss")

    def replace(self, **kwargs: typing.Any) -> "URL":
        if (
            "username" in kwargs
            or "password" in kwargs
            or "hostname" in kwargs
            or "port" in kwargs
        ):
            hostname = kwargs.pop("hostname", self.hostname)
            port = kwargs.pop("port", self.port)
            username = kwargs.pop("username", self.username)
            password = kwargs.pop("password", self.password)

            netloc = hostname
            if port is not None:
                netloc += f":{port}"
            if username is not None:
                userpass = username
                if password is not None:
                    userpass += f":{password}"
                netloc = f"{userpass}@{netloc}"

            kwargs["netloc"] = netloc

        components = self.components._replace(**kwargs)
        return self.__class__(components.geturl())

    def __eq__(self, other: typing.Any) -> bool:
        return str(self) == str(other)

    def __str__(self) -> str:
        return self._url

    def __repr__(self) -> str:
        url = str(self)
        if self.password:
            url = str(self.replace(password="********"))
        return f"{self.__class__.__name__}({repr(url)})"


class DatabaseURL(URL):
    @property
    def database(self) -> str:
        return self.path.lstrip("/")

    @property
    def dialect(self) -> str:
        return self.scheme.split("+")[0]

    @property
    def driver(self) -> str:
        if "+" not in self.scheme:
            return ""
        return self.scheme.split("+", 1)[1]

    def replace(self, **kwargs: typing.Any) -> "URL":
        if "database" in kwargs:
            kwargs["path"] = "/" + kwargs.pop("database")
        return super().replace(**kwargs)


class URLPath(str):
    """
    A URL path string that also holds an associated protocol.
    Used by the routing to return `url_path_for` matches.
    """

    def __new__(cls, path: str, protocol: str) -> str:
        assert protocol in ("http", "websocket")
        return str.__new__(cls, path)  # type: ignore

    def __init__(self, path: str, protocol: str) -> None:
        self.protocol = protocol

    def make_absolute_url(self, base_url: typing.Union[str, URL]) -> str:
        if isinstance(base_url, str):
            base_url = URL(base_url)
        scheme = {
            "http": {True: "https", False: "http"},
            "websocket": {True: "wss", False: "ws"},
        }[self.protocol][base_url.is_secure]
        netloc = base_url.netloc
        return str(URL(scheme=scheme, netloc=base_url.netloc, path=str(self)))


class Secret:
    """
    Holds a string value that should not be revealed in tracebacks etc.
    You should cast the value to `str` at the point it is required.
    """

    def __init__(self, value: str):
        self._value = value

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}('**********')"

    def __str__(self) -> str:
        return self._value


class CommaSeparatedStrings(Sequence):
    def __init__(self, value: typing.Union[str, typing.Sequence[str]]):
        if isinstance(value, str):
            splitter = shlex(value, posix=True)
            splitter.whitespace = ","
            splitter.whitespace_split = True
            self._items = [item.strip() for item in splitter]
        else:
            self._items = list(value)

    def __len__(self) -> int:
        return len(self._items)

    def __getitem__(self, index: typing.Union[int, slice]) -> typing.Any:
        return self._items[index]

    def __iter__(self) -> typing.Iterator[str]:
        return iter(self._items)

    def __repr__(self) -> str:
        list_repr = repr([item for item in self])
        return f"{self.__class__.__name__}({list_repr})"

    def __str__(self) -> str:
        return ", ".join([repr(item) for item in self])


class QueryParams(typing.Mapping[str, str]):
    """
    An immutable multidict.
    """

    def __init__(
        self,
        params: typing.Union["QueryParams", typing.Mapping[str, str]] = None,
        items: typing.List[typing.Tuple[str, str]] = None,
        query_string: str = None,
        scope: Scope = None,
    ) -> None:
        _items = []  # type: typing.List[typing.Tuple[str, str]]
        if params is not None:
            assert items is None, "Cannot set both 'params' and 'items'"
            assert query_string is None, "Cannot set both 'params' and 'query_string'"
            assert scope is None, "Cannot set both 'params' and 'scope'"
            if isinstance(params, QueryParams):
                _items = list(params.multi_items())
            else:
                _items = list(params.items())
        elif items is not None:
            assert query_string is None, "Cannot set both 'items' and 'query_string'"
            assert scope is None, "Cannot set both 'items' and 'scope'"
            _items = list(items)
        elif query_string is not None:
            assert scope is None, "Cannot set both 'query_string' and 'scope'"
            _items = parse_qsl(query_string)
        elif scope is not None:
            _items = parse_qsl(scope["query_string"].decode("latin-1"))

        self._dict = {k: v for k, v in _items}
        self._list = _items

    def getlist(self, key: typing.Any) -> typing.List[str]:
        return [item_value for item_key, item_value in self._list if item_key == key]

    def keys(self) -> typing.List[str]:  # type: ignore
        return list(self._dict.keys())

    def values(self) -> typing.List[str]:  # type: ignore
        return list(self._dict.values())

    def items(self) -> typing.List[typing.Tuple[str, str]]:  # type: ignore
        return list(self._dict.items())

    def multi_items(self) -> typing.List[typing.Tuple[str, str]]:
        return list(self._list)

    def get(self, key: typing.Any, default: typing.Any = None) -> typing.Any:
        if key in self._dict:
            return self._dict[key]
        return default

    def __getitem__(self, key: typing.Any) -> str:
        return self._dict[key]

    def __contains__(self, key: typing.Any) -> bool:
        return key in self._dict

    def __iter__(self) -> typing.Iterator[typing.Any]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._dict)

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, QueryParams):
            return False
        return sorted(self._list) == sorted(other._list)

    def __str__(self) -> str:
        return urlencode(self._list)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(query_string={repr(str(self))})"


class Headers(typing.Mapping[str, str]):
    """
    An immutable, case-insensitive multidict.
    """

    def __init__(
        self,
        headers: typing.Mapping[str, str] = None,
        raw: typing.List[typing.Tuple[bytes, bytes]] = None,
        scope: Scope = None,
    ) -> None:
        self._list = []  # type: typing.List[typing.Tuple[bytes, bytes]]
        if headers is not None:
            assert raw is None, 'Cannot set both "headers" and "raw".'
            assert scope is None, 'Cannot set both "headers" and "scope".'
            self._list = [
                (key.lower().encode("latin-1"), value.encode("latin-1"))
                for key, value in headers.items()
            ]
        elif raw is not None:
            assert scope is None, 'Cannot set both "raw" and "scope".'
            self._list = raw
        elif scope is not None:
            self._list = scope["headers"]

    @property
    def raw(self) -> typing.List[typing.Tuple[bytes, bytes]]:
        return list(self._list)

    def keys(self) -> typing.List[str]:  # type: ignore
        return [key.decode("latin-1") for key, value in self._list]

    def values(self) -> typing.List[str]:  # type: ignore
        return [value.decode("latin-1") for key, value in self._list]

    def items(self) -> typing.List[typing.Tuple[str, str]]:  # type: ignore
        return [
            (key.decode("latin-1"), value.decode("latin-1"))
            for key, value in self._list
        ]

    def get(self, key: str, default: typing.Any = None) -> typing.Any:
        try:
            return self[key]
        except KeyError:
            return default

    def getlist(self, key: str) -> typing.List[str]:
        get_header_key = key.lower().encode("latin-1")
        return [
            item_value.decode("latin-1")
            for item_key, item_value in self._list
            if item_key == get_header_key
        ]

    def mutablecopy(self) -> "MutableHeaders":
        return MutableHeaders(raw=self._list[:])

    def __getitem__(self, key: str) -> str:
        get_header_key = key.lower().encode("latin-1")
        for header_key, header_value in self._list:
            if header_key == get_header_key:
                return header_value.decode("latin-1")
        raise KeyError(key)

    def __contains__(self, key: typing.Any) -> bool:
        get_header_key = key.lower().encode("latin-1")
        for header_key, header_value in self._list:
            if header_key == get_header_key:
                return True
        return False

    def __iter__(self) -> typing.Iterator[typing.Any]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._list)

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, Headers):
            return False
        return sorted(self._list) == sorted(other._list)

    def __repr__(self) -> str:
        as_dict = dict(self.items())
        if len(as_dict) == len(self):
            return f"{self.__class__.__name__}({repr(as_dict)})"
        return f"{self.__class__.__name__}(raw={repr(self.raw)})"


class MutableHeaders(Headers):
    def __setitem__(self, key: str, value: str) -> None:
        """
        Set the header `key` to `value`, removing any duplicate entries.
        Retains insertion order.
        """
        set_key = key.lower().encode("latin-1")
        set_value = value.encode("latin-1")

        found_indexes = []
        for idx, (item_key, item_value) in enumerate(self._list):
            if item_key == set_key:
                found_indexes.append(idx)

        for idx in reversed(found_indexes[1:]):
            del self._list[idx]

        if found_indexes:
            idx = found_indexes[0]
            self._list[idx] = (set_key, set_value)
        else:
            self._list.append((set_key, set_value))

    def __delitem__(self, key: str) -> None:
        """
        Remove the header `key`.
        """
        del_key = key.lower().encode("latin-1")

        pop_indexes = []
        for idx, (item_key, item_value) in enumerate(self._list):
            if item_key == del_key:
                pop_indexes.append(idx)

        for idx in reversed(pop_indexes):
            del (self._list[idx])

    @property
    def raw(self) -> typing.List[typing.Tuple[bytes, bytes]]:
        return self._list

    def setdefault(self, key: str, value: str) -> str:
        """
        If the header `key` does not exist, then set it to `value`.
        Returns the header value.
        """
        set_key = key.lower().encode("latin-1")
        set_value = value.encode("latin-1")

        for idx, (item_key, item_value) in enumerate(self._list):
            if item_key == set_key:
                return item_value.decode("latin-1")
        self._list.append((set_key, set_value))
        return value

    def update(self, other: dict) -> None:
        for key, val in other.items():
            self[key] = val

    def append(self, key: str, value: str) -> None:
        """
        Append a header, preserving any duplicate entries.
        """
        append_key = key.lower().encode("latin-1")
        append_value = value.encode("latin-1")
        self._list.append((append_key, append_value))

    def add_vary_header(self, vary: str) -> None:
        existing = self.get("vary")
        if existing is not None:
            vary = ", ".join([existing, vary])
        self["vary"] = vary
