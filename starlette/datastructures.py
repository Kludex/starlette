import typing
from starlette.types import Scope
from urllib.parse import parse_qsl, unquote, urlparse, ParseResult


class URL:
    def __init__(self, url: str = "", scope: Scope = None) -> None:
        if scope is not None:
            assert not url, 'Cannot set both "url" and "scope".'
            scheme = scope.get("scheme", "http")
            server = scope.get("server", None)
            path = scope.get("root_path", "") + scope["path"]
            query_string = scope["query_string"]

            if server is None:
                url = path
            else:
                host, port = server
                default_port = {"http": 80, "https": 443, "ws": 80, "wss": 443}[scheme]
                if port == default_port:
                    url = "%s://%s%s" % (scheme, host, path)
                else:
                    url = "%s://%s:%s%s" % (scheme, host, port, path)

            if query_string:
                url += "?" + unquote(query_string.decode())
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

    def replace(self, **kwargs: typing.Any) -> "URL":
        if "hostname" in kwargs or "port" in kwargs:
            hostname = kwargs.pop("hostname", self.hostname)
            port = kwargs.pop("port", self.port)
            if port is None:
                kwargs["netloc"] = hostname
            else:
                kwargs["netloc"] = "%s:%d" % (hostname, port)
        components = self.components._replace(**kwargs)
        return URL(components.geturl())

    def __eq__(self, other: typing.Any) -> bool:
        return str(self) == str(other)

    def __str__(self) -> str:
        return self._url

    def __repr__(self) -> str:
        return "%s(%s)" % (self.__class__.__name__, repr(self._url))


# Type annotations for valid `__init__` values to QueryParams and Headers.
StrPairs = typing.Sequence[typing.Tuple[str, str]]
BytesPairs = typing.List[typing.Tuple[bytes, bytes]]
StrDict = typing.Mapping[str, str]


class QueryParams(StrDict):
    """
    An immutable multidict.
    """

    def __init__(
        self, value: typing.Union[str, typing.Union[StrDict, StrPairs]] = None
    ) -> None:
        if value is None:
            value = []
        elif isinstance(value, str):
            value = parse_qsl(value)

        if hasattr(value, "items"):
            items = list(typing.cast(StrDict, value).items())
        else:
            items = list(typing.cast(StrPairs, value))
        self._dict = {k: v for k, v in reversed(items)}
        self._list = items

    def getlist(self, key: typing.Any) -> typing.List[str]:
        return [item_value for item_key, item_value in self._list if item_key == key]

    def keys(self) -> typing.List[str]:  # type: ignore
        return [key for key, value in self._list]

    def values(self) -> typing.List[str]:  # type: ignore
        return [value for key, value in self._list]

    def items(self) -> StrPairs:  # type: ignore
        return list(self._list)

    def get(self, key: typing.Any, default: typing.Any = None) -> typing.Any:
        if key in self._dict:
            return self._dict[key]
        else:
            return default

    def __getitem__(self, key: typing.Any) -> str:
        return self._dict[key]

    def __contains__(self, key: typing.Any) -> bool:
        return key in self._dict

    def __iter__(self) -> typing.Iterator[typing.Any]:
        return iter(self._list)

    def __len__(self) -> int:
        return len(self._list)

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, QueryParams):
            other = QueryParams(other)
        return sorted(self._list) == sorted(other._list)

    def __repr__(self) -> str:
        return "QueryParams(%s)" % repr(self._list)


class Headers(typing.Mapping[str, str]):
    """
    An immutable, case-insensitive multidict.
    """

    def __init__(self, raw_headers: BytesPairs = None) -> None:
        if raw_headers is None:
            self._list = []  # type: BytesPairs
        else:
            for header_key, header_value in raw_headers:
                assert isinstance(header_key, bytes)
                assert isinstance(header_value, bytes)
                assert header_key == header_key.lower()
            self._list = raw_headers

    def keys(self) -> typing.List[str]:  # type: ignore
        return [key.decode("latin-1") for key, value in self._list]

    def values(self) -> typing.List[str]:  # type: ignore
        return [value.decode("latin-1") for key, value in self._list]

    def items(self) -> StrPairs:  # type: ignore
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
        return MutableHeaders(self._list[:])

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
        return iter(self.items())

    def __len__(self) -> int:
        return len(self._list)

    def __eq__(self, other: typing.Any) -> bool:
        if not isinstance(other, Headers):
            return False
        return sorted(self._list) == sorted(other._list)

    def __repr__(self) -> str:
        return "%s(%s)" % (self.__class__.__name__, repr(self.items()))


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

    def add_vary_header(self, vary: str) -> None:
        existing = self.get("vary")
        if existing is not None:
            vary = ", ".join([existing, vary])
        self["vary"] = vary
