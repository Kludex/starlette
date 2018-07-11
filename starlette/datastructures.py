import typing
from urllib.parse import parse_qsl, urlparse


class URL(str):
    @property
    def components(self):
        if not hasattr(self, "_components"):
            self._components = urlparse(self)
        return self._components

    @property
    def scheme(self):
        return self.components.scheme

    @property
    def netloc(self):
        return self.components.netloc

    @property
    def path(self):
        return self.components.path

    @property
    def params(self):
        return self.components.params

    @property
    def query(self):
        return self.components.query

    @property
    def fragment(self):
        return self.components.fragment

    @property
    def username(self):
        return self.components.username

    @property
    def password(self):
        return self.components.password

    @property
    def hostname(self):
        return self.components.hostname

    @property
    def port(self):
        return self.components.port


# Type annotations for valid `__init__` values to QueryParams and Headers.
StrPairs = typing.Sequence[typing.Tuple[str, str]]
StrDict = typing.Mapping[str, str]


class QueryParams(typing.Mapping[str, str]):
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

    def get_list(self, key: str) -> typing.List[str]:
        return [item_value for item_key, item_value in self._list if item_key == key]

    def keys(self):
        return [key for key, value in self._list]

    def values(self):
        return [value for key, value in self._list]

    def items(self):
        return list(self._list)

    def get(self, key, default=None):
        if key in self._dict:
            return self._dict[key]
        else:
            return default

    def __getitem__(self, key):
        return self._dict[key]

    def __contains__(self, key):
        return key in self._dict

    def __iter__(self):
        return iter(self._list)

    def __len__(self):
        return len(self._list)

    def __eq__(self, other):
        if not isinstance(other, QueryParams):
            other = QueryParams(other)
        return sorted(self._list) == sorted(other._list)

    def __repr__(self):
        return "QueryParams(%s)" % repr(self._list)


class Headers(typing.Mapping[str, str]):
    """
    An immutable, case-insensitive multidict.
    """

    def __init__(self, raw_headers=None) -> None:
        if raw_headers is None:
            self._list = []
        else:
            for header_key, header_value in raw_headers:
                assert isinstance(header_key, bytes)
                assert isinstance(header_value, bytes)
                assert header_key == header_key.lower()
            self._list = raw_headers

    def keys(self):
        return [key.decode("latin-1") for key, value in self._list]

    def values(self):
        return [value.decode("latin-1") for key, value in self._list]

    def items(self):
        return [
            (key.decode("latin-1"), value.decode("latin-1"))
            for key, value in self._list
        ]

    def get(self, key: str, default: str = None):
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

    def __getitem__(self, key: str):
        get_header_key = key.lower().encode("latin-1")
        for header_key, header_value in self._list:
            if header_key == get_header_key:
                return header_value.decode("latin-1")
        raise KeyError(key)

    def __contains__(self, key: str):
        get_header_key = key.lower().encode("latin-1")
        for header_key, header_value in self._list:
            if header_key == get_header_key:
                return True
        return False

    def __iter__(self):
        return iter(self.items())

    def __len__(self):
        return len(self._list)

    def __eq__(self, other):
        if not isinstance(other, Headers):
            return False
        return sorted(self._list) == sorted(other._list)

    def __repr__(self):
        return "%s(%s)" % (self.__class__.__name__, repr(self.items()))


class MutableHeaders(Headers):
    def __setitem__(self, key: str, value: str):
        """
        Set the header `key` to `value`, removing any duplicate entries.
        """
        set_key = key.lower().encode("latin-1")
        set_value = value.encode("latin-1")

        pop_indexes = []
        for idx, (item_key, item_value) in enumerate(self._list):
            if item_key == set_key:
                pop_indexes.append(idx)

        for idx in reversed(pop_indexes):
            del self._list[idx]

        self._list.append((set_key, set_value))

    def __delitem__(self, key: str):
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

    def setdefault(self, key: str, value: str):
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
