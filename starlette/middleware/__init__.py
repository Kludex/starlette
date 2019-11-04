import typing


class Middleware:
    def __init__(
        self, cls: type, options: dict = None, enabled: typing.Any = True
    ) -> None:
        self.cls = cls
        self.options = dict(options) if options else {}
        self.enabled = bool(enabled)

    def __iter__(self) -> typing.Iterator:
        as_tuple = (self.cls, self.options, self.enabled)
        return iter(as_tuple)

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        options_repr = "" if not self.options else f", options={self.options!r}"
        enabled_repr = "" if self.enabled else ", enabled=False"
        return f"{class_name}({self.cls.__name__}{options_repr}{enabled_repr})"
