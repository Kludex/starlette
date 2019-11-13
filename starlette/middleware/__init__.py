import typing


class Middleware:
    def __init__(self, cls: type, **options: typing.Any) -> None:
        self.cls = cls
        self.options = options

    def __iter__(self) -> typing.Iterator:
        as_tuple = (self.cls, self.options)
        return iter(as_tuple)

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        option_strings = ["{key}={value!r}" for key, value in self.options.items()]
        options_repr = ", ".join(option_strings)
        return f"{class_name}({self.cls.__name__}{options_repr})"
