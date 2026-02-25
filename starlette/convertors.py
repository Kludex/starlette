from __future__ import annotations

import math
import uuid
from typing import Any, ClassVar, Generic, TypeVar

T = TypeVar("T")


class Convertor(Generic[T]):
    regex: ClassVar[str] = ""

    def convert(self, value: str) -> T:
        raise NotImplementedError()  # pragma: no cover

    def to_string(self, value: T) -> str:
        raise NotImplementedError()  # pragma: no cover


class StringConvertor(Convertor[str]):
    regex = "[^/]+"

    def convert(self, value: str) -> str:
        return value

    def to_string(self, value: str) -> str:
        value = str(value)
        if "/" in value:
            raise ValueError("May not contain path separators")
        if not value:
            raise ValueError("Must not be empty")
        return value


class PathConvertor(Convertor[str]):
    regex = ".*"

    def convert(self, value: str) -> str:
        return str(value)

    def to_string(self, value: str) -> str:
        return str(value)


class IntegerConvertor(Convertor[int]):
    regex = "[0-9]+"

    def convert(self, value: str) -> int:
        return int(value)

    def to_string(self, value: int) -> str:
        value = int(value)
        if value < 0:
            raise ValueError("Negative integers are not supported")
        return str(value)


class FloatConvertor(Convertor[float]):
    regex = r"[0-9]+(\.[0-9]+)?"

    def convert(self, value: str) -> float:
        return float(value)

    def to_string(self, value: float) -> str:
        value = float(value)
        if value < 0.0:
            raise ValueError("Negative floats are not supported")
        if math.isnan(value):
            raise ValueError("NaN values are not supported")
        if math.isinf(value):
            raise ValueError("Infinite values are not supported")
        return ("%0.20f" % value).rstrip("0").rstrip(".")


class UUIDConvertor(Convertor[uuid.UUID]):
    regex = "[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}"

    def convert(self, value: str) -> uuid.UUID:
        return uuid.UUID(value)

    def to_string(self, value: uuid.UUID) -> str:
        return str(value)


CONVERTOR_TYPES: dict[str, Convertor[Any]] = {
    "str": StringConvertor(),
    "path": PathConvertor(),
    "int": IntegerConvertor(),
    "float": FloatConvertor(),
    "uuid": UUIDConvertor(),
}


def register_url_convertor(key: str, convertor: Convertor[Any]) -> None:
    CONVERTOR_TYPES[key] = convertor
