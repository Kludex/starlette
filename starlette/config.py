import os
import typing


class undefined:
    pass


class Config:
    def __init__(
        self, env_file: str = None, environ: typing.Mapping[str, str] = os.environ
    ) -> None:
        self.environ = environ
        self.file_values = {}  # type: typing.Dict[str, str]
        if env_file is not None:
            self.file_values = self._read_file(env_file)

    def get(
        self, key: str, cast: type = None, default: typing.Any = undefined
    ) -> typing.Any:
        if key in self.environ:
            value = self.environ[key]
            return self._perform_cast(key, value, cast)
        if key in self.file_values:
            value = self.file_values[key]
            return self._perform_cast(key, value, cast)
        if default is not undefined:
            return default
        raise KeyError("Config '%s' is missing, and has no default." % key)

    def _read_file(self, file_name: str) -> typing.Dict[str, str]:
        file_values = {}  # type: typing.Dict[str, str]
        with open(file_name) as input_file:
            for line in input_file.readlines():
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip("\"'")
                    file_values[key] = value
        return file_values

    def _perform_cast(self, key: str, value: str, cast: type = None) -> typing.Any:
        if cast is None or value is None:
            return value
        elif cast is bool and isinstance(value, str):
            mapping = {"true": True, "false": False}
            value = value.lower()
            if value not in mapping:
                raise ValueError(
                    "Config '%s' has value '%s'. Not a valid bool." % (key, value)
                )
            return mapping[value]
        try:
            return cast(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Config '%s' has value '%s'. Not a valid %s."
                % (key, value, cast.__name__)
            )
