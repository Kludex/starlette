import functools
import logging
import typing
from types import TracebackType

from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.sql import ClauseElement

from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("starlette.database")


def compile(query: ClauseElement, dialect: Dialect) -> typing.Tuple[str, list]:
    # query = execute_defaults(query)  # default values for Insert/Update
    compiled = query.compile(dialect=dialect)
    compiled_params = sorted(compiled.params.items())

    mapping = {key: "$" + str(i) for i, (key, _) in enumerate(compiled_params, start=1)}
    compiled_query = compiled.string % mapping

    processors = compiled._bind_processors
    args = [
        processors[key](val) if key in processors else val
        for key, val in compiled_params
    ]

    logger.debug(compiled_query)
    return compiled_query, args


def transaction(func: typing.Callable) -> typing.Callable:
    @functools.wraps(func)
    async def wrapper(request: Request) -> Response:
        async with request.database.transaction():
            return await func(request)

    return wrapper


class DatabaseBackend:
    async def startup(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def shutdown(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    def session(self) -> "DatabaseSession":
        raise NotImplementedError()  # pragma: no cover


class DatabaseSession:
    async def fetchall(self, query: ClauseElement) -> typing.Any:
        raise NotImplementedError()  # pragma: no cover

    async def fetchone(self, query: ClauseElement) -> typing.Any:
        raise NotImplementedError()  # pragma: no cover

    async def fetchval(self, query: ClauseElement, index: int = 0) -> typing.Any:
        row = await self.fetchone(query)
        return row[index]

    async def execute(self, query: ClauseElement) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def executemany(self, query: ClauseElement, values: list) -> None:
        raise NotImplementedError()  # pragma: no cover

    def transaction(self) -> "DatabaseTransaction":
        raise NotImplementedError()  # pragma: no cover


class DatabaseTransaction:
    async def __aenter__(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def __aexit__(
        self,
        exc_type: typing.Type[BaseException] = None,
        exc_value: BaseException = None,
        traceback: TracebackType = None,
    ) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def start(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def commit(self) -> None:
        raise NotImplementedError()  # pragma: no cover

    async def rollback(self) -> None:
        raise NotImplementedError()  # pragma: no cover
