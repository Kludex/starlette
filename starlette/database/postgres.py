import typing
from types import TracebackType

import asyncpg
from sqlalchemy.dialects.postgresql import pypostgresql
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.sql import ClauseElement

from starlette.database.core import (
    DatabaseBackend,
    DatabaseSession,
    DatabaseTransaction,
    compile,
)
from starlette.datastructures import DatabaseURL


class PostgresBackend(DatabaseBackend):
    def __init__(self, database_url: typing.Union[str, DatabaseURL]) -> None:
        self.database_url = database_url
        self.dialect = self.get_dialect()
        self.pool = None

    def get_dialect(self) -> Dialect:
        dialect = pypostgresql.dialect(paramstyle="pyformat")

        dialect.implicit_returning = True
        dialect.supports_native_enum = True
        dialect.supports_smallserial = True  # 9.2+
        dialect._backslash_escapes = False
        dialect.supports_sane_multi_rowcount = True  # psycopg 2.0.9+
        dialect._has_native_hstore = True

        return dialect

    async def startup(self) -> None:
        self.pool = await asyncpg.create_pool(str(self.database_url))

    async def shutdown(self) -> None:
        assert self.pool is not None, "DatabaseBackend is not running"
        await self.pool.close()
        self.pool = None

    def session(self) -> "PostgresSession":
        assert self.pool is not None, "DatabaseBackend is not running"
        return PostgresSession(self.pool, self.dialect)


class PostgresSession(DatabaseSession):
    def __init__(self, pool: asyncpg.pool.Pool, dialect: Dialect):
        self.pool = pool
        self.dialect = dialect
        self.conn = None
        self.connection_holders = 0

    async def fetchall(self, query: ClauseElement) -> typing.Any:
        query, args = compile(query, dialect=self.dialect)

        conn = await self.acquire_connection()
        try:
            return await conn.fetch(query, *args)
        finally:
            await self.release_connection()

    async def fetchone(self, query: ClauseElement) -> typing.Any:
        query, args = compile(query, dialect=self.dialect)

        conn = await self.acquire_connection()
        try:
            return await conn.fetchrow(query, *args)
        finally:
            await self.release_connection()

    async def execute(self, query: ClauseElement) -> typing.Any:
        query, args = compile(query, dialect=self.dialect)

        conn = await self.acquire_connection()
        try:
            return await conn.execute(query, *args)
        finally:
            await self.release_connection()

    def transaction(self) -> DatabaseTransaction:
        return PostgresTransaction(self)

    async def acquire_connection(self) -> asyncpg.Connection:
        """
        Either acquire a connection from the pool, or return the
        existing connection. Must be followed by a corresponding
        call to `release_connection`.
        """
        self.connection_holders += 1
        if self.conn is None:
            self.conn = await self.pool.acquire()
        return self.conn

    async def release_connection(self) -> None:
        self.connection_holders -= 1
        if self.connection_holders == 0:
            await self.pool.release(self.conn)
            self.conn = None


class PostgresTransaction(DatabaseTransaction):
    def __init__(self, session: PostgresSession):
        self.session = session

    async def __aenter__(self) -> None:
        await self.start()

    async def __aexit__(
        self,
        exc_type: typing.Type[BaseException] = None,
        exc_value: BaseException = None,
        traceback: TracebackType = None,
    ) -> None:
        if exc_type is not None:
            await self.rollback()
        else:
            await self.commit()

    async def start(self) -> None:
        conn = await self.session.acquire_connection()
        self.transaction = conn.transaction()
        await self.transaction.start()

    async def commit(self) -> None:
        await self.transaction.commit()
        await self.session.release_connection()

    async def rollback(self) -> None:
        await self.transaction.rollback()
        await self.session.release_connection()
