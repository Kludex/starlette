import typing

from starlette.database.core import (
    DatabaseBackend,
    DatabaseSession,
    DatabaseTransaction,
)
from starlette.datastructures import DatabaseURL
from starlette.types import ASGIApp, ASGIInstance, Message, Receive, Scope, Send


class DatabaseMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        database_url: typing.Union[str, DatabaseURL],
        rollback_on_shutdown: bool = False,
    ) -> None:
        self.app = app
        self.backend = self.get_backend(database_url)
        self.rollback_on_shutdown = rollback_on_shutdown
        self.session = None  # type: typing.Optional[DatabaseSession]
        self.transaction = None  # type: typing.Optional[DatabaseTransaction]

    def get_backend(
        self, database_url: typing.Union[str, DatabaseURL]
    ) -> DatabaseBackend:
        if isinstance(database_url, str):
            database_url = DatabaseURL(database_url)
        assert database_url.dialect in [
            "postgresql",
            "mysql",
        ], "Currently only postgresql and mysql are supported."

        if database_url.dialect == "postgresql":
            from starlette.database.postgres import PostgresBackend

            return PostgresBackend(database_url)

        else:
            assert database_url.dialect == "mysql"
            from starlette.database.mysql import MysqlBackend

            return MysqlBackend(database_url)

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] == "lifespan":
            return DatabaseLifespan(
                self.app, scope, startup=self.startup, shutdown=self.shutdown
            )

        if self.session is not None:
            session = self.session
        else:
            session = self.backend.session()  # pragma: no cover
        scope["database"] = session
        return self.app(scope)

    async def startup(self) -> None:
        await self.backend.startup()
        if self.rollback_on_shutdown:
            self.session = self.backend.session()
            self.transaction = self.session.transaction()
            await self.transaction.start()

    async def shutdown(self) -> None:
        if self.rollback_on_shutdown:
            assert self.session is not None
            assert self.transaction is not None
            await self.transaction.rollback()
        await self.backend.shutdown()


class DatabaseLifespan:
    def __init__(
        self,
        app: ASGIApp,
        scope: Scope,
        startup: typing.Callable,
        shutdown: typing.Callable,
    ) -> None:
        self.inner = app(scope)
        self.startup = startup
        self.shutdown = shutdown

    async def __call__(self, receive: Receive, send: Send) -> None:
        async def receiver() -> Message:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await self.startup()
            elif message["type"] == "lifespan.shutdown":
                await self.shutdown()
            return message

        await self.inner(receiver, send)
