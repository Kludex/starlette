from functools import partial
from urllib.parse import urlparse
import asyncio
import asyncpg


class DatabaseMiddleware:
    def __init__(self, app, database_url=None, database_config=None):
        self.app = app
        if database_config is None:
            parsed = urlparse(database_url)
            database_config = {
                "user": parsed.user,
                "password": parsed.password,
                "database": parsed.database,
                "host": parsed.host,
                "port": parsed.port,
            }
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.create_pool(database_config))

    async def create_pool(self, database_config):
        self.pool = await asyncpg.create_pool(**database_config)

    def __call__(self, scope):
        scope["database"] = self.pool
        return self.app(scope)
