from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

import httpx

from starlette.testclient import TestClient
from starlette.types import ASGIApp

if TYPE_CHECKING:

    class TestClientFactory(Protocol):  # pragma: no cover
        def __call__(
            self,
            app: ASGIApp,
            base_url: str = "http://testserver",
            raise_server_exceptions: bool = True,
            root_path: str = "",
            cookies: httpx._types.CookieTypes | None = None,
            headers: dict[str, str] | None = None,
            follow_redirects: bool = True,
            client: tuple[str, int] = ("testclient", 50000),
        ) -> TestClient: ...
else:  # pragma: no cover

    class TestClientFactory:
        __test__ = False
