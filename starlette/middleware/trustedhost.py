from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse
from starlette.types import ASGIApp, ASGIInstance, Scope
import typing


class TrustedHostMiddleware:
    def __init__(
        self, app: ASGIApp, allowed_hosts: typing.Sequence[str] = ["*"]
    ) -> None:
        self.app = app
        self.allowed_hosts = allowed_hosts
        self.allow_any = "*" in allowed_hosts

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] in ("http", "websocket") and not self.allow_any:
            headers = Headers(scope=scope)
            host = headers.get("host")
            if host not in self.allowed_hosts:
                return PlainTextResponse("Invalid host header", status_code=400)

        return self.app(scope)
