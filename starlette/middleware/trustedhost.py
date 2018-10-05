from starlette.datastructures import Headers
from starlette.responses import PlainTextResponse


class TrustedHostMiddleware:
    def __init__(self, app, allowed_hosts=["*"]):
        self.app = app
        self.allowed_hosts = allowed_hosts
        self.allow_any = "*" in allowed_hosts

    def __call__(self, scope):
        if scope["type"] in ("http", "websocket") and not self.allow_any:
            headers = Headers(scope["headers"])
            host = headers.get("host")
            if host not in self.allowed_hosts:
                return PlainTextResponse("Invalid host header", status_code=400)

        return self.app(scope)
