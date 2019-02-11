from starlette.datastructures import URL
from starlette.responses import RedirectResponse
from starlette.types import ASGIApp, ASGIInstance, Scope


class HTTPSRedirectMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] in ("http", "websocket") and scope["scheme"] in ("http", "ws"):
            url = URL(scope=scope)
            redirect_scheme = {"http": "https", "ws": "wss"}[url.scheme]
            netloc = url.hostname if url.port in (80, 443) else url.netloc
            url = url.replace(scheme=redirect_scheme, netloc=netloc)
            return RedirectResponse(url, status_code=301)

        return self.app(scope)
