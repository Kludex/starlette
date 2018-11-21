import typing

from starlette.datastructures import URL, Headers
from starlette.responses import PlainTextResponse, RedirectResponse
from starlette.types import ASGIApp, ASGIInstance, Scope

ENFORCE_DOMAIN_WILDCARD = "Domain wildcard patterns must be like '*.example.com'."


class TrustedHostMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        allowed_hosts: typing.Sequence[str] = ["*"],
        www_redirect: bool = True,
    ) -> None:
        for pattern in allowed_hosts:
            assert "*" not in pattern[1:], ENFORCE_DOMAIN_WILDCARD
            if pattern.startswith("*") and pattern != "*":
                assert pattern.startswith("*."), ENFORCE_DOMAIN_WILDCARD
        self.app = app
        self.allowed_hosts = list(allowed_hosts)
        self.allow_any = "*" in allowed_hosts
        self.www_redirect = www_redirect

    def __call__(self, scope: Scope) -> ASGIInstance:
        if scope["type"] in ("http", "websocket") and not self.allow_any:
            headers = Headers(scope=scope)
            host = headers.get("host", "").split(":")[0]
            found_www_redirect = False
            for pattern in self.allowed_hosts:
                if host == pattern or (
                    pattern.startswith("*") and host.endswith(pattern[1:])
                ):
                    break
                elif "www." + host == pattern:
                    found_www_redirect = True
            else:
                if found_www_redirect and self.www_redirect:
                    url = URL(scope=scope)
                    redirect_url = url.replace(netloc="www." + url.netloc)
                    return RedirectResponse(url=str(redirect_url))
                return PlainTextResponse("Invalid host header", status_code=400)

        return self.app(scope)
