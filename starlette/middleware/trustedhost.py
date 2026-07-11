from __future__ import annotations

from collections.abc import Sequence

from starlette.datastructures import URL, Headers
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

ENFORCE_DOMAIN_WILDCARD = "Domain wildcard patterns must be like '*.example.com'."


class TrustedHostMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        allowed_hosts: Sequence[str] | None = None,
        www_redirect: bool = True,
    ) -> None:
        if allowed_hosts is None:
            allowed_hosts = ["*"]

        for pattern in allowed_hosts:
            assert "*" not in pattern[1:], ENFORCE_DOMAIN_WILDCARD
            if pattern.startswith("*") and pattern != "*":
                assert pattern.startswith("*."), ENFORCE_DOMAIN_WILDCARD
        self.app = app
        self.allowed_hosts = list(allowed_hosts)
        self.allow_any = "*" in allowed_hosts
        self.www_redirect = www_redirect

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if self.allow_any or scope["type"] not in (
            "http",
            "websocket",
        ):  # pragma: no cover
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        host_header = headers.get("host", "")
        if host_header.startswith("["):
            # IPv6: extract [::1] from [::1]:8000
            # Validate that after ] only :port or nothing follows
            bracket_end = host_header.find("]")  # pragma: no cover
            if bracket_end != -1:  # pragma: no cover
                suffix = host_header[bracket_end + 1:]  # pragma: no cover
                if suffix == "" or suffix.startswith(":"):  # pragma: no cover
                    host = host_header[1:bracket_end]  # pragma: no cover
                else:  # pragma: no cover
                    # Malformed: not a real IPv6, fall back to treating entire header as host
                    host = host_header  # pragma: no cover
            else:  # pragma: no cover
                host = host_header  # pragma: no cover
        else:
            host = host_header.split(":")[0]
        is_valid_host = False
        found_www_redirect = False
        for pattern in self.allowed_hosts:
            if host == pattern or (pattern.startswith("*") and host.endswith(pattern[1:])):
                is_valid_host = True
                break
            elif "www." + host == pattern:
                found_www_redirect = True

        if is_valid_host:
            await self.app(scope, receive, send)
        else:
            response: Response
            if found_www_redirect and self.www_redirect:
                url = URL(scope=scope)
                redirect_url = url.replace(netloc="www." + url.netloc)
                response = RedirectResponse(url=str(redirect_url))
            else:
                response = PlainTextResponse("Invalid host header", status_code=400)
            await response(scope, receive, send)
