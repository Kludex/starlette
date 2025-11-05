from __future__ import annotations

import functools
import re
from collections.abc import Collection

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import PlainTextResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

ALL_METHODS = {"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"}
SAFELISTED_HEADERS = {"Accept", "Accept-Language", "Content-Language", "Content-Type"}


class CORSMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        allow_origins: Collection[str] = {},
        allow_methods: Collection[str] = {"GET"},
        allow_headers: Collection[str] = {},
        allow_credentials: bool = False,
        allow_origin_regex: str | None = None,
        allow_private_network: bool = False,
        expose_headers: Collection[str] = {},
        max_age: int = 600,
    ) -> None:
        if "*" in allow_methods:
            allow_methods = ALL_METHODS

        allow_all_origins = "*" in allow_origins
        allow_all_headers = "*" in allow_headers
        explicit_allow_origin = allow_credentials or not allow_all_origins
        allow_headers = SAFELISTED_HEADERS.union(allow_headers)

        simple_headers: dict[str, str] = {}
        if not explicit_allow_origin:
            simple_headers["Access-Control-Allow-Origin"] = "*"
        if allow_credentials:
            simple_headers["Access-Control-Allow-Credentials"] = "true"
        if expose_headers:
            simple_headers["Access-Control-Expose-Headers"] = ", ".join(expose_headers)

        preflight_headers: dict[str, str] = {
            "Access-Control-Allow-Methods": ", ".join(allow_methods),
            "Access-Control-Max-Age": str(max_age),
        }
        if not explicit_allow_origin:
            preflight_headers["Access-Control-Allow-Origin"] = "*"
        if not allow_all_headers:
            preflight_headers["Access-Control-Allow-Headers"] = ", ".join(sorted(allow_headers))
        if allow_credentials:
            preflight_headers["Access-Control-Allow-Credentials"] = "true"

        preflight_vary: list[str] = ["Access-Control-Request-Headers", "Access-Control-Request-Private-Network"]
        if allow_methods != ALL_METHODS:
            preflight_vary.append("Access-Control-Request-Method")
        if explicit_allow_origin:
            preflight_vary.append("Origin")
        preflight_headers["Vary"] = ", ".join(preflight_vary)

        self.app = app
        self.allow_origins = allow_origins
        self.allow_methods = allow_methods
        self.allow_headers = {h.lower() for h in allow_headers}
        self.allow_all_origins = allow_all_origins
        self.allow_all_headers = allow_all_headers
        self.explicit_allow_origin = explicit_allow_origin
        self.allow_origin_regex = re.compile(allow_origin_regex) if allow_origin_regex is not None else None
        self.allow_private_network = allow_private_network
        self.simple_headers = simple_headers
        self.preflight_headers = preflight_headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # pragma: no cover
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)

        if "origin" not in headers:
            await self.app(scope, receive, send)
            return

        if scope["method"] == "OPTIONS" and "access-control-request-method" in headers:
            response = self.preflight_response(request_headers=headers)
            await response(scope, receive, send)
            return

        await self.simple_response(scope, receive, send, request_headers=headers)

    def is_allowed_origin(self, origin: str) -> bool:
        if origin in self.allow_origins:
            return True
        if origin == "null":
            return False
        if self.allow_origin_regex is not None and self.allow_origin_regex.fullmatch(origin):
            return True

        return self.allow_all_origins

    def preflight_response(self, request_headers: Headers) -> Response:
        requested_origin = request_headers["origin"]
        requested_method = request_headers["access-control-request-method"]
        requested_headers = request_headers.get("access-control-request-headers")
        requested_private_network = request_headers.get("access-control-request-private-network")

        headers = dict(self.preflight_headers)
        failures: list[str] = []

        if self.is_allowed_origin(requested_origin):
            if self.explicit_allow_origin:
                # The "else" case is already accounted for in self.preflight_headers
                # and the value would be "*".
                headers["Access-Control-Allow-Origin"] = requested_origin
        else:
            failures.append("origin")

        if requested_method not in self.allow_methods:
            failures.append("method")

        # When allow_headers is wildcard, mirror any requested headers.
        if self.allow_all_headers and requested_headers is not None:
            headers["Access-Control-Allow-Headers"] = requested_headers
        elif requested_headers is not None:
            for header in requested_headers.split(","):
                if header.strip().lower() not in self.allow_headers:
                    failures.append("headers")
                    break

        if requested_private_network is not None:
            if self.allow_private_network:
                headers["Access-Control-Allow-Private-Network"] = "true"
            else:
                failures.append("private-network")

        # We don't strictly need to use 400 responses here, since its up to
        # the browser to enforce the CORS policy, but its more informative
        # if we do.
        if failures:
            failure_text = "Disallowed CORS " + ", ".join(failures)
            return PlainTextResponse(failure_text, status_code=400, headers=headers)

        return PlainTextResponse("OK", status_code=200, headers=headers)

    async def simple_response(self, scope: Scope, receive: Receive, send: Send, request_headers: Headers) -> None:
        send = functools.partial(self.send, send=send, request_headers=request_headers)
        await self.app(scope, receive, send)

    async def send(self, message: Message, send: Send, request_headers: Headers) -> None:
        if message["type"] != "http.response.start":
            await send(message)
            return

        message.setdefault("headers", [])
        headers = MutableHeaders(scope=message)
        origin = request_headers["Origin"]

        if self.explicit_allow_origin:
            headers.add_vary_header("Origin")

        if self.is_allowed_origin(origin):
            headers.update(self.simple_headers)

            if self.explicit_allow_origin:
                headers["Access-Control-Allow-Origin"] = origin

        await send(message)
