from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from starlette.datastructures import MutableHeaders
from starlette.types import Message, Scope


@dataclass(frozen=True)
class CompressionPlan:
    encoding: str | None
    body_allowed: bool


def prepare_response(
    initial_message: Message,
    message: Message,
    scope: Scope,
    encoding: str | None,
    minimum_size: int,
    exclude_content_types: tuple[str, ...],
    accepts: Callable[[str], bool] | None,
) -> CompressionPlan:
    headers = MutableHeaders(raw=initial_message["headers"])
    status = initial_message["status"]
    method = scope.get("method", "GET")
    metadata_only = method == "HEAD" or status == 304
    body_allowed = not metadata_only and status >= 200 and status not in (204, 205)
    if not metadata_only and not body_allowed:
        return CompressionPlan("identity", False)

    existing_encoding = headers.get("content-encoding")
    if existing_encoding is not None:
        accepted = accepts is None or all(accepts(coding.strip().lower()) for coding in existing_encoding.split(","))
        return CompressionPlan("identity" if accepted else None, body_allowed)

    media_type = headers.get("content-type", "").partition(";")[0].strip().lower()
    media_types = {media_type, media_type.partition("/")[0] + "/*"}
    eligible = (
        status != 206 and media_types.isdisjoint(exclude_content_types) and message["type"] == "http.response.body"
    )
    identity_allowed = accepts is None or accepts("identity")
    large_enough = len(message.get("body", b"")) >= minimum_size or message.get("more_body", False)
    if eligible and (large_enough or metadata_only or not identity_allowed):
        vary = {value.strip().lower() for value in headers.get("vary", "").split(",")}
        if not vary.intersection({"*", "accept-encoding"}):
            headers.add_vary_header("Accept-Encoding")
        selected = encoding
    else:
        selected = "identity"
    if selected == "identity" and not identity_allowed:
        selected = None

    if selected not in (None, "identity"):
        etag = headers.get("etag")
        if etag is not None and not etag.startswith("W/"):
            headers["etag"] = "W/" + etag
        if metadata_only:
            del headers["content-length"]
    return CompressionPlan(selected, body_allowed)
