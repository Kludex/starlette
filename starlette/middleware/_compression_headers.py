from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from starlette.datastructures import MutableHeaders
from starlette.types import Message, Scope


@dataclass(frozen=True)
class CompressionPlan:
    encoding: str | None
    body_allowed: bool


def compressible(initial_message: Message, exclude_content_types: tuple[str, ...]) -> bool:
    status = initial_message["status"]
    if status < 200 or status in (204, 205, 206):
        return False
    content_type = b""
    for key, value in initial_message["headers"]:
        key = key.lower()
        if key == b"content-encoding":
            return False
        if key == b"content-type" and not content_type:
            content_type = value
    media_type = content_type.decode("latin-1").partition(";")[0].strip().lower()
    media_types = {media_type, media_type.partition("/")[0] + "/*"}
    if media_type.startswith("application/grpc+"):
        media_types.add("application/grpc")
    return media_types.isdisjoint(exclude_content_types)


def prepare_response(
    initial_message: Message,
    message: Message | None,
    scope: Scope,
    eligible: bool,
    encoding: str | None,
    minimum_size: int,
    accepts: Callable[[str], bool] | None,
) -> CompressionPlan:
    status = initial_message["status"]
    if status < 200 or status in (204, 205):
        return CompressionPlan("identity", False)

    not_modified = status == 304
    metadata_only = not_modified or scope.get("method") == "HEAD"
    large_enough = False
    if message is not None:
        eligible = eligible and message["type"] == "http.response.body"
        large_enough = len(message.get("body", b"")) >= minimum_size or message.get("more_body", False)
    compress = eligible and (large_enough or metadata_only)
    if accepts is None and not compress:
        # Without negotiation, an uncompressed response keeps its headers unchanged.
        return CompressionPlan("identity", not metadata_only)

    headers = MutableHeaders(raw=initial_message["headers"])
    existing_encoding = headers.get("content-encoding")
    vary = {value.strip().lower() for value in ",".join(headers.getlist("vary")).split(",")}
    if not vary.intersection({"*", "accept-encoding"}):
        headers.add_vary_header("Accept-Encoding")

    if existing_encoding is not None:
        accepted = accepts is None or all(accepts(coding.strip().lower()) for coding in existing_encoding.split(","))
        return CompressionPlan("identity" if accepted else None, not metadata_only)

    identity_allowed = accepts is None or accepts("identity")
    selected = encoding if eligible and (large_enough or metadata_only or not identity_allowed) else "identity"
    if selected == "identity" and not identity_allowed:
        selected = None

    if selected not in (None, "identity"):
        etag = headers.get("etag")
        if etag is not None and not etag.startswith("W/"):
            headers["etag"] = "W/" + etag
        if metadata_only:
            del headers["content-length"]
        if not not_modified:
            headers["content-encoding"] = selected
    return CompressionPlan(selected, not metadata_only)
