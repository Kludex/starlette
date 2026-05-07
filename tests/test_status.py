import importlib

import pytest


@pytest.mark.parametrize(
    "constant,msg",
    (
        (
            "HTTP_413_REQUEST_ENTITY_TOO_LARGE",
            "'HTTP_413_REQUEST_ENTITY_TOO_LARGE' is deprecated. Use 'HTTP_413_CONTENT_TOO_LARGE' instead.",
        ),
        (
            "HTTP_414_REQUEST_URI_TOO_LONG",
            "'HTTP_414_REQUEST_URI_TOO_LONG' is deprecated. Use 'HTTP_414_URI_TOO_LONG' instead.",
        ),
    ),
)
def test_deprecated_types(constant: str, msg: str) -> None:
    with pytest.warns(DeprecationWarning) as record:
        getattr(importlib.import_module("starlette.status"), constant)
        assert len(record) == 1
        assert msg in str(record.list[0])


def test_unknown_status() -> None:
    with pytest.raises(
        AttributeError,
        match="module 'starlette.status' has no attribute 'HTTP_999_UNKNOWN_STATUS_CODE'",
    ):
        getattr(importlib.import_module("starlette.status"), "HTTP_999_UNKNOWN_STATUS_CODE")
