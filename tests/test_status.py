import importlib

import pytest


@pytest.mark.parametrize(
    "constant,msg",
    (
        (
            "WS_1004_NO_STATUS_RCVD",
            "'WS_1004_NO_STATUS_RCVD' is deprecated. Use 'WS_1005_NO_STATUS_RCVD' instead.",
        ),
        (
            "WS_1005_ABNORMAL_CLOSURE",
            "'WS_1005_ABNORMAL_CLOSURE' is deprecated. Use 'WS_1006_ABNORMAL_CLOSURE' instead.",
        ),
    ),
)
def test_deprecated_types(constant: str, msg: str) -> None:
    with pytest.warns(DeprecationWarning) as record:
        getattr(importlib.import_module("starlette.status"), constant)
        assert len(record) == 1
        assert msg in str(record.list[0])
