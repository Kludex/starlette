from collections.abc import Iterator
from datetime import datetime
from uuid import UUID

import pytest

from starlette import convertors
from starlette.convertors import Convertor, register_url_convertor
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, Router
from tests.types import TestClientFactory


@pytest.fixture(scope="module", autouse=True)
def refresh_convertor_types() -> Iterator[None]:
    convert_types = convertors.CONVERTOR_TYPES.copy()
    yield
    convertors.CONVERTOR_TYPES = convert_types


class DateTimeConvertor(Convertor[datetime]):
    regex = "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(.[0-9]+)?"

    def convert(self, value: str) -> datetime:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")

    def to_string(self, value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%S")


@pytest.fixture(scope="function")
def app() -> Router:
    register_url_convertor("datetime", DateTimeConvertor())

    def datetime_convertor(request: Request) -> JSONResponse:
        param = request.path_params["param"]
        assert isinstance(param, datetime)
        return JSONResponse({"datetime": param.strftime("%Y-%m-%dT%H:%M:%S")})

    return Router(
        routes=[
            Route(
                "/datetime/{param:datetime}",
                endpoint=datetime_convertor,
                name="datetime-convertor",
            )
        ]
    )


def test_datetime_convertor(test_client_factory: TestClientFactory, app: Router) -> None:
    client = test_client_factory(app)
    response = client.get("/datetime/2020-01-01T00:00:00")
    assert response.json() == {"datetime": "2020-01-01T00:00:00"}

    assert (
        app.url_path_for("datetime-convertor", param=datetime(1996, 1, 22, 23, 0, 0)) == "/datetime/1996-01-22T23:00:00"
    )


@pytest.mark.parametrize("param, status_code", [("1.0", 200), ("1-0", 404)])
def test_default_float_convertor(test_client_factory: TestClientFactory, param: str, status_code: int) -> None:
    def float_convertor(request: Request) -> JSONResponse:
        param = request.path_params["param"]
        assert isinstance(param, float)
        return JSONResponse({"float": param})

    app = Router(routes=[Route("/{param:float}", endpoint=float_convertor)])

    client = test_client_factory(app)
    response = client.get(f"/{param}")
    assert response.status_code == status_code


# 2026-10-08: Generated float paths must resolve to the original finite value.
@pytest.mark.parametrize(
    "value",
    [
        0.0,
        -0.0,
        1.0,
        100.0,
        25.5,
        1e-21,
        1e-100,
        5e-324,
        1.2345678901234567e-10,
        0.00012345678901234567,
        1.7976931348623157e308,
    ],
)
def test_float_convertor_url_roundtrip(test_client_factory: TestClientFactory, value: float) -> None:
    def endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"value": request.path_params["value"]})

    app = Router(routes=[Route("/{value:float}", endpoint=endpoint, name="float")])
    client = test_client_factory(app)

    path = app.url_path_for("float", value=value)
    response = client.get(path)

    assert response.status_code == 200
    assert response.json() == {"value": value}


@pytest.mark.parametrize(
    ("value", "expected_path"),
    [
        (0.0, "/0"),
        (-0.0, "/0"),
        (1.0, "/1"),
        (100.0, "/100"),
        (25.5, "/25.5"),
        (1e21, "/1000000000000000000000"),
        (1e-21, "/0.000000000000000000001"),
    ],
)
def test_float_convertor_url_format(value: float, expected_path: str) -> None:
    route = Route("/{value:float}", endpoint=JSONResponse({}), name="float")
    assert route.url_path_for("float", value=value) == expected_path


@pytest.mark.parametrize("value", [-1.0, float("nan"), float("inf"), float("-inf")])
def test_float_convertor_rejects_invalid_url_values(value: float) -> None:
    route = Route("/{value:float}", endpoint=JSONResponse({}), name="float")
    with pytest.raises(AssertionError):
        route.url_path_for("float", value=value)


@pytest.mark.parametrize(
    "param, status_code",
    [
        ("00000000-aaaa-ffff-9999-000000000000", 200),
        ("00000000aaaaffff9999000000000000", 200),
        ("00000000-AAAA-FFFF-9999-000000000000", 200),
        ("00000000AAAAFFFF9999000000000000", 200),
        ("not-a-uuid", 404),
    ],
)
def test_default_uuid_convertor(test_client_factory: TestClientFactory, param: str, status_code: int) -> None:
    def uuid_convertor(request: Request) -> JSONResponse:
        param = request.path_params["param"]
        assert isinstance(param, UUID)
        return JSONResponse("ok")

    app = Router(routes=[Route("/{param:uuid}", endpoint=uuid_convertor)])

    client = test_client_factory(app)
    response = client.get(f"/{param}")
    assert response.status_code == status_code
