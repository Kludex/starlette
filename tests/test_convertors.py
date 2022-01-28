from datetime import datetime

import pytest

from starlette import convertors
from starlette.convertors import Convertor, register_url_convertor
from starlette.responses import JSONResponse
from starlette.routing import Route, Router


@pytest.fixture(scope="module", autouse=True)
def refresh_convertor_types():
    convert_types = convertors.CONVERTOR_TYPES.copy()
    yield
    convertors.CONVERTOR_TYPES = convert_types


class DateTimeConvertor(Convertor):
    regex = "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(.[0-9]+)?"

    def convert(self, value: str) -> datetime:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")

    def to_string(self, value: datetime) -> str:
        return value.strftime("%Y-%m-%dT%H:%M:%S")


@pytest.fixture(scope="function")
def app() -> Router:
    register_url_convertor("datetime", DateTimeConvertor())

    def datetime_convertor(request):
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


def test_datetime_convertor(test_client_factory, app: Router):
    client = test_client_factory(app)
    response = client.get("/datetime/2020-01-01T00:00:00")
    assert response.json() == {"datetime": "2020-01-01T00:00:00"}

    assert (
        app.url_path_for("datetime-convertor", param=datetime(1996, 1, 22, 23, 0, 0))
        == "/datetime/1996-01-22T23:00:00"
    )
