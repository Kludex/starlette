import inspect
import typing

from starlette.responses import Response
from starlette.routing import BaseRoute, Route

try:
    import yaml
except ImportError:  # pragma: nocover
    yaml = None  # type: ignore


class OpenAPIResponse(Response):
    media_type = "application/vnd.oai.openapi"

    def render(self, content: typing.Any) -> bytes:
        assert yaml is not None, "`pyyaml` must be installed to use OpenAPIResponse."
        assert isinstance(
            content, dict
        ), "The schema passed to OpenAPIResponse should be a dictionary."
        return yaml.dump(content, default_flow_style=False).encode("utf-8")


class BaseSchemaGenerator:
    def get_schema(self, routes: typing.List[BaseRoute]) -> dict:
        raise NotImplementedError()  # pragma: no cover


class SchemaGenerator(BaseSchemaGenerator):
    def __init__(self, base_schema: dict) -> None:
        assert yaml is not None, "`pyyaml` must be installed to use SchemaGenerator."
        self.base_schema = base_schema

    def get_schema(self, routes: typing.List[BaseRoute]) -> dict:
        paths = {}  # type: dict

        for route in routes:
            if not isinstance(route, Route) or not route.include_in_schema:
                continue

            if inspect.isfunction(route.endpoint) or inspect.ismethod(route.endpoint):
                docstring = route.endpoint.__doc__
                for method in route.methods or ["GET"]:
                    if method == "HEAD":
                        continue
                    if route.path not in paths:
                        paths[route.path] = {}
                    data = yaml.safe_load(docstring) if docstring else {}
                    paths[route.path][method.lower()] = data
            else:
                for method in ["get", "post", "put", "patch", "delete", "options"]:
                    if not hasattr(route.endpoint, method):
                        continue
                    docstring = getattr(route.endpoint, method).__doc__
                    if route.path not in paths:
                        paths[route.path] = {}
                    data = yaml.safe_load(docstring) if docstring else {}
                    paths[route.path][method] = data

        schema = dict(self.base_schema)
        schema["paths"] = paths
        return schema
