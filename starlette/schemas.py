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


class EndpointInfo(typing.NamedTuple):
    path: str
    http_method: str
    func: typing.Callable


class BaseSchemaGenerator:
    def get_schema(self, routes: typing.List[BaseRoute]) -> dict:
        raise NotImplementedError()  # pragma: no cover

    def get_endpoints(
        self, routes: typing.List[BaseRoute]
    ) -> typing.List[EndpointInfo]:
        """
        Given the routes, yields the following information:

        - path
            eg: /users/
        - http_method
            one of 'get', 'post', 'put', 'patch', 'delete', 'options'
        - func
            method ready to extract the docstring
        """
        endpoints_info: list = []

        for route in routes:
            if not isinstance(route, Route) or not route.include_in_schema:
                continue

            if inspect.isfunction(route.endpoint) or inspect.ismethod(route.endpoint):
                for method in route.methods or ["GET"]:
                    if method == "HEAD":
                        continue
                    endpoints_info.append(
                        EndpointInfo(route.path, method.lower(), route.endpoint)
                    )
            else:
                for method in ["get", "post", "put", "patch", "delete", "options"]:
                    if not hasattr(route.endpoint, method):
                        continue
                    func = getattr(route.endpoint, method)
                    endpoints_info.append(
                        EndpointInfo(route.path, method.lower(), func)
                    )
        return endpoints_info

    def parse_docstring(self, func_or_method: typing.Callable) -> dict:
        """
        Given a function, parse the docstring as YAML and return a dictionary of info.
        """
        docstring = func_or_method.__doc__
        return yaml.safe_load(docstring) if docstring else {}


class SchemaGenerator(BaseSchemaGenerator):
    def __init__(self, base_schema: dict) -> None:
        self.base_schema = base_schema

    def get_schema(self, routes: typing.List[BaseRoute]) -> dict:
        schema = dict(self.base_schema)
        schema.setdefault("paths", {})
        endpoints_info = self.get_endpoints(routes)

        for endpoint in endpoints_info:
            if endpoint.path not in schema["paths"]:
                schema["paths"][endpoint.path] = {}
            schema["paths"][endpoint.path][endpoint.http_method] = self.parse_docstring(
                endpoint.func
            )
        return schema
