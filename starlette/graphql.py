from starlette import status
from starlette.responses import PlainTextResponse, Response, JSONResponse
from starlette.requests import Request
from starlette.types import ASGIInstance, Receive, Scope, Send
import asyncio
import functools
import typing

try:
    import graphene
    from graphql.execution.executors.asyncio import AsyncioExecutor
    from graphql.error import format_error as format_graphql_error
    from graphql.error import GraphQLError
except ImportError:  # pragma: nocover
    graphene = None  # type: ignore
    AsyncioExecutor = None  # type: ignore
    format_graphql_error = None  # type: ignore
    GraphQLError = None  # type: ignore


class GraphQLApp:
    def __init__(self, schema: "graphene.Schema", executor: typing.Any = None) -> None:
        self.schema = schema
        self.executor = executor
        self.is_async = isinstance(executor, AsyncioExecutor)

    def __call__(self, scope: Scope) -> ASGIInstance:
        return functools.partial(self.asgi, scope=scope)

    async def asgi(self, receive: Receive, send: Send, scope: Scope) -> None:
        request = Request(scope, receive=receive)
        response = await self.handler(request)
        await response(receive, send)

    async def handler(self, request: Request) -> Response:
        if request.method == "GET":
            data = request.query_params  # type: typing.Mapping[str, typing.Any]

        elif request.method == "POST":
            content_type = request.headers.get("Content-Type", "")

            if "application/json" in content_type:
                data = await request.json()
            elif "application/graphql" in content_type:
                body = await request.body()
                text = body.decode()
                data = {"query": text}
            elif "query" in request.query_params:
                data = request.query_params
            else:
                return PlainTextResponse(
                    "Unsupported Media Type",
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                )

        else:
            return PlainTextResponse(
                "Method Not Allowed", status_code=status.HTTP_405_METHOD_NOT_ALLOWED
            )

        try:
            query = data["query"]
            variables = data.get("variables")
            operation_name = data.get("operationName")
        except KeyError:
            return PlainTextResponse(
                "No GraphQL query found in the request",
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        result = await self.execute(query, variables)
        error_data = (
            [format_graphql_error(err) for err in result.errors]
            if result.errors
            else None
        )
        response_data = {"data": result.data, "errors": error_data}
        status_code = (
            status.HTTP_400_BAD_REQUEST if result.errors else status.HTTP_200_OK
        )
        return JSONResponse(response_data, status_code=status_code)

    async def execute(self, query, variables=None, operation_name=None):  # type: ignore
        if self.is_async:
            return await self.schema.execute(
                query,
                variables=variables,
                operation_name=operation_name,
                executor=self.executor,
                return_promise=True,
            )
        else:
            func = functools.partial(
                self.schema.execute, variables=variables, operation_name=operation_name
            )
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, func, query)
