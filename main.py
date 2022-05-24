import asyncio

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Route


async def homepage(request):
    await asyncio.sleep(2)
    return JSONResponse({"hello": "world"})


routes = [
    Route("/", homepage, name="homepage"),
]


class CustomHeaderMiddleware1(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        return await call_next(request)


class CustomHeaderMiddleware2(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        return await call_next(request)


all_middleware = [
    Middleware(CustomHeaderMiddleware1),
    Middleware(CustomHeaderMiddleware2),
]


app = Starlette(debug=True, routes=routes, middleware=all_middleware)
