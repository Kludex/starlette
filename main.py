from re import I

import requests

from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import FileResponse
from starlette.routing import Route


async def stream_file_response(request: Request) -> FileResponse:
    return FileResponse(path="/home/marcelo/Downloads/go1.17.linux-amd64.tar.gz")


app = Starlette(routes=[Route("/file", stream_file_response, methods=["GET"])])

if __name__ == "__main__":
    response = requests.get("http://localhost:8000/file", stream=True)
    from time import sleep

    sleep(0.5)
    response.close()
