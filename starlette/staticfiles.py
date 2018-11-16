import os
import stat
import typing
from email.utils import parsedate

from aiofiles.os import stat as aio_stat

from starlette.datastructures import Headers
from starlette.responses import FileResponse, PlainTextResponse, Response
from starlette.types import ASGIInstance, Receive, Scope, Send

NOT_MODIFIED_HEADERS = (
    "cache-control",
    "content-location",
    "date",
    "etag",
    "expires",
    "vary",
)


class StaticFiles:
    def __init__(self, *, directory: str, check_dir: bool = True) -> None:
        if check_dir and not os.path.isdir(directory):
            raise RuntimeError("Directory '%s' does not exist" % directory)
        self.directory = directory
        self.config_checked = False

    def __call__(self, scope: Scope) -> ASGIInstance:
        assert scope["type"] == "http"
        if scope["method"] not in ("GET", "HEAD"):
            return PlainTextResponse("Method Not Allowed", status_code=405)
        path = os.path.normpath(os.path.join(*scope["path"].split("/")))
        if path.startswith(".."):
            return PlainTextResponse("Not Found", status_code=404)
        path = os.path.join(self.directory, path)
        if self.config_checked:
            check_directory = None
        else:
            check_directory = self.directory
            self.config_checked = True
        return _StaticFilesResponder(scope, path=path, check_directory=check_directory)


class _StaticFilesResponder:
    def __init__(self, scope: Scope, path: str, check_directory: str = None) -> None:
        self.scope = scope
        self.path = path
        self.check_directory = check_directory

    async def check_directory_configured_correctly(self) -> None:
        """
        Perform a one-off configuration check that StaticFiles is actually
        pointed at a directory, so that we can raise loud errors rather than
        just returning 404 responses.
        """
        directory = self.check_directory
        try:
            stat_result = await aio_stat(directory)
        except FileNotFoundError:
            raise RuntimeError("StaticFiles directory '%s' does not exist." % directory)
        if not (stat.S_ISDIR(stat_result.st_mode) or stat.S_ISLNK(stat_result.st_mode)):
            raise RuntimeError("StaticFiles path '%s' is not a directory." % directory)

    def is_not_modified(self, stat_headers: typing.Dict[str, str]) -> bool:
        etag = stat_headers["etag"]
        last_modified = stat_headers["last-modified"]
        req_headers = Headers(scope=self.scope)
        if etag == req_headers.get("if-none-match"):
            return True
        if "if-modified-since" not in req_headers:
            return False
        last_req_time = req_headers["if-modified-since"]
        return parsedate(last_req_time) >= parsedate(last_modified)  # type: ignore

    def not_modified_response(self, stat_headers: dict) -> Response:
        headers = {
            name: value
            for name, value in stat_headers.items()
            if name in NOT_MODIFIED_HEADERS
        }
        return Response(status_code=304, headers=headers)

    async def __call__(self, receive: Receive, send: Send) -> None:
        if self.check_directory is not None:
            await self.check_directory_configured_correctly()

        try:
            stat_result = await aio_stat(self.path)
        except FileNotFoundError:
            response = PlainTextResponse("Not Found", status_code=404)  # type: Response
        else:
            mode = stat_result.st_mode
            if not stat.S_ISREG(mode):
                response = PlainTextResponse("Not Found", status_code=404)
            else:
                stat_headers = FileResponse.get_stat_headers(stat_result)
                if self.is_not_modified(stat_headers):
                    response = self.not_modified_response(stat_headers)
                else:
                    response = FileResponse(
                        self.path, stat_result=stat_result, method=self.scope["method"]
                    )

        await response(receive, send)
