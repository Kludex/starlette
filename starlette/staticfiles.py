import importlib.util
import os
import stat
import typing
from email.utils import parsedate

from aiofiles.os import stat as aio_stat

from starlette.datastructures import Headers
from starlette.responses import FileResponse, PlainTextResponse, Response
from starlette.types import Receive, Scope, Send


class NotModifiedResponse(Response):
    NOT_MODIFIED_HEADERS = (
        "cache-control",
        "content-location",
        "date",
        "etag",
        "expires",
        "vary",
    )

    def __init__(self, headers: Headers):
        return super().__init__(
            status_code=304,
            headers={
                name: value
                for name, value in headers.items()
                if name in self.NOT_MODIFIED_HEADERS
            },
        )


class StaticFiles:
    def __init__(
        self,
        *,
        directory: str = None,
        packages: typing.List[str] = None,
        check_dir: bool = True,
    ) -> None:
        self.directory = directory
        self.packages = packages
        self.all_directories = self.get_directories(directory, packages)
        self.config_checked = False
        if check_dir and directory is not None and not os.path.isdir(directory):
            raise RuntimeError(f"Directory '{directory}' does not exist")

    def get_directories(
        self, directory: str = None, packages: typing.List[str] = None
    ) -> typing.List[str]:
        directories = []
        if directory is not None:
            directories.append(directory)
        for package in packages or []:
            spec = importlib.util.find_spec(package)
            assert spec is not None, f"Package {package!r} could not be found."
            assert (
                spec.origin is not None
            ), "Directory 'statics' in package {package!r} could not be found."
            directory = os.path.normpath(os.path.join(spec.origin, "..", "statics"))
            assert os.path.isdir(
                directory
            ), "Directory 'statics' in package {package!r} could not be found."
            directories.append(directory)
        return directories

    def get_path(self, scope: Scope) -> str:
        return os.path.normpath(os.path.join(*scope["path"].split("/")))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        assert scope["type"] == "http"

        if not self.config_checked:
            await self.check_config()
            self.config_checked = True

        path = self.get_path(scope)
        method = scope["method"]
        headers = Headers(scope=scope)
        response = await self.get_response(path, method, headers)
        await response(scope, receive, send)

    async def get_response(
        self, path: str, method: str, request_headers: Headers
    ) -> Response:
        if method not in ("GET", "HEAD"):
            return PlainTextResponse("Method Not Allowed", status_code=405)

        if path.startswith(".."):
            return PlainTextResponse("Not Found", status_code=404)

        stat_result = None
        for directory in self.all_directories:
            full_path = os.path.join(directory, path)
            try:
                stat_result = await aio_stat(full_path)
            except FileNotFoundError:
                pass
            else:
                break

        if stat_result is None:
            return PlainTextResponse("Not Found", status_code=404)

        mode = stat_result.st_mode
        if not stat.S_ISREG(mode):
            return PlainTextResponse("Not Found", status_code=404)

        response = FileResponse(full_path, stat_result=stat_result, method=method)
        if self.is_not_modified(response.headers, request_headers):
            return NotModifiedResponse(response.headers)
        return response

    async def check_config(self) -> None:
        """
        Perform a one-off configuration check that StaticFiles is actually
        pointed at a directory, so that we can raise loud errors rather than
        just returning 404 responses.
        """
        if self.directory is None:
            return

        try:
            stat_result = await aio_stat(self.directory)
        except FileNotFoundError:
            raise RuntimeError(
                f"StaticFiles directory '{self.directory}' does not exist."
            )
        if not (stat.S_ISDIR(stat_result.st_mode) or stat.S_ISLNK(stat_result.st_mode)):
            raise RuntimeError(
                f"StaticFiles path '{self.directory}' is not a directory."
            )

    def is_not_modified(
        self, response_headers: Headers, request_headers: Headers
    ) -> bool:
        try:
            if_none_match = request_headers["if-none-match"]
            etag = response_headers["etag"]
            if if_none_match == etag:
                return True
        except KeyError:
            pass

        try:
            if_modified_since = parsedate(request_headers["if-modified-since"])
            last_modified = parsedate(response_headers["last-modified"])
            if (
                if_modified_since is not None
                and last_modified is not None
                and if_modified_since >= last_modified
            ):
                return True
        except KeyError:
            pass

        return False
