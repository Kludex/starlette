from starlette import PlainTextResponse, FileResponse
from aiofiles.os import stat as aio_stat
import os
import stat


class StaticFile:
    def __init__(self, *, path):
        self.path = path

    def __call__(self, scope):
        if scope["method"] not in ("GET", "HEAD"):
            return PlainTextResponse("Method not allowed", status_code=406)
        return _StaticFileResponder(scope, path=self.path)


class StaticFiles:
    def __init__(self, *, directory):
        self.directory = directory
        self.config_checked = False

    def __call__(self, scope):
        if scope["method"] not in ("GET", "HEAD"):
            return PlainTextResponse("Method not allowed", status_code=406)
        path = os.path.normpath(os.path.join(*scope["path"].split("/")))
        if path.startswith(".."):
            return PlainTextResponse("Not found", status_code=404)
        path = os.path.join(self.directory, path)
        if self.config_checked:
            check_directory = None
        else:
            check_directory = self.directory
            self.config_checked = True
        return _StaticFilesResponder(scope, path=path, check_directory=check_directory)


class _StaticFileResponder:
    def __init__(self, scope, path):
        self.scope = scope
        self.path = path

    async def __call__(self, receive, send):
        try:
            stat_result = await aio_stat(self.path)
        except FileNotFoundError:
            raise RuntimeError("StaticFile at path '%s' does not exist." % self.path)
        else:
            mode = stat_result.st_mode
            if not stat.S_ISREG(mode):
                raise RuntimeError("StaticFile at path '%s' is not a file." % self.path)

        response = FileResponse(self.path, stat_result=stat_result)
        await response(receive, send)


class _StaticFilesResponder:
    def __init__(self, scope, path, check_directory=None):
        self.scope = scope
        self.path = path
        self.check_directory = check_directory

    async def check_directory_configured_correctly(self):
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

    async def __call__(self, receive, send):
        if self.check_directory is not None:
            await self.check_directory_configured_correctly()

        try:
            stat_result = await aio_stat(self.path)
        except FileNotFoundError:
            response = PlainTextResponse("Not found", status_code=404)
        else:
            mode = stat_result.st_mode
            if not stat.S_ISREG(mode):
                response = PlainTextResponse("Not found", status_code=404)
            else:
                response = FileResponse(self.path, stat_result=stat_result)

        await response(receive, send)
