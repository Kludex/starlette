from starlette import PlainTextResponse, FileResponse
from aiofiles.os import stat as aio_stat
import os
import stat


class StaticFile:
    def __init__(self, *, path):
        self.path = path

    def __call__(self, scope):
        if scope['method'] not in ('GET', 'HEAD'):
            return PlainTextResponse('Method not allowed', status_code=406)
        return _StaticFileResponder(scope, path=self.path, allow_404=False)


class StaticFiles:
    def __init__(self, *, directory):
        self.directory = directory

    def __call__(self, scope):
        if scope['method'] not in ('GET', 'HEAD'):
            return PlainTextResponse('Method not allowed', status_code=406)
        split_path = scope['path'].split('/')
        path = os.path.join(self.directory, *split_path)
        return _StaticFileResponder(scope, path=path, allow_404=True)


class _StaticFileResponder:
    def __init__(self, scope, path, allow_404):
        self.scope = scope
        self.path = path
        self.allow_404 = allow_404

    async def __call__(self, receive, send):
        try:
            stat_result = await aio_stat(self.path)
        except FileNotFoundError:
            if not self.allow_404:
                raise RuntimeError("StaticFile at path '%s' does not exist." % self.path)
            response = PlainTextResponse('Not found', status_code=404)
        else:
            mode = stat_result.st_mode
            if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
                response = FileResponse(self.path, stat_result=stat_result)
            else:
                if not self.allow_404:
                    raise RuntimeError("StaticFile at path '%s' is not a file." % self.path)
                response = PlainTextResponse('Not found', status_code=404)
        await response(receive, send)
