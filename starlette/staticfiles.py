from __future__ import annotations

import errno
import importlib.util
import os
import stat
from email.utils import parsedate
from threading import Lock
from typing import BinaryIO, Union

import anyio
import anyio.to_thread

from starlette._utils import get_route_path
from starlette.datastructures import URL, Headers
from starlette.exceptions import HTTPException
from starlette.responses import FileResponse, RedirectResponse, Response
from starlette.types import Receive, Scope, Send
from starlette.websockets import WebSocketClose

PathLike = Union[str, "os.PathLike[str]"]


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
        super().__init__(
            status_code=304,
            headers={name: value for name, value in headers.items() if name in self.NOT_MODIFIED_HEADERS},
        )


class StaticFiles:
    def __init__(
        self,
        *,
        directory: PathLike | None = None,
        packages: list[str | tuple[str, str]] | None = None,
        html: bool = False,
        check_dir: bool = True,
        follow_symlink: bool = False,
    ) -> None:
        self.directory = directory
        self.packages = packages
        self.all_directories = self.get_directories(directory, packages)
        self.html = html
        self.config_checked = False
        self.follow_symlink = follow_symlink
        self._directory_anchors: dict[str, tuple[str, os.stat_result]] = {}
        self._directory_anchor_lock = Lock()
        if check_dir and directory is not None and not os.path.isdir(directory):
            raise RuntimeError(f"Directory '{directory}' does not exist")

    def get_directories(
        self,
        directory: PathLike | None = None,
        packages: list[str | tuple[str, str]] | None = None,
    ) -> list[PathLike]:
        """
        Given `directory` and `packages` arguments, return a list of all the
        directories that should be used for serving static files from.
        """
        directories = []
        if directory is not None:
            directories.append(directory)

        for package in packages or []:
            if isinstance(package, tuple):
                package, statics_dir = package
            else:
                statics_dir = "statics"
            spec = importlib.util.find_spec(package)
            assert spec is not None, f"Package {package!r} could not be found."
            assert spec.origin is not None, f"Package {package!r} could not be found."
            package_directory = os.path.normpath(os.path.join(spec.origin, "..", statics_dir))
            assert os.path.isdir(package_directory), (
                f"Directory '{statics_dir!r}' in package {package!r} could not be found."
            )
            directories.append(package_directory)

        return directories

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """
        The ASGI entry point.
        """
        if scope["type"] == "websocket":
            websocket_close = WebSocketClose()
            await websocket_close(scope, receive, send)
            return

        assert scope["type"] == "http"

        if not self.config_checked:
            await self.check_config()
            self.config_checked = True

        path = self.get_path(scope)
        response = await self.get_response(path, scope)
        await response(scope, receive, send)

    def get_path(self, scope: Scope) -> str:
        """
        Given the ASGI scope, return the `path` string to serve up,
        with OS specific path separators, and any '..', '.' components removed.
        """
        route_path = get_route_path(scope)
        return os.path.normpath(os.path.join(*route_path.split("/")))

    async def get_response(self, path: str, scope: Scope) -> Response:
        """
        Returns an HTTP response, given the incoming path, method and request headers.
        """
        if scope["method"] not in ("GET", "HEAD"):
            raise HTTPException(status_code=405)

        try:
            _, stat_result = await anyio.to_thread.run_sync(self.lookup_path, path)
        except PermissionError:
            raise HTTPException(status_code=401)
        except OSError as exc:
            # Filename is too long, so it can't be a valid static file.
            if exc.errno == errno.ENAMETOOLONG:
                raise HTTPException(status_code=404)

            raise exc
        except ValueError:
            # Null bytes or other invalid characters in the path.
            raise HTTPException(status_code=404)

        if stat_result and stat.S_ISREG(stat_result.st_mode):
            # We have a static file to serve.
            response = await self._open_file_response(path, scope)
            if response is not None:
                return response

        elif stat_result and stat.S_ISDIR(stat_result.st_mode) and self.html:
            # We're in HTML mode, and have got a directory URL.
            # Check if we have 'index.html' file to serve.
            index_path = os.path.join(path, "index.html")
            _, stat_result = await anyio.to_thread.run_sync(self.lookup_path, index_path)
            if stat_result is not None and stat.S_ISREG(stat_result.st_mode):
                if not scope["path"].endswith("/"):
                    # Directory URLs should redirect to always end in "/".
                    url = URL(scope=scope)
                    url = url.replace(path=url.path + "/")
                    return RedirectResponse(url=url)
                response = await self._open_file_response(index_path, scope)
                if response is not None:
                    return response

        if self.html:
            # Check for '404.html' if we're in HTML mode.
            _, stat_result = await anyio.to_thread.run_sync(self.lookup_path, "404.html")
            if stat_result and stat.S_ISREG(stat_result.st_mode):
                response = await self._open_file_response("404.html", scope, status_code=404)
                if response is not None:
                    return response
        raise HTTPException(status_code=404)

    async def _open_file_response(self, path: str, scope: Scope, status_code: int = 200) -> Response | None:
        try:
            opened = await anyio.to_thread.run_sync(self._open_path, path)
        except PermissionError:
            raise HTTPException(status_code=401)
        except OSError as exc:
            if exc.errno == errno.ENAMETOOLONG:
                return None
            raise

        if opened is None:
            return None

        full_path, stat_result, file = opened
        try:
            if status_code == 200:
                response = self.file_response(full_path, stat_result, scope)
            else:
                response = FileResponse(full_path, stat_result=stat_result, status_code=status_code)
        except BaseException:
            file.close()
            raise

        if isinstance(response, FileResponse):
            response._file = file
        else:
            file.close()
        return response

    def _open_path(self, path: str) -> tuple[str, os.stat_result, BinaryIO] | None:
        if path.startswith(("/", "\\")):
            return None

        for directory in self.all_directories:
            file: BinaryIO
            if self.follow_symlink:
                full_path = os.path.abspath(os.path.join(directory, path))
                directory_path = os.path.abspath(directory)
                if os.path.commonpath([full_path, directory_path]) != str(directory_path):
                    continue
                try:
                    file = open(full_path, "rb")
                except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
                    continue
            else:
                try:
                    directory_path, directory_stat = self._get_directory_anchor(directory)
                except (FileNotFoundError, NotADirectoryError):
                    continue
                full_path = os.path.abspath(os.path.join(directory_path, path))
                if os.path.commonpath([full_path, directory_path]) != str(directory_path):
                    continue
                try:
                    file = self._open_path_without_symlinks(directory_path, path, directory_stat)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.ENOTDIR, errno.EISDIR, errno.ELOOP):
                        continue
                    raise

            try:
                stat_result = os.fstat(file.fileno())
            except BaseException:
                file.close()
                raise
            if stat.S_ISREG(stat_result.st_mode):
                return full_path, stat_result, file
            file.close()
        return None

    @staticmethod
    def _open_path_without_symlinks(
        directory: PathLike, path: str, directory_stat: os.stat_result | None = None
    ) -> BinaryIO:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        supports_dir_fd = os.open in os.supports_dir_fd

        if not nofollow or not directory_flag or not supports_dir_fd:
            full_path = os.path.join(directory, path)
            if directory_stat is not None and not os.path.samestat(directory_stat, os.stat(directory)):
                raise OSError(errno.ELOOP, "Static files directory was replaced")
            file = open(full_path, "rb")
            try:
                resolved_path = os.path.realpath(full_path)
                directory_path = os.path.realpath(directory)
                current_directory_stat = os.stat(directory)
                opened_stat = os.fstat(file.fileno())
                resolved_stat = os.stat(resolved_path)
            except BaseException:
                file.close()
                raise
            if (
                (directory_stat is not None and not os.path.samestat(directory_stat, current_directory_stat))
                or os.path.commonpath([resolved_path, directory_path]) != str(directory_path)
                or not os.path.samestat(opened_stat, resolved_stat)
            ):
                file.close()
                raise OSError(errno.ELOOP, "Path changed or contains a symbolic link")
            return file

        normalized_path = os.path.normpath(path)
        parts = [part for part in normalized_path.split(os.sep) if part not in ("", ".")]
        if not parts or any(part == os.pardir for part in parts):
            raise FileNotFoundError(path)

        directory_fd = os.open(directory, os.O_RDONLY | directory_flag | nofollow | close_on_exec)
        file_fd: int | None = None
        try:
            if directory_stat is not None and not os.path.samestat(directory_stat, os.fstat(directory_fd)):
                raise OSError(errno.ELOOP, "Static files directory was replaced")
            for part in parts[:-1]:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | directory_flag | nofollow | close_on_exec,
                    dir_fd=directory_fd,
                )
                os.close(directory_fd)
                directory_fd = next_fd
            file_fd = os.open(parts[-1], os.O_RDONLY | nofollow | close_on_exec, dir_fd=directory_fd)
            file = os.fdopen(file_fd, "rb")
            file_fd = None
            return file
        finally:
            os.close(directory_fd)
            if file_fd is not None:
                os.close(file_fd)

    def _get_directory_anchor(self, directory: PathLike) -> tuple[str, os.stat_result]:
        directory_key = os.path.abspath(os.fspath(directory))
        with self._directory_anchor_lock:
            anchor = self._directory_anchors.get(directory_key)
            if anchor is None:
                directory_path = os.path.realpath(directory_key)
                anchor = directory_path, os.stat(directory_path)
                self._directory_anchors[directory_key] = anchor
            return anchor

    def lookup_path(self, path: str) -> tuple[str, os.stat_result | None]:
        # Reject absolute paths so they cannot escape the served directory.
        if path.startswith(("/", "\\")):
            return "", None
        for directory in self.all_directories:
            joined_path = os.path.join(directory, path)
            if self.follow_symlink:
                full_path = os.path.abspath(joined_path)
                directory = os.path.abspath(directory)
            else:
                try:
                    directory, _ = self._get_directory_anchor(directory)
                except (FileNotFoundError, NotADirectoryError):
                    continue
                full_path = os.path.realpath(os.path.join(directory, path))
            if os.path.commonpath([full_path, directory]) != str(directory):
                # Don't allow misbehaving clients to break out of the static files directory.
                continue
            try:
                return full_path, os.stat(full_path)
            except (FileNotFoundError, NotADirectoryError):
                continue
        return "", None

    def file_response(
        self,
        full_path: PathLike,
        stat_result: os.stat_result,
        scope: Scope,
        status_code: int = 200,
    ) -> Response:
        request_headers = Headers(scope=scope)

        response = FileResponse(full_path, status_code=status_code, stat_result=stat_result)
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
            stat_result = await anyio.to_thread.run_sync(os.stat, self.directory)
        except FileNotFoundError:
            raise RuntimeError(f"StaticFiles directory '{self.directory}' does not exist.")
        if not (stat.S_ISDIR(stat_result.st_mode) or stat.S_ISLNK(stat_result.st_mode)):
            raise RuntimeError(f"StaticFiles path '{self.directory}' is not a directory.")

    def is_not_modified(self, response_headers: Headers, request_headers: Headers) -> bool:
        """
        Given the request and response headers, return `True` if an HTTP
        "Not Modified" response could be returned instead.
        """
        if if_none_match := request_headers.get("if-none-match"):
            if if_none_match.strip() == "*":
                return True
            # The "etag" header is added by FileResponse, so it's always present.
            etag = response_headers["etag"]
            return etag in [tag.strip().removeprefix("W/") for tag in if_none_match.split(",")]

        try:
            if_modified_since = parsedate(request_headers["if-modified-since"])
            last_modified = parsedate(response_headers["last-modified"])
            if if_modified_since is not None and last_modified is not None and if_modified_since >= last_modified:
                return True
        except KeyError:
            pass

        return False
