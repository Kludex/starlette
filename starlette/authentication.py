import asyncio
import functools
import inspect
import typing

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response


def has_required_scope(request: Request, scopes: typing.Sequence[str]) -> bool:
    for scope in scopes:
        if scope not in request.auth.scopes:
            return False
    return True


def requires(
    scopes: typing.Union[str, typing.Sequence[str]],
    status_code: int = 403,
    redirect: str = None,
) -> typing.Callable:
    scopes_list = [scopes] if isinstance(scopes, str) else list(scopes)

    def decorator(func: typing.Callable) -> typing.Callable:
        sig = inspect.signature(func)
        for idx, parameter in enumerate(sig.parameters.values()):
            if parameter.name == "request":
                break
        else:
            raise Exception(f'No "request" argument on function "{func}"')

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def wrapper(*args: typing.Any, **kwargs: typing.Any) -> Response:
                request = kwargs.get("request", args[idx])
                assert isinstance(request, Request)

                if not has_required_scope(request, scopes_list):
                    if redirect is not None:
                        return RedirectResponse(url=request.url_for(redirect))
                    raise HTTPException(status_code=status_code)
                return await func(*args, **kwargs)

            return wrapper

        @functools.wraps(func)
        def sync_wrapper(*args: typing.Any, **kwargs: typing.Any) -> Response:
            # Support either `func(request)` or `func(self, request)`
            request = kwargs.get("request", args[idx])
            assert isinstance(request, Request)

            if not has_required_scope(request, scopes_list):
                if redirect is not None:
                    return RedirectResponse(url=request.url_for(redirect))
                raise HTTPException(status_code=status_code)
            return func(*args, **kwargs)

        return sync_wrapper

    return decorator


class AuthenticationError(Exception):
    pass


class AuthenticationBackend:
    async def authenticate(
        self, request: Request
    ) -> typing.Optional[typing.Tuple["AuthCredentials", "BaseUser"]]:
        raise NotImplemented()  # pragma: no cover


class AuthCredentials:
    def __init__(self, scopes: typing.Sequence[str] = None):
        self.scopes = [] if scopes is None else list(scopes)


class BaseUser:
    @property
    def is_authenticated(self) -> bool:
        raise NotImplemented()  # pragma: no cover

    @property
    def display_name(self) -> str:
        raise NotImplemented()  # pragma: no cover

    @property
    def identity(self) -> str:
        raise NotImplemented()  # pragma: no cover


class SimpleUser(BaseUser):
    def __init__(self, username: str) -> None:
        self.username = username

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.username


class UnauthenticatedUser(BaseUser):
    @property
    def is_authenticated(self) -> bool:
        return False

    @property
    def display_name(self) -> str:
        return ""
