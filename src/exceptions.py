""" Exceptions raised by the server.

"""

import traceback

from apiflask import HTTPError


class APIException(HTTPError):
    def __init__(
        self,
        status_code: int,
        *args,
        message: str | None = None,
        detail: dict | None = None,
        **kwargs,
    ):
        # create a *fresh* dict each time
        if detail is None:
            detail = {}

        # copy instead of mutating caller’s dict
        safe_detail = dict(detail)

        super().__init__(
            status_code=status_code,
            message="",
            detail=safe_detail,
            extra_data=kwargs,
        )

        self.message = " ".join(map(str, args)) if message is None else message

        if not safe_detail:
            self.detail |= kwargs  # same semantics, but safe

    def repr_attr(self):
        return (
            ["status_code", "message"]
            + list(self.detail.keys())
            + list(self.extra_data.keys())
        )

    def __repr__(self):
        cname = self.__class__.__name__
        vattr = [(a, getattr(self, a, None)) for a in self.repr_attr()]
        pattr = [f"{a}={v!r}" for a, v in vattr if v is not None]
        p = ", ".join(pattr)
        return f"{cname}({p})"


# ------------------------------------------
#  Exceptions raised on bad requests (400)
# ------------------------------------------


class DataError(APIException):
    """The request format is wrong (e.g. missing elements)"""

    def __init__(self, *args, **kwargs):
        super().__init__(400, *args, **kwargs)


class InvalidError(APIException):
    """A value is bad in request (but in correct format)"""

    def __init__(self, *args, **kwargs):
        super().__init__(400, *args, **kwargs)


class AuthorizationError(APIException):
    """The user is not authorized to do this"""

    def __init__(self, *args, **kwargs):
        super().__init__(403, *args, **kwargs)


class AuthenticationError(APIException):
    """The user is not authorized to do this"""

    def __init__(self, *args, **kwargs):
        super().__init__(401, *args, **kwargs)


class NotFoundError(APIException):
    """Entity not found"""

    def __init__(self, entity: str = None, *args, **kwargs):
        super().__init__(404, *args, entity=entity, **kwargs)
        self.entity = entity

    def repr_attr(self):
        return super().repr_attr() + ["entity"]


class NotAllowedError(APIException):
    """The request is not allowed"""

    def __init__(self, *args, **kwargs):
        super().__init__(405, *args, **kwargs)


class ConflictError(APIException):
    """The request conflicts with the current state"""

    def __init__(self, *args, **kwargs):
        super().__init__(409, *args, **kwargs)


# ------------------------------------------
#  Exceptions raised on server error (500)
# ------------------------------------------


BACKEND_SERVICES = ["ckan", "minio", "postgresql", "ontop", "keycloak", "kubernetes"]


def validate_service(svc):
    if svc is not None and svc not in BACKEND_SERVICES:
        raise ValueError("Internal Error: bad backend", svc)


class InternalException(APIException, RuntimeError):
    """An exception was caught by the front end.

    This would normally indicate a bug, or other type of problem in the
    server.
    """

    def __init__(self, exc):
        super().__init__(
            500, *exc.args, message=repr(exc), format_exc=traceback.format_exc()
        )


class BackendError(APIException, RuntimeError):
    """Communication to another service failed.

    This exception is raised when the service (or communication with it)
    failed in an unpredictable way (maybe hardware failure or bug).

    If instead the service refused to honor some user request, then
    more specific exceptions should be thrown.

    Other services are:
    - ckan
    - minio
    - postgresql
    - ontop
    - keycloak
    - kubernetes
    """

    def __init__(self, svc: str = None, *args, **kwargs):
        super().__init__(502, *args, **kwargs)
        validate_service(svc)
        self.svc = svc

    def repr_attr(self):
        return super().repr_attr() + ["svc"]


class BackendLogicError(APIException):
    """Some service responded in an unexpected way.

    This probably indicates a bug in the STELAR API service.
    """

    def __init__(self, svc: str = None, *args, **kwargs):
        super().__init__(502, *args, **kwargs)
        validate_service(svc)
        self.svc = svc

    def repr_attr(self):
        return super().repr_attr() + ["svc"]
