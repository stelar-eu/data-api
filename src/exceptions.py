""" Exceptions raised by the server.

"""


class APIException(Exception):
    """These are to be reported to the client as part of the response.
    They come along with an appropriate status code.
    """

    def __init__(self, status_code, message: str = None, *args, **kwargs):
        super().__init__(*args)
        self.status_code = status_code

        # A message can be constructed explicitly, or as a concatenation of
        # positional arguments
        if message is None:
            self.message = " ".join(str(a) for a in args)
        else:
            self.message = message

        self.details = kwargs

    def repr_attr(self):
        return ["status_code", "message"] + list(self.details.keys())

    def __repr__(self):
        cname = self.__class__.__name__
        pargs = [repr(a) for a in self.args]
        vattr = [(a, getattr(self, a, None)) for a in self.repr_attr()]
        pattr = [f"{a}={v!r}" for a, v in vattr if v is not None]
        p = ", ".join(pargs + pattr)
        return f"{cname}({p})"


# ------------------------------------------
#  Exceptions raised on bad requests (400)
# ------------------------------------------


class DataError(APIException):
    """The request format is wrong (e.g. missing elements)"""

    def __init__(self, *args, **kwargs):
        super().__init__(400, *args, **kwargs)


class AuthorizationError(APIException):
    """The user is not authorized to do this"""

    def __init__(self, *args, **kwargs):
        super().__init__(403, *args, **kwargs)


class NotFoundError(APIException):
    """Entity not found"""

    def __init__(self, entity: str = None, *args, **kwargs):
        super().__init__(404, *args, **kwargs)
        self.entity = entity

    def repr_attr(self):
        return super().repr_attr() + ["entity"]


class ValidationError(APIException):
    """A value is bad in request (but in correct format)"""

    def __init__(self, *args, **kwargs):
        super().__init__(409, *args, **kwargs)


# ------------------------------------------
#  Exceptions raised on server error (500)
# ------------------------------------------


BACKEND_SERVICES = ["ckan", "minio", "postgresql", "ontop", "keycloak", "kubernetes"]


def validate_service(svc):
    if svc is not None and svc not in BACKEND_SERVICES:
        raise ValueError("Internal Error: bad backend", svc)


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
        super().__init__(500, *args, **kwargs)
        validate_service(svc)
        self.svc = svc

    def repr_attr(self):
        return super().repr_attr() + ["svc"]


class BackendLogicError(APIException):
    """Some service responded in an unexpected way.

    This probably indicates a bug in the STELAR API service.
    """

    def __init__(self, svc: str = None, *args, **kwargs):
        super().__init__(500, *args, **kwargs)
        validate_service(svc)
        self.svc = svc

    def repr_attr(self):
        return super().repr_attr() + ["svc"]
