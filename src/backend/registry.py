import requests
import logging
import kutils

from typing import TYPE_CHECKING, Optional, Dict, Any
from urllib.parse import urljoin

from exceptions import (
    BackendError,
    BackendLogicError,
    AuthorizationError,
    DataError,
    InvalidError,
    NotFoundError,
)


from requests import Response

logger = logging.getLogger(__name__)

registry_client = None
api_url = None


def initialize_registry_client(config):
    """Initialize the Registry client.

    This should be called once at the start of the application.
    """
    global registry_client
    registry_client = requests.Session()

    registry_client.headers.update(
        {
            "Content-Type": "application/json",
        }
    )
    global api_url
    api_url = urljoin(config["REGISTRY_API"], "/api/v1/")


def raw_request(
    endpoint: str,
    *,
    json: Optional[dict] = None,
    method: str = "GET",
    headers: Dict[str, str] = {},
    params: Optional[Dict[str, Any]] = None,
    **kwargs,
):
    """
    Sends a request to the Quay Registry API

    Args:
        endpoint (str): The API endpoint (relative to `api_url`). Can include query parameters.
        params (dict, optional): URL query parameters.
        json (dict, optional): JSON body to send in the request.
        headers (dict, optional): Additional headers to send with the request.
        **kwargs: Additional arguments to pass to the requests library.

    Returns:
        Response: The response object from the requests library.

    Raises:
        BackendError: If there is an error with the backend request.
    """
    url = urljoin(api_url, endpoint.lstrip("/"))
    logger.debug("Quay API URL: %s", url)

    if method.upper() == "GET":
        if json is not None or kwargs:
            raise InvalidError("GET request cannot have a body")

    if kwargs:
        if json is None:
            request_args = kwargs
        else:
            request_args = json | kwargs
    else:
        request_args = json

    # Prepare headers, including Authorization if token is present
    headers = {"Authorization": "Bearer " + kutils.current_token()} | headers

    try:
        response = registry_client.request(
            method=method.upper(),
            url=url,
            json=request_args,
            headers=headers,
            params=params,
        )
    except Exception as e:
        message = "Request to Quay Image Registry failed: " + repr(e)
        detail = {
            "url": url,
            "request_args": request_args,
            "json": request_args,
        }
        raise BackendError(500, "quay", *e.args, message=message, detail=detail) from e

    logger.debug("Quay API response: Status: %d", response.status_code)
    return response


def raise_registry_error(response: Response, context: dict):
    if response.status_code == 401:
        raise AuthorizationError("Authorization failed", detail=response.json())
    if response.status_code == 403:
        raise AuthorizationError("Authorization failed", detail=response.json())
    if response.status_code == 404:
        raise NotFoundError("Resource not found", detail=response.json())
    if response.status_code == 400:
        raise DataError("Bad request", detail=response.json())
    if response.status_code == 500:
        raise BackendLogicError("Backend error", detail=response.json())

    return response


def quay_request(
    endpoint: str,
    *,
    json: Optional[dict] = None,
    method: str = "GET",
    headers: Dict[str, str] = {},
    params: Optional[Dict[str, Any]] = None,
    **kwargs,
):
    """Make a request to the Quay Registry API and raise on error."""
    response = raw_request(
        endpoint=endpoint,
        json=json,
        method=method,
        headers=headers,
        params=params,
        **kwargs,
    )
    raise_registry_error(response, context={})
    logger.debug(f"Quay Response Body: {response.text}")
    if response.status_code == 204:
        return True
    jsobj = response.json()
    return jsobj
