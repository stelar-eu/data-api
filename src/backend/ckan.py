"""Access CKAN
"""

from __future__ import annotations

import logging
import traceback
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin

import requests
from flask import current_app

from exceptions import (
    BackendError,
    BackendLogicError,
    DataError,
    NotFoundError,
    ValidationError,
)

if TYPE_CHECKING:
    from requests import Response

logger = logging.getLogger(__name__)


ckan_client = None
api_url = None


def initialize_ckan_client(config):
    """Initialize the CKAN client.

    This should be called once at the start of the application.
    """
    global ckan_client
    ckan_client = requests.Session()

    ckan_client.headers.update(
        {
            "Authorization": config["CKAN_ADMIN_TOKEN"],
            "Content-Type": "application/json",
        }
    )
    global api_url
    api_url = config["CKAN_API"]


def raw_request(
    endpoint, *, json: Optional[dict] = None, headers: dict = {}, params=None, **kwargs
):
    """
    Sends a request to the CKAN API

    Args:
        endpoint (str): The API endpoint (relative to `api_url`). Can include query parameters.
        params (dict, optional): URL query parameters.
        headers (dict, optional): Additional request headers.
        json (dict, optional): JSON data to be sent in the body.

        **kwargs: These are added to json

    Returns:
        requests.Response: The response object from the API.
    """
    # Fetch the app config to gain access to URLs.
    config = current_app.config["settings"]

    # The base url of the CKAN API endpoint
    # Should be sth like http://ckan:5000/api/3/action/
    # api_url = config["CKAN_API"]

    # Combine base_url with the endpoint
    url = urljoin(api_url, endpoint)

    # Prepare headers, defaulting to Authorization if token is present and Content-Type
    # headers = {"Authorization": config["CKAN_ADMIN_TOKEN"]} | headers

    # Make the request using the provided method, url, params, data, json, and headers
    if kwargs:
        if json is None:
            request_args = kwargs
        else:
            request_args = json | kwargs
    else:
        request_args = json

    logger.debug("CKAN API call: %s %s", url, request_args)
    try:
        # response = requests.post(
        response = ckan_client.post(
            url=url,
            json=request_args,
            headers=headers,
            params=params,
        )
    except Exception as e:
        message = "Request to CKAN failed: " + repr(e)
        detail = {
            "url": url,
            "request_args": str(request_args),
            "format_exc": traceback.format_exc(),
        }
        raise BackendError(500, "ckan", *e.args, message=message, detail=detail) from e

    logger.debug("CKAN API response: %d", response.status_code)
    return response


def request(
    endpoint, *, json: Optional[dict] = None, headers: dict = {}, params=None, **kwargs
):
    """Make a CKAN request and raise on error."""
    # Raise an exception for HTTP errors (4xx, 5xx responses)
    response = raw_request(
        endpoint, json=json, headers=headers, params=params, **kwargs
    )
    response.raise_for_status()
    return response


def raise_ckan_error(response: Response, context: dict):
    if 200 <= response.status_code < 300:
        return
    if 300 <= response.status_code < 400:
        raise BackendLogicError("ckan", "Unexpected redirect", response.status_code)
    if 400 <= response.status_code:
        c = response.json()
        etype = c["error"]["__type"]
        emsg = c["error"]["message"]
        context_detail = {
            k: v for k, v in context.items() if isinstance(v, (int, str, float, bool))
        }

        match etype:
            case "Integrity Error":
                raise DataError(emsg, detail=context_detail)
            case "Authorization Error":
                raise BackendLogicError("ckan", etype, emsg, detail=context_detail)
            case "Not Found Error":
                entity = context.get("entity", None)
                raise NotFoundError(entity, emsg, detail=context_detail)
            case "Validation Error":
                raise ValidationError(emsg, detail=context_detail)
            case "Search Query Error":
                raise DataError(etype, emsg, detail=context_detail)
            case "Search Error":
                raise ValidationError(etype, emsg, detail=context_detail)
            case "Search Index Error" | "Solr Connection Error" | "Internal Server Error":
                raise BackendError("ckan", etype, emsg, detail=context_detail)
            case _:
                raise BackendLogicError(
                    "ckan", "Unknown error type", etype, detail=context_detail
                )
    raise BackendLogicError(
        "ckan", "Unexpected status code", response.status_code, detail=context_detail
    )


def ckan_request(
    endpoint,
    *,
    json: Optional[dict] = None,
    headers: dict = {},
    params=None,
    context={},
    **kwargs,
):
    """Make a CKAN request and return the JSON response."""
    # Raise an exception for HTTP errors (4xx, 5xx responses)
    response = raw_request(
        endpoint, json=json, headers=headers, params=params, **kwargs
    )
    raise_ckan_error(response, context)
    jsobj = response.json()
    obj = jsobj["result"]
    return obj
