"""Access CKAN
"""

from __future__ import annotations

import logging
import traceback
from typing import TYPE_CHECKING, Optional
from urllib.parse import urljoin
from flask import current_app
import requests
import kutils
from psycopg2 import sql
import jwt
from datetime import datetime
import random
import string
from exceptions import (
    BackendError,
    BackendLogicError,
    DataError,
    InvalidError,
    NotFoundError,
)
from .redis import REDIS
from .pgsql import transaction, execSql

if TYPE_CHECKING:
    from requests import Response

logger = logging.getLogger(__name__)


ckan_client = None
api_url = None


def create_and_cache_user_token():
    user = kutils.current_user()
    response = raw_request(
        endpoint="api_token_create",
        json={"user": user["sub"], "name": "stelar-token"},
        admin=True,
    )
    raise_ckan_error(response, {"user_token": user["sub"]})

    token = response.json()["result"]["token"]
    # Cache token into Redis using the token_id as the key
    REDIS.set("ckantoken:" + user["sub"], token)

    return token


def get_user_ckan_token(config, admin=False):
    """Get the CKAN token for the current user.

    This should be called once at the start of the application.
    """
    user = kutils.current_user()
    if user["preferred_username"] == "admin" or admin:
        # If the user is admin, use the admin token
        return config["CKAN_ADMIN_TOKEN"]

    # Check if the token is already cached in Redis
    token = REDIS.get("ckantoken:" + user["sub"])
    if token is None:
        # If not cached, create and cache the token
        token = create_and_cache_user_token(config)

    if not token:
        raise BackendError(500, "ckan", "Failed to get CKAN token from Redis")

    logger.debug("CKAN token: %s", token)
    return token


def initialize_ckan_client(config, token=None):
    """Initialize the CKAN client.

    This should be called once at the start of the application.
    """
    global ckan_client
    ckan_client = requests.Session()

    ckan_client.headers.update(
        {
            "Content-Type": "application/json",
        }
    )
    global api_url
    api_url = config["CKAN_API"]


def raw_request(
    endpoint,
    *,
    json: Optional[dict] = None,
    headers: dict = {},
    params=None,
    admin=False,
    **kwargs,
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
    # The base url of the CKAN API endpoint
    # Should be sth like http://ckan:5000/api/3/action/
    # api_url = config["CKAN_API"]

    # Combine base_url with the endpoint
    url = urljoin(api_url, endpoint)

    # Prepare headers, defaulting to Authorization if token is present and Content-Type
    # headers = {"Authorization": config["CKAN_ADMIN_TOKEN"]} | headers
    headers = {
        "Authorization": get_user_ckan_token(current_app.config["settings"], admin),
    } | headers

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
        try:
            err = c["error"]  # Must have this...
        except Exception as e:
            logger.exception(
                "CKAN error response unexpected: status code=%d, json response==%s",
                response.status_code,
                c,
            )
            raise BackendLogicError(
                "ckan",
                "No error information provided",
                c,
                response.status_code,
                detail=context,
            ) from e

        if (etype := err.get("__type", None)) is None:
            raise DataError("No error type provided", err, detail=context)

        emsg = err.get("message", "No message provided")
        context_detail = {
            k: v for k, v in context.items() if isinstance(v, (int, str, float, bool))
        }
        eextra = {k: v for k, v in c["error"].items() if k not in ["__type", "message"]}
        if eextra:
            context_detail["extra"] = eextra

        match etype:
            case "Integrity Error":
                raise DataError(emsg, detail=context_detail)
            case "Authorization Error":
                raise BackendLogicError("ckan", etype, emsg, detail=context_detail)
            case "Not Found Error":
                entity = context.get("entity", None)
                raise NotFoundError(entity, emsg, detail=context_detail)
            case "Validation Error":
                raise InvalidError(emsg, detail=context_detail)
            case "Search Query Error":
                raise DataError(etype, emsg, detail=context_detail)
            case "Search Error":
                raise InvalidError(etype, emsg, detail=context_detail)
            case (
                "Search Index Error" | "Solr Connection Error" | "Internal Server Error"
            ):
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


def filter_list_by_type(
    id_list: list[str], etype: str, tablename: str = "package", idattr: str = "id"
) -> list[str]:
    """Given a list of IDs, return only those that have the given type.

    Processing is done using the SQL database, so it is very fast.

    The table queried must have a 'type' string attribute.

    Also, the table must have either the 'id' or the 'name' attribute, which-ever is specified
    by the 'idattr' argument.

    The 'tablename' argument specifies the table to query from. By default, it is _package_.
    Another option is _group_. Note that, _resource_ is not, since the "type attribute" is
    named "resource_type".

    Args:
        id_list (list[str]): The list of IDs to filter.
        etype (str): The type to filter by.
        tablename (str, optional): The table to filter from. Defaults to 'package'.
        idattr (str, optional): The attribute to filter by. Defaults to 'id'.

    Returns:
        list[str]: The filtered list of IDs.
    """
    query = sql.SQL(
        """\
        SELECT {idattr}
        FROM {tablename}
        WHERE {idattr} =ANY(%s) AND type = %s"""
    ).format(idattr=sql.Identifier(idattr), tablename=sql.Identifier(tablename))
    # Pluck out the IDs from the list of tuples
    with transaction() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (id_list, etype))
            rows = cur.fetchall()
    return [row[0] for row in rows]


def get_solr_schema():
    """Get the Solr schema."""
    response = requests.get("http://solr:8983/solr/ckan/schema")
    if response.status_code != 200:
        raise BackendError(500, "solr", "Failed to fetch schema", response.status_code)
    return response.json()["schema"]
