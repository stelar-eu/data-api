"""Access CKAN
"""

from __future__ import annotations

import logging
import traceback
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin
from flask import current_app
import requests
import kutils
import time
from requests.exceptions import ConnectionError
from psycopg2 import sql
from exceptions import (
    BackendError,
    BackendLogicError,
    DataError,
    InternalException,
    InvalidError,
    NotFoundError,
)
from .redis import REDIS
from .pgsql import transaction

if TYPE_CHECKING:
    from requests import Response

logger = logging.getLogger(__name__)


ckan_client = None
api_url = None


def create_and_cache_user_token(config):
    user = kutils.current_user()
    response = raw_request(
        endpoint="api_token_create",
        json={"user": user["sub"], "name": "stelar-token"},
        token_override=config["CKAN_ADMIN_TOKEN"],
    )
    raise_ckan_error(response, {"user_token": user["sub"]})

    token = response.json()["result"]["token"]
    # Cache token into Redis using the token_id as the key
    REDIS.set("ckantoken:" + user["sub"], token)

    return token


def get_user_ckan_token(config, user=None, admin=False):
    """Get the CKAN token for the current user."""
    try:
        user = kutils.current_user()
    except Exception as e:
        logger.exception("Failed to get user from kutils: %s", e)
        return config["CKAN_ADMIN_TOKEN"]

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
    token_override=None,
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
        "Authorization": token_override
        or get_user_ckan_token(current_app.config["settings"]),
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


def raw_request_with_retries(*args, max_retries=2, **kwargs):
    backoff = 1
    for attempt in range(max_retries):
        try:
            return raw_request(*args, **kwargs)
        except ConnectionError as e:
            if attempt == max_retries - 1:
                raise
            logger.warning(
                "CKAN request failed (attempt %d/%d): %s; retrying in %ds",
                attempt + 1,
                max_retries,
                e,
                backoff,
            )
            time.sleep(backoff)
            backoff *= 2


def request(
    endpoint, *, json: Optional[dict] = None, headers: dict = {}, params=None, **kwargs
):
    """Make a CKAN request and raise on error."""
    # Raise an exception for HTTP errors (4xx, 5xx responses)
    response = raw_request_with_retries(
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
    response = raw_request_with_retries(
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


# -------------------------------------------
#  CKAN relationships
#
#
# The folowing code bypasses some idiosyncracies of the
# CKAN API re. relationships, which is not very well documented.
#
#  1. When an illegal relationship type is passed to the
#     CKAN API, it returns a 500 error!
#  2. The CKAN API returns relationships using package names instead of IDs.
#  3. Creation and update of relationships often raises a 500 error,
#     even though the relationship is created/updated successfully.
#     This error is a bug in the CKAN code constructing the response, and
#     does not affect the integrity of the database.
#  4. In returning responses, the CKAN API does not mention package type.
#
#  Therefore, we return relationships using the following format:
#  {
#      "subject": <subject_id>,
#      "object": <object_id>,
#      "relationship": <relationship_type>,
#      "comment": <comment>,
#      "subject_type": <subject_type>,
#      "object_type": <object_type>,
#      "subject_name": <subject_name>,
#      "object_name": <object_name>,
#  }
# ---------------------------------------------


# Define the relationship types between entities (forward, reverse)
# These are synchronized with the CKAN implementation.
# The forward relationship is the one that is used in the database.
RELATIONSHIPS: list[tuple[str, str]] = [
    ("depends_on", "dependency_of"),
    ("derives_from", "has_derivation"),
    ("links_to", "linked_from"),
    ("child_of", "parent_of"),
]

ALL_RELATIONSHIPS: set[str] = {r for pair in RELATIONSHIPS for r in pair}
FWD_RELATIONSHIPS: set[str] = {r[0] for r in RELATIONSHIPS}
REV_RELATIONSHIPS: set[str] = {r[1] for r in RELATIONSHIPS}
PEER_RELATIONSHIPS: set[str] = {r[0]: r[1] for r in RELATIONSHIPS} | {
    r[1]: r[0] for r in RELATIONSHIPS
}


def get_id_for_entity_id_or_name(eid: str, tablename: str = "package") -> str:
    """Get the ID for an entity, given its name or ID.

    Args:
        eid (str): The entity ID or name.
        tablename (str): The entity type. Can be one of 'package', 'group', 'vocabulary', or 'user'.

    Returns:
        str: The entity ID.
    """
    if tablename not in ["package", "group", "vocabulary", "user"]:
        raise ValueError(f"Invalid entity type: {tablename}")

    query = sql.SQL(
        """\
        SELECT id
        FROM {tablename}
        WHERE id = %s OR name = %s"""
    ).format(tablename=sql.Identifier(tablename))
    with transaction() as conn:
        with conn.cursor() as cur:
            cur.execute(query, (eid, eid))
            rows = cur.fetchall()
            if not rows:
                return None
            if len(rows) > 1:
                raise DataError(
                    f"Multiple rows found for {tablename} with id/name {eid}"
                )
            return rows[0][0]


def _compose_relationship_sql_query(
    subid: str, objid: str | None = None, rel: str | None = None
) -> tuple[sql.SQL, tuple]:
    select_clause = """\
    SELECT DISTINCT
        r.subject_package_id as subject, 
        r.object_package_id as object, 
        r.type as relationship, 
        r.comment,
        ps.type as subject_type,
        po.type as object_type,
        ps.name as subject_name,
        po.name as object_name
    """

    from_clause = """\
    FROM package_relationship r
    JOIN package ps ON r.subject_package_id = ps.id
    JOIN package po ON r.object_package_id = po.id
    """

    where_clause = """\
        WHERE r.state='active'
    """

    if rel is None:
        select_clause += """\
        , r.object_package_id=%s as flag
        """

        if objid is None:
            where_clause += """\
                AND (r.subject_package_id = %s OR r.object_package_id = %s)
                """
            params = (subid, subid, subid)
        else:
            where_clause += """\
                AND( (r.subject_package_id = %s AND r.object_package_id = %s)
                    OR (r.object_package_id = %s AND r.subject_package_id = %s) )
                """
            params = (subid, subid, objid, subid, objid)
    elif rel in REV_RELATIONSHIPS:
        select_clause += """\
        , true as flag
        """

        if objid is None:
            where_clause += """AND r.object_package_id = %s AND r.type = %s"""
            params = (subid, PEER_RELATIONSHIPS[rel])
        else:
            where_clause += """\
                AND r.subject_package_id = %s AND r.object_package_id = %s
                    AND r.type = %s
                """
            params = (objid, subid, PEER_RELATIONSHIPS[rel])
    else:
        select_clause += """\
        , false as flag
        """

        if objid is None:
            where_clause += """AND r.subject_package_id = %s AND r.type = %s"""
            params = (subid, rel)
        else:
            where_clause += """\
                AND r.subject_package_id = %s AND r.object_package_id = %s
                    AND r.type = %s
                """
            params = (subid, objid, rel)

    query = sql.SQL(select_clause + from_clause + where_clause)
    return query, params


def relationships_from_sql(
    subid: str, objid: str | None = None, rel: str | None = None
) -> list[dict[str, Any]]:
    """Get relationships from the SQL database.

    Returns the relationships of <subid>, filtering by <objid> and <rel> if
    provided.

    The relationships are returned as a list of dictionaries, where each
    dictionary contains the following keys:
        - subject: The subject ID.
        - object: The object ID.
        - relationship: The relationship type.
        - comment: The comment or description of the relationship.
        - subject_type: The type of the subject.
        - object_type: The type of the object.
        - subject_name: The name of the subject.
        - object_name: The name of the object.

    Args:
        subid (str): Subject ID.
        objid (str|None): Object ID.
        rel (str|None): Relationship type.

    Returns:
        list[dict[str, Any]]: List of relationships.
    """

    assert rel is None or rel in ALL_RELATIONSHIPS, f"Invalid relationship: {rel}"
    assert isinstance(subid, str), "Subject ID must be a string"
    assert isinstance(objid, str | None), "Object ID must be a string or None"

    with transaction() as conn:
        # Step 1: Canonicalize the IDs
        subid = get_id_for_entity_id_or_name(subid)
        if objid is not None:
            objid = get_id_for_entity_id_or_name(objid)
            if objid is None:
                raise NotFoundError(
                    entity=f"Object {objid} not found", detail={"subid": subid}
                )

        # Step 2: Compose the SQL query and execute it
        query, params = _compose_relationship_sql_query(subid, objid, rel)

        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()

    # Step 3: Process the results, reversing the tuples that need to be reversed
    return [_relationsip_row_to_dict(row) for row in rows]


def _relationsip_row_to_dict(row: tuple) -> dict[str, Any]:
    """Convert a row from the SQL query to a dictionary.

    Args:
        row (tuple): The row from the SQL query.

    Returns:
        dict[str, Any]: The dictionary representation of the row.
    """
    if row[8]:
        # Reverse the order of the subject and object and the relationship direction
        # if the flag is set
        row = (
            row[1],
            row[0],
            PEER_RELATIONSHIPS[row[2]],
            row[3],
            row[5],
            row[4],
            row[7],
            row[6],
        )
    return {
        "subject": row[0],
        "object": row[1],
        "relationship": row[2],
        "comment": row[3],
        "subject_type": row[4],
        "object_type": row[5],
        "subject_name": row[6],
        "object_name": row[7],
    }


def establish_relationship(
    operation: str,
    subid: str,
    objid: str,
    rel: str,
    comment: Optional[str] = None,
):
    """Update a CKAN relationship between two entities.

    If the relationship already exists, it will be updated (w/ the new comment).
    If the relationship does not exist, it will be created.

    Args:
        operation (str): The operation to perform: "create" or "update".
        subid (str): Subject ID.
        objid (str): Object ID.
        rel (str): Relationship type.
        comment (Any): Comment or description of the relationship.

    """

    if operation not in ["create", "update"]:
        raise InternalException(
            f"In ckan.establish_relationship invalid op {repr(operation)}, expected 'create' or 'update'"
        )

    # Check if the relationship is valid
    if rel not in ALL_RELATIONSHIPS:
        raise InvalidError(f"Invalid relationship type: {rel}")

    # Perform the create operation, using raw request, ignoring the
    # Internal Server Error
    # response, since it is a bug in CKAN.

    response = raw_request(
        f"package_relationship_{operation}",
        json={
            "subject": subid,
            "object": objid,
            "type": rel,
            "comment": comment,
        },
    )

    # Check for errors in the response
    if (
        response.status_code == 500
        and response.json().get("error", {}).get("__type") == "Internal Server Error"
    ):
        # Ignore the error, since it is a bug in CKAN
        logger.info("CKAN error: %s", response.json())
    else:
        raise_ckan_error(response, {"subid": subid, "objid": objid, "rel": rel})

    return relationships_from_sql(subid, objid, rel)


def disband_relationship(
    subid: str,
    objid: str,
    rel: str,
):
    """Delete a CKAN relationship between two entities.

    If the relationship does not exist, it will be ignored.
    If the relationship exists, it will be deleted.

    Args:
        subid (str): Subject ID.
        objid (str): Object ID.
        rel (str): Relationship type.

    """
    if rel not in ALL_RELATIONSHIPS:
        raise InvalidError(f"Invalid relationship type: {rel}")

    response = raw_request(
        "package_relationship_delete",
        json={
            "subject": subid,
            "object": objid,
            "type": rel,
        },
    )

    # This is a bit tricky:
    # CKAN returns a 404 error if the relationship does not exist,
    # and also a 404 if any of the two entities do not exist.
    # We need to ignore the former case and raise an error
    # on the latter case.

    if (
        response.status_code == 404
        and (err := response.json()["error"])
        and err.get("__type") == "Not Found Error"
        and err.get("message") == "Not found"
    ):
        pass
    else:
        # Check for errors in the response
        raise_ckan_error(response, {"subid": subid, "objid": objid, "rel": rel})

    return None
