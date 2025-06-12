"""Code related to search endpoints."""

from typing import Any, Optional

from apiflask import Schema

from backend.ckan import ckan_request
from exceptions import DataError

# Notes:
# q: query
# defType: lucene/dismax/edismax
#
# fq: filter query
# fq_list: list of filter queries
#
# fl: fields to return
# sort: sort order  (default: score desc, medatada_modified desc)
# start: offset
# rows: limit
#
# facet: bool
# facet_fields: list of fields to facet on
# facet_mincount: minimum count for facet
# facet_limit: maximum number of facet values

# Advanced:
# qf: query fields
# tie: tie breaker
# wt: response writer
# mm: minimum should match
# boost: boost query
# bf: boost functions

# Notes: for SOLR search on resources, we need to add indexed fields to
# "ckan.extra_resource_fields"  in the ckan.ini configuration file.


def check_list_of_strings(L, attr):
    if not isinstance(L, list) or not all(isinstance(s, str) for s in L):
        raise DataError(f"Expected {attr} to be a list of strings")


def entity_search(
    etype: str,
    *,
    q: str = None,
    bbox: str | list[float] = None,
    fq: list[str] = [],
    fl: list[str] = "id",
    sort: str = "score desc, metadata_modified desc",
    facet: dict[str, Any] | None = None,
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    include_private: bool = False,
) -> dict:
    """Search for entities of a given type.

    This function returns package-based entities.

    Query syntax is described at:
    https://lucene.apache.org/solr/guide/8_9/the-standard-query-parser.html

    Args:
        etype (str): The entity type. This must be one of 'dataset', 'workflow', 'tool', or 'process'.
        q (str): The search query.
        fq (list[str]): The filter queries. These queries are cached and reused at the backend.
        fl (list[str]): The fields to return. By default, only the entity ID is returned.
        facet (dict[str, Any]): The facet parameters. These are 'fields', 'mincount', and 'limit'.
            The 'fields' value is a list of fields to facet on. The 'mincount' value is the minimum
            count for a facet value to be included. The 'limit' value is the maximum number of facet
            values to return.
        sort (str): The sort order.
        limit (int): The maximum number of results to return. The default is 10.
        offset (int): The number of results to skip. The default is 0.

    Returns:
        dict: The search results.
    """

    if etype not in ["dataset", "workflow", "tool", "process"]:
        raise DataError(f"Invalid entity type '{etype}'")

    # Build the query parameters.
    params = {}

    if q:
        params["q"] = q

    if bbox is not None:
        if isinstance(bbox, str):
            bbox = [float(x) for x in bbox.split(",")]
        if len(bbox) != 4:
            raise DataError("bbox must have 4 values", bbox)
        params["ext_bbox"] = bbox

    if fq:
        if isinstance(fq, str):
            fq = [fq]
        check_list_of_strings(fq, "fq")
    else:
        fq = []
    fq.append(f"+type:{etype}")
    params["fq_list"] = fq

    if fl is not None:
        if isinstance(fl, str):
            fl = [fl]
        check_list_of_strings(fl, "fl")
        params["fl"] = fl

    if sort:
        params["sort"] = sort

    if facet:
        if not isinstance(facet, dict):
            raise DataError("facet must be a dictionary")
        if "fields" not in facet:
            raise DataError("facet must have a 'fi  elds' key")
        check_list_of_strings(facet["fields"], "facet.fields")
        params["facet"] = True
        params["facet.field"] = facet["fields"]
        if "mincount" in facet:
            params["facet.mincount"] = facet["mincount"]
        if "limit" in facet:
            params["facet.limit"] = facet["limit"]

    if limit:
        params["rows"] = limit

    if offset:
        params["start"] = offset

    if include_private:
        params["include_private"] = include_private

    # Perform the search.
    result = ckan_request("package_search", json=params)
    return result


def resource_search(
    query: str | list[str],
    order_by: str,
    limit: int | None = None,
    offset: int | None = None,
) -> dict:
    """Searches for resources in public datasets satisfying the search criteria.

    The 'query' parameter is a required field.  It is a string of the form
    ``{field}:{term}`` or a list of strings, each of the same form. Within
    each string, ``{field}`` is a field or extra field on the Resource domain
    object.

    If ``{field}`` is ``"hash"``, then an attempt is made to match the
    `{term}` as a *prefix* of the ``Resource.hash`` field.

    If ``{field}`` is an extra field, then an attempt is made to match against
    the extra fields stored against the Resource.

    Note: The search is limited to search against extra fields declared in
    the config setting ``ckan.extra_resource_fields``.

    Note: Due to a Resource's extra fields being stored as a json blob, the
    match is made against the json string representation.  As such, false
    positives may occur. If the search criteria is:
    ```
        query = "field1:term1"
    ```
    then a json blob with the string representation of
    ```
        {"field1": "foo", "field2": "term1"}
    ```
    will match the search criteria!  This is a known short-coming of this
    approach.

    All matches are made ignoring case; and apart from the "hash" field,
    a term matches if it is a substring of the field's value.

    Finally, when specifying more than one search criteria, the criteria are
    AND-ed together.

    Arguments:
        query: The search criteria.
        order_by: The field to order by. Only ordering one field is available, and in ascending order only.
        limit: The maximum number of results to return.
        offset: The number of results to skip.

    Returns:
        dict: The search results. It returns a dictionary with 2 fields:
        `count` and `results`.  The `count` field contains the total number
        of Resources found without the limit or query parameters having an effect.
        The `results` field is a list of Resource objects.
    """

    if isinstance(query, str):
        query = [query]
    check_list_of_strings(query, "query")

    # Build the query parameters.
    params = {"query": query}

    if order_by:
        params["order_by"] = order_by

    if limit is not None:
        params["limit"] = limit

    if limit is not None:
        params["offset"] = offset

    # Perform the search.
    result = ckan_request("resource_search", json=params)
    return result
