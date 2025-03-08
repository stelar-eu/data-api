"""Code related to search endpoints."""


def search_entities(etype: str, query: str, limit: int, offset: int):
    """Search for entities of a given type.

    Args:
        etype (str): The entity type.
        query (str): The search query.
        limit (int): The maximum number of results to return.
        offset (int): The number of results to skip.

    Returns:
        dict: The search results.
    """

    # Notes:
    # q: query       defType: dismax/edismax
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
