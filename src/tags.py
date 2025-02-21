"""Methods for working with tags and vocabularies in CKAN.

This module provides methods for working with tags and vocabularies in CKAN.
In particular, it provides methods for converting between tag strings and tag
objects, and for fetching vocabularies from CKAN.

The module also provides a cache for vocabularies, so that they are not
repeatedly fetched from CKAN. The cache makes the conversion much faster.

NOTE: the cache is currently implemented as a simple LRU cache, which is
not cleared when the CKAN database is updated. 

TODO: implement proper cache invalidation. In order to support multiple processes,
a technique for notifying the cache that a vocabulary has been updated is needed.
The simplest case involves using PostgreSQL's NOTIFY/LISTEN mechanism to notify
all processes that a vocabulary has been updated. This would require a trigger
on the vocabulary table to send a notification when a vocabulary is updated.
 
"""
import functools
import re

import requests

from backend.ckan import raw_request
from exceptions import BackendError


def __get_vocabulary(name_or_id):
    """Return a vocabulary either by name or by id.

    The object returned
    """
    try:
        hresp = raw_request("vocabulary_show", json={"id": name_or_id})
        response = hresp.json()
        if response["success"]:
            vocab = response["result"]
            vocab["tagnames"] = {tag["name"] for tag in vocab["tags"]}
            return vocab
        else:
            raise ValueError("Vocabulary not found", name_or_id)
    except requests.exceptions.HTTPError as he:
        detail = {"errno": he.errno, "strerror": he.strerror, "url": he.request.url}
        raise BackendError(
            500, "CKAN failed on vocabulary access", name_or_id, detail=detail
        ) from he


@functools.lru_cache(maxsize=128)
def __get_cached_vocabulary(name_or_id):
    return {"vocab": __get_vocabulary(name_or_id), "fresh": True}


def get_vocabulary(name_or_id, cached=True):
    """Return a vocabulary either by name or by id.

    The object returned may be cached; if fetched by ID, its name
    and ID will be correct, since the ID is not repeatable and name
    is not volatile. However, tag information may be stale.

    If searched by name, the ID returned may be stale...
    Eventually, this will need to be fixed.
    """
    obj = __get_cached_vocabulary(name_or_id)
    if obj["fresh"]:
        obj["fresh"] = False
        return obj["vocab"]
    elif not cached:
        # Refresh
        voc = __get_vocabulary(name_or_id)
        obj["vocab"] = voc
        return voc
    else:
        return obj["vocab"]


def tag_object_to_string(tagobj):
    "Return a tag string for the given tag object"
    v = tagobj.get("vocabulary_id")  # ok if vocabulary_id is missing!
    if v is None:
        return tagobj["name"]
    else:
        voc = get_vocabulary(v)
        return ":".join((voc["name"], tagobj["name"]))


TAGNAME_PATTERN = re.compile(r"^[A-Za-z0-9 _-]{2,100}$")
TAGSPEC_PATTERN = re.compile(r"^((.{2,100})\:)?([A-Za-z0-9 _-]{2,100})$")


def tag_split(tagspec: str) -> tuple[str | None, str]:
    """Split a tag string into a pair or (<vocabulary-name> , <tag-name>).

    Properly, a tagspec is either <tag-name>  or <vocabulary-name>:<tag-name>,
    where
        <tagname> is a string made only of lower-case alphanumerics, hyphen (-) and underscore (_),
        and of length in [2,100]
        <vocabulary-name> is any string (which may contain spaces and other ascii characters) of
        length [2,100].
    """
    m = TAGSPEC_PATTERN.fullmatch(tagspec)
    if m is None:
        raise ValueError(f"Invalid tagspec: {tagspec}")
    return m.groups()[1:]


def tag_string_to_object(tagspec):
    """Convert a tagspec (vocab:tagname) to an object, suitable for
    sending to CKAN.

    Args:
        tagspec (str): the tagspec to convert.
    Returns:
        an object for the tagspec.
    Raises:
        ValueError if the vocabulary cannot be found or the tag string is badly formed.
    """
    vocname, tagname = tag_split(tagspec)
    if vocname is None:
        return {"name": tagname}
    else:
        vocab = get_vocabulary(vocname)
        if tagname in vocab["tagnames"]:
            return {"name": tagname, "vocabulary_id": vocab["id"]}
        else:
            raise ValueError(f"Tag '{tagname}' not in vocabulary '{vocab['name']}'")
