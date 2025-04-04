"""
    Code related to package based entities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from backend.ckan import (
    ckan_request,
    disband_relationship,
    establish_relationship,
    relationships_from_sql,
)
from exceptions import InternalException, NotFoundError

# TODO: Eventually, move PackageEntity here from entity.py


def _call_establish_relationship(
    operation: str,
    subid: str,
    objid: str,
    rel: str,
    comment: Any,
) -> dict[str, Any]:
    res = establish_relationship(
        operation=operation,
        subid=subid,
        objid=objid,
        rel=rel,
        comment=comment,
    )

    if len(res) != 1:
        raise RuntimeError(
            "Failed to create relationship",
            dict(
                subid=subid,
                objid=objid,
                rel=rel,
                comment=comment,
                remark=f"establish_relationship returned {len(res)} results",
            ),
        )
    else:
        return res[0]


def create_relationship(subid: str, objid: str, rel: str, comment: Any):
    """Create a CKAN relationship between two entities.

    If the relationship already exists, it will be updated (w/ the new comment).
    If the relationship does not exist, it will be created.

    Args:
        subid (str): Subject ID.
        objid (str): Object ID.
        rel (str): Relationship type.
        comment (Any): Comment or description of the relationship.
    """
    return _call_establish_relationship(
        operation="create",
        subid=subid,
        objid=objid,
        rel=rel,
        comment=comment,
    )


def update_relationship(subid: str, objid: str, rel: str, comment: Any):
    """Update a CKAN relationship between two entities.

    If the relationship already exists, it will be updated (w/ the new comment).
    If the relationship does not exist, a NotFound error will be raised.

    Args:
        subid (str): Subject ID.
        objid (str): Object ID.
        rel (str): Relationship type.
        comment (Any): Comment or description of the relationship.
    """
    return _call_establish_relationship(
        operation="update",
        subid=subid,
        objid=objid,
        rel=rel,
        comment=comment,
    )


def delete_relationship(subid: str, objid: str, rel: str):
    """Delete a CKAN relationship between two entities.

    If the relationship does not exist, no error will be raised.

    Args:
        subid (str): Subject ID.
        objid (str): Object ID.
        rel (str): Relationship type.
    """
    return disband_relationship(subid, objid, rel)


def get_relationships(
    subid: str, objid: str | None, rel: str | None
) -> list[dict[str, Any]]:
    """Get a list of relationships between two entities.

    Args:
        subid (str): Subject ID.
        objid (str): Object ID.
        rel (str): Relationship type.

    Returns:
        list[dict[str, Any]]: List of relationships.
    """

    return relationships_from_sql(
        subid=subid,
        objid=objid,
        rel=rel,
    )
