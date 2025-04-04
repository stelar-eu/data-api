"""
    Generic authorization logic for entities.
"""


import flask

from exceptions import AuthorizationError, InternalException
from kutils import current_user


def generic_action(action, entity):
    """Generate a generic action string for the given action and entity."""
    return f"{action}_{entity}"


def combine_generic(gen_actions, gen_entities):
    return [
        generic_action(action, entity)
        for action in gen_actions
        for entity in gen_entities
    ]


_CRUD = [
    "create",
    "read",
    "update",
    "delete",
]

GENERIC_ACTION_ENTITIES = [
    "dataset",
    "workflow",
    "process",
    "tool",
    "group",
    "organization",
    "user",
]

ACTIONS = [
    *combine_generic(_CRUD, GENERIC_ACTION_ENTITIES),
    *combine_generic(_CRUD, ["vocabulary", "tag"]),
    # purging
    *combine_generic(
        ["purge"],
        [
            "dataset",
            "workflow",
            "process",
            "tool",
            "group",
            "organization",
        ],
    ),
    # Membership
    *combine_generic(["edit_membership"], GENERIC_ACTION_ENTITIES),
    "add_member",
    "remove_member",
    # Tasks
    *combine_generic(["create", "read"], ["task"]),
    "kill",
    "readlog",
    # Process
    "add_task",
    "terminate",
    # Tool
    "exec",
    # Users
    "edit_roles",
]


def authorize(resource, entity, action):
    """Check the authorization for the current user.

    If successfull, the function simply returns, else,
    an `AuthorizationError` is returned.

    Authorization policy:
    * If the current user is admin, then the function returns
    * Else, the action is checked using `authz_module.authorization()`

    Arguments
    ---------
        resource: the data related to the action to be authorized
        entity: the type of the resource
        action: the action to authorize

    Returns
    -------
        None

    Raises
    ------
        AuthorizationError if authorization fails.
    """

    from authz_module import Resource, authorization

    if not flask.has_request_context():
        return

    # Check for admin
    cu = current_user()
    # TODO: Check if user is admin via user attributes!!
    is_admin = cu.get("is_admin",None)
    if is_admin is not None and is_admin:
        return

    # Call authz_module.authorization(...)
    if action not in ACTIONS:
        gaction = generic_action(action, entity)
        if gaction in ACTIONS:
            action = gaction
    else:
        raise InternalException(f"Illegal action passed: {action}")

    if not authorization(Resource(resource, entity), action):
        detail = {
            "entity": entity,
            "resource": resource,
            "action": action,
        }
        raise AuthorizationError(message="Authorization failed", detail=detail)
