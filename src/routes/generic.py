from __future__ import annotations

import functools
from logging import Logger, getLogger
from typing import List, Optional

# Input schema for validating and structuring several API requests
from apiflask import APIBlueprint
from flask import request

import schema
from auth import security_doc, token_active
from cutils import Entity, MemberEntity
from exceptions import APIException, InternalException

gen_logger = getLogger(__name__)


# -----------------------------------
# Generic API rendering
#
# These functions implement generically the
# ReST standards of the catalog API.
#
# Note: these standards should be observed all over the
# STELAR API.
# ------------------------------------


def generic_error_500(exc: Exception):
    import traceback

    return {
        "help": request.url,
        "success": False,
        "error": {
            "__type": "Internal Server Error",
            "message": repr(exc),
            "detail": {
                "exception": traceback.format_exc(),
            },
        },
    }, 500


def generic_api_exception(exc: APIException):
    exattr = [(a, getattr(exc, a, None)) for a in exc.repr_attr() if a != "message"]
    detail = {a: v for a, v in exattr if v is not None}
    robj = {
        "help": request.url,
        "success": False,
        "error": {
            "__type": exc.__class__.__name__,
            "message": exc.message,
            "detail": detail,
        },
    }
    return robj, exc.status_code


def generic_api_result(result):
    return {"help": request.url, "success": True, "result": result}


def render_api_output(logger: Logger):
    """Decorator for generic endpoints that handles exceptions uniformly"""

    def my_wrapper(endp_func: callable):
        @functools.wraps(endp_func)
        def exc_handler(*args, **kwargs):
            try:
                return generic_api_result(endp_func(*args, **kwargs))
            except APIException:
                logger.debug("APIException in render_api_output", exc_info=True)
                raise
                # return generic_api_exception(ex)
            except Exception as e:
                logger.exception("Internal error in render_api_output")
                # return generic_error_500(e)
                raise InternalException(e)

        return exc_handler

    return my_wrapper


def rename_endpoint(name):
    """Decorator to rename generic endpoint functions.

    Flask requires distinct paths to be mapped to distinct function names.
    This decorator does this. It should be applied to a function before
    Flask sees it.
    """

    def do_rename(func):
        func.__name__ = name
        return func

    return do_rename


def error_responses(status_list: List[int]):
    # Add some standard errors
    status_list = [
        401,
        422,
        500,
    ]
    status_list.sort()

    responses = {}
    for status in status_list:
        if status == 200:
            responses[200] = {
                "description": "Request was successful",
                "content": {"application/json": {"schema": schema.APIErrorResponse}},
            }
        elif status == 400:
            responses[400] = {
                "description": "Bad request. This error implies that the data sent in the request is invalid.",
                "content": {"application/json": {"schema": schema.APIErrorResponse}},
            }
        elif status == 403:
            responses[403] = {
                "description": "Forbidden request. This error implies that the user is not authorized to perform "
                "the requested action.",
                "content": {"application/json": {"schema": schema.APIErrorResponse}},
            }
        elif status == 404:
            responses[404] = {
                "description": "Resource not found. This error implies that the resource requested does not exist.",
                "content": {"application/json": {"schema": schema.APIErrorResponse}},
            }
        elif status == 409:
            responses[409] = {
                "description": "Conflict (e.g., Resource already exists). ",
                "content": {"application/json": {"schema": schema.APIErrorResponse}},
            }
        elif status == 500:
            responses[500] = {
                "description": "Internal server error. The error may be caused by a bug in the server, or some malfunction in"
                "some other service.",
                "content": {"application/json": {"schema": schema.APIErrorResponse}},
            }
        else:
            responses[status] = {
                "description": f"Error {status}. This is an unknown error.",
                "content": {"application/json": {"schema": schema.APIErrorResponse}},
            }
    return responses


def generate_list_entities(entity: Entity, bp: APIBlueprint, logger: Logger):
    """This method generates the entity "list" endpoints"""

    @bp.get(f"/{entity.collection_name}")
    @bp.input(schema.PaginationParameters, location="query")
    @bp.output(schema.IdListResponse, status_code=200)
    @bp.doc(
        summary=f"List {entity.collection_name} in the Data Catalog",
        description=f"""List all {entity.collection_name} in the Data Catalog. \\
        This function returns a list of {entity.collection_name} identifiers. \\
        It is designed to be used for exploratory or bulk operations where only the IDs of {entity.collection_name} are required. \\
        """,
        tags=["RESTful Search Operations"],
        security=security_doc,
        responses=error_responses([409]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(f"api_list_{entity.collection_name}")
    def generic_list_entities(query_data):
        limit = query_data.get("limit", None)
        offset = query_data.get("offset", None)

        return entity.list_entities(limit=limit, offset=offset)

    return generic_list_entities


def generate_fetch_entities(entity: Entity, bp: APIBlueprint, logger: Logger):
    """This method generates the entity "list" endpoints, but returns instances instead of just IDs"""

    @bp.get(f"/{entity.collection_name}.fetch")
    @bp.input(schema.PaginationParameters, location="query")
    @bp.output(schema.EntityListResponse, status_code=200)
    @bp.doc(
        summary=f"List {entity.collection_name} in the Data Catalog",
        description=f"""List all {entity.collection_name} in the Data Catalog. \\
        This function returns a list of {entity.collection_name} objects. \\
        The operation is expensive and should not be used without the 'limit' argument.
        """,
        tags=["RESTful Search Operations"],
        security=security_doc,
        responses=error_responses([409]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(f"api_fetch_{entity.collection_name}")
    def generic_fetch_entities(query_data):
        limit = query_data.get("limit", None)
        offset = query_data.get("offset", None)

        return entity.fetch_entities(limit=limit, offset=offset)

    return generic_fetch_entities


def generate_get_entity(entity: Entity, bp: APIBlueprint, logger: Logger):
    """Generates the entity get endpoints"""

    @bp.get(f"/{entity.name}/<entity_id>")
    @bp.output(schema.APIResponse, status_code=200)
    @bp.doc(
        summary=f"Get {entity.name} by ID",
        description=f"""Retrieve a {entity.name} from the Data Catalog by its ID with full information. \\
        This route allows clients to query the catalog and fetch details of a {entity.name} using its unique
        {entity.name} ID. \\
        """,
        tags=["RESTful Search Operations"],
        security=security_doc,
        responses=error_responses([403, 404]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(f"api_get_{entity.name}")
    def generic_get_entity(entity_id: str):
        return entity.get_entity(entity_id)

    return generic_get_entity


def generate_delete_entity(entity: Entity, bp: APIBlueprint, logger: Logger):
    @bp.delete(f"/{entity.name}/<entity_id>")
    @bp.input(schema.DeleteRequest, location="query")
    @bp.output(schema.DeleteResponse, status_code=200)
    @bp.doc(
        summary=f"Delete {entity.name} by ID",
        description=f"""Delete a {entity.name} from the Data Catalog by its ID. \\
        This route allows clients to delete a specific {entity.name} by its unique {entity.name} ID. \\
        Any catalog resources associated with the {entity.name} will also be deleted. \\

        Normally, deletion simply marks the {entity.name} as deleted, but does not remove it from the catalog. \\
        If you want to remove the {entity.name} from the catalog permanently, you can use the 'purge' parameter. \\

        ! ATTENTION ! This action performs a hard-delete and the {entity.name} will no longer be retrievable. \\
        """,
        tags=["RESTful Search Operations"],
        security=security_doc,
        responses=error_responses([400, 403, 404, 409]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(f"api_delete_{entity.name}")
    def generic_delete_entity(entity_id: str, query_data: Optional[bool] = False):
        purge = query_data.get("purge", False)
        return entity.delete_entity(entity_id, purge=purge)

    return generic_delete_entity


def generate_create_entity(entity: Entity, bp: APIBlueprint, logger: Logger):
    """Generates the entity create endpoints"""

    @bp.post(f"/{entity.name}")
    @bp.input(entity.creation_schema, location="json")
    @bp.output(schema.APIResponse, status_code=200)
    @bp.doc(
        summary=f"Create {entity.name}",
        description=f"""Create and publish a {entity.name} in the Data Catalog. \\
        This route allows clients to publish {entity.name} by sending metadata in the request body. \\
        It supports the inclusion of basic, extra, and profile metadata for the {entity.name}. \\
        """,
        tags=["RESTful Publishing Operations"],
        security=security_doc,
        responses=error_responses([400, 403, 404, 409]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(f"api_create_{entity.name}")
    def generic_create_entity(json_data):
        return entity.create_entity(json_data)

    return generic_create_entity


def generate_update_entity(entity: Entity, bp: APIBlueprint, logger: Logger):
    """Generates the entity update endpoints"""

    @bp.put(f"/{entity.name}/<entity_id>")
    @bp.input(entity.update_schema, location="json")
    @bp.output(schema.APIResponse, status_code=200)
    @bp.doc(
        summary=f"Update {entity.name} by ID",
        description=f"""Update a {entity.name} in the Data Catalog by its ID. \\
        The {entity.name} metadata (e.g., name, description, tags) is passed in the request body. \\
        Any existing attributes that are excluded but their respective \\
        fields are included in the body WILL BE REMOVED. \\
        """,
        tags=["RESTful Publishing Operations"],
        security=security_doc,
        responses=error_responses([400, 403, 404]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(f"api_update_{entity.name}")
    def generic_update_entity(entity_id: str, json_data):
        return entity.update_entity(entity_id, json_data)

    return generic_update_entity


def generate_patch_entity(entity: Entity, bp: APIBlueprint, logger: Logger):
    """Generates the entity update endpoints"""

    @bp.patch(f"/{entity.name}/<entity_id>")
    @bp.input(entity.update_schema, location="json")
    @bp.output(schema.APIResponse, status_code=200)
    @bp.doc(
        summary=f"Update {entity.name} by ID",
        description=f"""Partially update a {entity.name} in the Data Catalog by its ID. \\
        The {entity.name} metadata (e.g., name, description, tags) is passed in the request body. \\
        Contrary to the PUT method, this method does not remove any omitted fields. \\
        """,
        tags=["RESTful Publishing Operations"],
        security=security_doc,
        responses=error_responses([400, 403, 404]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(f"api_patch_{entity.name}")
    def generic_patch_entity(entity_id: str, json_data):
        return entity.patch_entity(entity_id, json_data)

    return generic_patch_entity


def generate_add_member(member_entity: MemberEntity, bp: APIBlueprint, logger: Logger):
    """Generates the entity add member endpoints"""

    @bp.post(
        f"/{member_entity.parent.name}/<entity_id>/{member_entity.child.name}/<member_id>"
    )
    @bp.input(member_entity.capacity_schema, location="json")
    @bp.output(schema.APIResponse, status_code=200)
    @bp.doc(
        summary=f"Add a {member_entity.child.name} member to a {member_entity.parent.name} by ID",
        description=f"""Add a {member_entity.child.name} member to a {member_entity.parent.name} by ID. \\
        Members can be added with different capacities. \\
        
        The capacity of the member must be specified in the request body. \\
        {member_entity.capacity_schema.capdoc} \\
        """,
        tags=["RESTful Publishing Operations"],
        security=security_doc,
        responses=error_responses([400, 403, 404]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(
        f"api_add_{member_entity.child.name}_member_to_{member_entity.parent.name}"
    )
    def generic_add_member(entity_id: str, member_id: str, json_data):
        capacity = json_data.get("capacity")
        return member_entity.add_member(entity_id, member_id, capacity)

    return generic_add_member


def generate_remove_member(
    member_entity: MemberEntity, bp: APIBlueprint, logger: Logger
):
    """Generates the entity remove member endpoints"""

    @bp.delete(
        f"/{member_entity.parent.name}/<entity_id>/{member_entity.child.name}/<member_id>"
    )
    @bp.output(schema.APIResponse, status_code=200)
    @bp.doc(
        summary=f"Remove a {member_entity.child.name} member from a {member_entity.parent.name} by ID",
        description=f"""Remove a {member_entity.child.name} member from a {member_entity.parent.name} by ID. \\
        Members can be removed from the parent entity. \\
        """,
        tags=["RESTful Publishing Operations"],
        security=security_doc,
        responses=error_responses([400, 403, 404]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(
        f"api_remove_{member_entity.child.name}_member_from_{member_entity.parent.name}"
    )
    def generic_remove_member(entity_id: str, member_id: str):
        return member_entity.remove_member(entity_id, member_id)

    return generic_remove_member


def generate_list_members(
    member_entity: MemberEntity, bp: APIBlueprint, logger: Logger
):
    """Generates the entity list member endpoints"""

    @bp.get(
        f"/{member_entity.parent.name}/<entity_id>/{member_entity.child.collection_name}"
    )
    @bp.input(member_entity.capacity_schema, location="query")
    @bp.output(schema.MemberListResponse, status_code=200)
    @bp.doc(
        summary=f"List {member_entity.child.name} members of a {member_entity.parent.name} by ID",
        description=f"""List all {member_entity.child.name} members of a {member_entity.parent.name} by ID. \\
        This function returns a list of {member_entity.child.name} identifiers and their membership capacities. \\
        """,
        tags=["RESTful Search Operations"],
        security=security_doc,
        responses=error_responses([403, 409]),
    )
    @token_active
    @render_api_output(logger)
    @rename_endpoint(
        f"api_list_{member_entity.child.name}_members_of_{member_entity.parent.name}"
    )
    def generic_list_members(entity_id: str, query_data):
        capacity = query_data.get("capacity", None)
        return member_entity.list_members(entity_id, capacity)

    return generic_list_members


GENERATOR = {
    "list": generate_list_entities,
    "fetch": generate_fetch_entities,
    "show": generate_get_entity,
    "delete": generate_delete_entity,
    "create": generate_create_entity,
    "update": generate_update_entity,
    "patch": generate_patch_entity,
    "add_member": generate_add_member,
    "remove_member": generate_remove_member,
    "list_members": generate_list_members,
}


def generate_endpoints(entity: Entity, bp: APIBlueprint, logger: Logger):
    """Generates the endpoints for an entity and adds them to a blueprint.

    The generated endpoints are those determined by the entity's "operations" field.
    In addition, if the entity is a MemberEntity, the member operations are also generated.

    Args:
        entity: The entity for which to generate the endpoints.
        bp: The APIBlueprint instance to which the endpoints should be added.
    Returns:
        A dictionary with the generated endpoints.
    """
    logger.info(f"Generating endpoints for {entity.name}")

    for op in entity.operations:
        entity.endpoints[op] = GENERATOR[op](entity, bp, logger)
    if isinstance(entity, MemberEntity):
        for me in entity.members:
            for op in me.operations:
                me.endpoints[op] = GENERATOR[op](me, bp, logger)
    return entity.endpoints
