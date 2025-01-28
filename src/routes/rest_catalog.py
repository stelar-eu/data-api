from __future__ import annotations

import functools
import json
import logging
from typing import List, Optional

from apiflask import APIBlueprint
from flask import jsonify, request, session

import cutils
import kutils

# Input schema for validating and structuring several API requests
import schema
from auth import security_doc, token_active
from exceptions import APIException, DataError, ValidationError

logger = logging.getLogger(__name__)

rest_catalog_bp = APIBlueprint(
    "rest_catalog_blueprint", __name__, tag="RESTful Publishing Operations"
)

# ------------------------------------------------------------
#             DATASETS
# ------------------------------------------------------------


@rest_catalog_bp.errorhandler(500)
def api_internal_error(ex):
    import traceback

    logging.exception("Internal error")
    return jsonify({"exception": traceback.format_exc()}), 500


@rest_catalog_bp.route("/datasets", methods=["GET"])
@rest_catalog_bp.doc(tags=["RESTful Search Operations"], security=security_doc)
@rest_catalog_bp.input(schema.PaginationParameters, location="query")
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_get_datasets(query_data):
    """
    Retrieve a list of datasets with rich information about each entry. Only Datasets, not workflows

    This endpoint allows clients to fetch dataset details, with the ability to specify
    a limit and offset for pagination.

    Args: (In URL)
        - 'limit' (int): Optional, The number of datasets to return. If not specified all datasets
            will be returned.
        - 'offset' (int): Optional, The offset (starting point) for the pagination.

    Responses:
        - 200: Datasets successfully retrieved.
        - 500: An unknown error occurred.

    Returns:
        dict: A JSON response containing the dataset details or error information.
    """
    try:
        offset = query_data.get("offset", None)
        limit = query_data.get("limit", None)

        resp = cutils.get_packages(
            limit=limit, offset=offset, tag_filter="Workflow", filter_mode="discard"
        )
        return {
            "success": True,
            "result": {"count": len(resp), "datasets": resp},
            "help": request.url,
        }, 200
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/datasets/list", methods=["GET"])
@rest_catalog_bp.doc(tags=["RESTful Search Operations"], security=security_doc)
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_list_datasets():
    """
    List all dataset IDs in the CKAN catalog.

    This function retrieves a list of dataset identifiers from the Data Catalog.
    It is designed to be used for exploratory or bulk operations where only the
    IDs of datasets are required.

    Responses:
        - 200: A list of dataset IDs retrieved successfully.
        - 500: An unknown error occurred during the listing process.

    Returns:
        dict: A JSON response containing the list of dataset IDs or an error message.
    """
    try:
        resp = cutils.list_packages()
        return {"success": True, "result": {"datasets": resp}, "help": request.url}, 200
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/datasets/<dataset_id>", methods=["GET"])
@rest_catalog_bp.doc(tags=["RESTful Search Operations"], security=security_doc)
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_get_dataset(dataset_id: str):
    """
    Retrieve a dataset from the Data Catalog by its ID with full information.

    This route allows clients to query the catalog and fetch details of a dataset
    using its unique dataset ID (`dataset_id`).

    Args:
        dataset_id (str): The unique identifier for the dataset to retrieve.

    Responses:
        - 200: Dataset successfully retrieved.
        - 404: Dataset not found in the catalog.
        - 500: An unknown error occurred.

    Returns:
        dict: A JSON response containing the dataset details or error information.
    """
    try:
        resp = cutils.get_package(dataset_id)
        return {"success": True, "result": {"dataset": resp}, "help": request.url}, 200

    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Dataset Entity Not Found"},
            "help": request.url,
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/datasets", methods=["POST"])
@rest_catalog_bp.input(schema.Dataset, location="json")
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@rest_catalog_bp.doc(tags=["RESTful Publishing Operations"], security=security_doc)
@token_active
def api_rest_create_dataset(json_data):
    """
    Create and publish a dataset in the Data Catalog.

    This route allows clients to publish datasets by sending metadata in the request body.
    It supports the inclusion of basic, extra, and profile metadata for the dataset.

    Request Body:
        - basic_metadata: Mandatory metadata for the dataset (e.g., title, tags, description).
        - extra_metadata: Optional additional metadata (e.g., theme, spatial data).
        - profile_metadata: Optional profile-related metadata (e.g., resource files or URLs).

    Responses:
        - 200: Dataset successfully created and returned.
        - 400: Missing required metadata or invalid parameters.
        - 409: Dataset name already exists in the catalog.
        - 500: An unknown error occurred.

    Args:
        json_data (dict): The validated JSON input containing dataset metadata.

    Returns:
        dict: A JSON response containing success status, the newly created dataset, or error details.
    """
    try:
        specs = json.loads(request.data.decode("utf-8"))

        if specs.get("basic_metadata"):
            if request.headers.get("Authorization"):
                user = kutils.get_user_by_token(
                    access_token=request.headers.get("Authorization").split(" ")[1]
                )
            else:
                user = kutils.get_user_by_token(
                    access_token=session.get("access_token")
                )
            if user:
                specs.get("basic_metadata")["author"] = user.get("username")
                specs.get("basic_metadata")["author_email"] = user.get("email")

        resp = cutils.create_package(
            specs.get("basic_metadata"),
            specs.get("extra_metadata"),
            specs.get("profile_metadata"),
        )
        return {"success": True, "result": {"dataset": resp}, "help": request.url}, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Missing Parameters Error",
            },
            "success": False,
        }, 400
    except AttributeError as ae:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ae}",
                "__type": "Package Name Already Exists Error",
            },
            "success": False,
        }, 409
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/datasets/<dataset_id>", methods=["PATCH"])
@rest_catalog_bp.doc(tags=["RESTful Publishing Operations"], security=security_doc)
@rest_catalog_bp.input(schema.Package, location="json")
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_patch_dataset(dataset_id: str, json_data):
    """
    Patch a dataset in the Data Catalog by its ID.
    The dataset metadata (e.g., name, description, tags) is passed in the request body.
    Any existing attributes that are excluded but their respective fields are included
    in the body WILL BE REMOVED.

    Args:
        - dataset_id (str): The unique identifier of the dataset in the Data Catalog.
        - json_data (dict): The JSON data containing the package metadata to update the dataset.

    Responses:
        - 200: Dataset successfully patched and returned.
        - 404: Dataset not found in the catalog.
        - 500: An unknown error occurred.
    Returns:
        - dict: A response with success status and the updated dataset details if successful.
    """
    try:
        specs = json.loads(request.data.decode("utf-8"))
        resp = cutils.patch_package(dataset_id, specs.get("package_metadata"))
        return {"success": True, "result": {"dataset": resp}, "help": request.url}, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Dataset Entity Not Found",
            },
            "success": False,
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/datasets/<dataset_id>", methods=["DELETE"])
@rest_catalog_bp.doc(tags=["RESTful Publishing Operations"], security=security_doc)
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_delete_dataset(dataset_id):
    """
    Delete a dataset in the Data Catalog by its ID.
    Any catalog resources associated with the dataset will also be deleted.
    ! ATTENTION ! This action performs a hard-delete and the dataset will no longer be retrievable.

    Args:
        - dataset_id (str): The unique identifier of the dataset in the Data Catalog.

    Responses:
        - 200: Dataset successfully deleted and returned.
        - 404: Dataset not found in the catalog.
        - 500: An unknown error occurred.
    Returns:
        - id (str): The ID of the deleted dataset when the action was performed succesfully.
    """

    try:
        resp = cutils.delete_package(dataset_id)
        return {"success": True, "result": {"dataset": resp}, "help": request.url}, 200

    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Package Entity Not Found"},
            "help": request.url,
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


# --------------------------------------------------------
#                    RESOURCES
# --------------------------------------------------------


@rest_catalog_bp.route("/datasets/<dataset_id>/resources", methods=["GET"])
@rest_catalog_bp.route("/datasets/<dataset_id>/resources/<filter>", methods=["GET"])
@rest_catalog_bp.doc(tags=["RESTful Search Operations"], security=security_doc)
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_get_dataset_resources(dataset_id: str, filter: str = None):
    """
    Retrieve the resources of a Dataset from the Data Catalog by its ID with full information.

    This route allows clients to query the catalog and fetch details of dataset resources

    Args:
        filter (str, Optional): __'owned'__ for resources that have the 'owned' relation with the
        dataset or __'profile'__ for generated profile resources.

    Responses:
        - 200: Dataset successfully retrieved.
        - 404: Dataset not found in the catalog.
        - 500: An unknown error occurred.

    Returns:
        dict: A JSON response containing the dataset details or error information.
    """
    try:
        resp = cutils.get_package_resources(dataset_id, filter)
        return {
            "success": True,
            "result": {"count": len(resp), "resources": resp},
            "help": request.url,
        }, 200

    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Package Entity Not Found"},
            "help": request.url,
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/datasets/<dataset_id>/resource", methods=["POST"])
@rest_catalog_bp.doc(tags=["RESTful Publishing Operations"], security=security_doc)
@rest_catalog_bp.input(schema.Resource, location="json")
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_create_resource(dataset_id: str, json_data):
    """
    Create a new resource associated with a dataset.

    This route allows clients to create a resource in the Data Catalog associated with a dataset.
    The resource published from here will be __owned__ by the dataset if the relation is not explicitely
    specified in the resource JSON.

    Args:
        resource_metatada (dict): The JSON body containing the information about the new resource.

    Responses:
        - 200: Resource successfully created.
        - 404: Package in which the resource was going to be published is not found.
        - 500: An unknown error occurred.

    Returns:
        dict: A JSON response containing the resource details or error information.
    """
    try:
        specs = json.loads(request.data.decode("utf-8"))
        resp = cutils.create_resource(dataset_id, specs.get("resource_metadata"))
        return {"success": True, "result": {"resource": resp}, "help": request.url}, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Dataset Entity Not Found",
            },
            "success": False,
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/resources/<resource_id>", methods=["GET"])
@rest_catalog_bp.doc(tags=["RESTful Search Operations"], security=security_doc)
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_get_resource(resource_id: str):
    """
    Retrieve a resource by its ID with full information.

    This route allows clients to query the catalog and fetch details of a specific resource by UUID

    Args:
        resource_id (str): The UUID of the resource.

    Responses:
        - 200: Resource successfully retrieved.
        - 404: Resource with ID not found in the catalog.
        - 500: An unknown error occurred.

    Returns:
        dict: A JSON response containing the resource details or error information.
    """
    try:
        resp = cutils.get_resource(resource_id)
        return {"success": True, "result": {"resource": resp}, "help": request.url}, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Resource Entity Not Found",
            },
            "success": False,
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/resources/<resource_id>", methods=["DELETE"])
@rest_catalog_bp.doc(tags=["RESTful Publishing Operations"], security=security_doc)
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_delete_resource(resource_id: str):
    """
    Delete a resource by its ID.

    This route allows clients to delete a specific resource by UUID

    Args:
        resource_id (str): The UUID of the resource.

    Responses:
        - 200: Resource successfully deleted.
        - 404: Resource with ID not found in the catalog.
        - 500: An unknown error occurred.

    Returns:
        id (str): The ID of the deleted resource.
    """
    try:
        resp = cutils.delete_resource(resource_id)
        return {"success": True, "result": {"resource": resp}, "help": request.url}, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Resource Entity Not Found",
            },
            "success": False,
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@rest_catalog_bp.route("/resources/<resource_id>", methods=["PATCH"])
@rest_catalog_bp.doc(tags=["RESTful Publishing Operations"], security=security_doc)
@rest_catalog_bp.input(schema.Resource, location="json")
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_patch_resource(resource_id: str, json_data):
    """
    Patch a resource's fields without deleting any omitted ones by its ID.

    This route allows clients to edit a specific resource by UUID

    Args:
        resource_id (str): The UUID of the resource.

    Responses:
        - 200: Resource successfully patched.
        - 400: Missing parameters
        - 404: Resource with ID not found in the catalog.
        - 500: An unknown error occurred.

    Returns:
        id (str): The ID of the deleted resource.
    """
    try:
        specs = json.loads(request.data.decode("utf-8"))
        resp = cutils.patch_resource(resource_id, specs.get("resource_metadata"))
        return {"success": True, "result": {"resource": resp}, "help": request.url}, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Resource Entity Not Found",
            },
            "success": False,
        }, 404
    except AttributeError as ae:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ae}",
                "__type": "Resource Parameters Missing",
            },
            "success": False,
        }, 400
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


# ------------------------------------------------------------
#  Generic stuff
# ------------------------------------------------------------


class Entity:
    def __init__(
        self, name, collection_name, ckan_name=None, extras=True, creation_schema=None
    ):
        self.name = name
        self.collection_name = collection_name

        self.ckan_name = ckan_name if ckan_name is not None else name
        self.ckan_api_list = f"{self.ckan_name}_list"
        self.ckan_api_show = f"{self.ckan_name}_show"
        self.ckan_api_create = f"{self.ckan_name}_create"
        self.ckan_api_delete = f"{self.ckan_name}_delete"
        self.ckan_api_purge = f"{self.ckan_name}_purge"
        self.ckan_api_update = f"{self.ckan_name}_update"
        self.ckan_api_patch = f"{self.ckan_name}_patch"

        self.creation_schema = creation_schema

        if extras:
            self.has_extras = True
            self.has_tags = True

        # Store the endpoint functions
        self.endpoints = {}

    def save_to_ckan(self, init_data):
        # Implement the logic to save data to CKAN
        if self.has_tags and "tags" in init_data:
            tags = init_data["tags"]
            init_data["tags"] = [cutils.tag_string_to_object(tag) for tag in tags]

        if self.has_extras and "extras" in init_data:
            extras = [{"key": k, "value": v} for k, v in init_data["extras"].items()]
            init_data["extras"] = extras

        return init_data

    def load_from_ckan(self, ci):
        if self.has_tags and "tags" in ci:
            tags = [cutils.tag_object_to_string(tagobj) for tagobj in ci["tags"]]
            ci["tags"] = tags

        if self.has_extras and "extras" in ci:
            extras = {e["key"]: e["value"] for e in ci["extras"]}
            ci["extras"] = extras

        return ci

    @staticmethod
    def check_limit_offset(val, name):
        if not isinstance(val, Optional[int]):
            raise DataError(f"{name} must be an integer, or None")
        if val is not None:
            if val < 0:
                raise ValidationError(f"{name} must be nonnegative")

    def list_entities(self, limit: Optional[int] = None, offset: Optional[int] = None):
        self.check_limit_offset(limit, "limit")
        self.check_limit_offset(offset, "offset")
        return cutils.ckan_request(self.ckan_api_list, limit=limit, offset=offset)

    def get_entity(self, eid: str):
        obj = cutils.ckan_request(
            self.ckan_api_show, id=eid, context={"entity": self.name}
        )
        return self.load_from_ckan(obj)

    def create_entity(self, init_data):
        context = {"entity": self.name}

        ckinit_data = self.save_to_ckan(init_data)

        obj = cutils.ckan_request(
            self.ckan_api_create, context=context, json=ckinit_data
        )
        return self.load_from_ckan(obj)

    def delete_entity(self, eid: str, purge=False):
        context = {"entity": self.name}
        if purge:
            return cutils.ckan_request(self.ckan_api_purge, id=eid, context=context)
        else:
            return cutils.ckan_request(self.ckan_api_delete, id=eid, context=context)

    def update_entity(self, eid: str, entity_data):
        context = {"entity": self.name}

        ck_data = self.save_to_ckan(entity_data)

        obj = cutils.ckan_request(
            self.ckan_api_update, id=eid, context=context, json=ck_data
        )
        return self.load_from_ckan(obj)

    def patch_entity(self, eid: str, patch_data):
        context = {"entity": self.name}

        ckpatch_data = self.save_to_ckan(patch_data)

        obj = cutils.ckan_request(
            self.ckan_api_patch, id=eid, context=context, json=ckpatch_data
        )
        return self.load_from_ckan(obj)


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


def render_api_output(endp_func):
    """Decorator for generic endpoints that handles exceptions uniformly"""

    @functools.wraps(endp_func)
    def exc_handler(*args, **kwargs):
        try:
            return generic_api_result(endp_func(*args, **kwargs))
        except APIException as ex:
            logger.exception("API error")
            return generic_api_exception(ex)
        except Exception as e:
            logger.exception("Internal error")
            return generic_error_500(e)

    return exc_handler


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


def generate_list_entities(entity: Entity):
    """This method generates the entity "list" endpoints"""

    @rest_catalog_bp.get(f"/{entity.collection_name}")
    @rest_catalog_bp.input(schema.PaginationParameters, location="query")
    @rest_catalog_bp.output(schema.EntityListResponse, status_code=200)
    @rest_catalog_bp.doc(
        summary=f"List {entity.collection_name} in the Data Catalog",
        description=f"""List all {entity.collection_name} in the Data Catalog. \\
        This function returns a list of {entity.collection_name} identifiers. \\
        It is designed to be used for exploratory or bulk operations where only the IDs of {entity.collection_name} are required. \\
        """,
        tags=["RESTful Search Operations"],
        security=security_doc,
        responses=error_responses([409, 500]),
    )
    @token_active
    @render_api_output
    @rename_endpoint(f"api_list_{entity.collection_name}")
    def generic_list_entities(query_data):
        limit = query_data.get("limit", None)
        offset = query_data.get("offset", None)

        return entity.list_entities(limit=limit, offset=offset)

    return generic_list_entities


def generate_get_entity(entity: Entity):
    """Generates the entity get endpoints"""

    @rest_catalog_bp.get(f"/{entity.name}/<entity_id>")
    @rest_catalog_bp.output(schema.APIResponse, status_code=200)
    @rest_catalog_bp.doc(
        summary=f"Get {entity.name} by ID",
        description=f"""Retrieve a {entity.name} from the Data Catalog by its ID with full information. \\
        This route allows clients to query the catalog and fetch details of a {entity.name} using its unique 
        {entity.name} ID. \\
        """,
        tags=["RESTful Search Operations"],
        security=security_doc,
        responses=error_responses([400, 404, 500]),
    )
    @token_active
    @render_api_output
    @rename_endpoint(f"api_get_{entity.name}")
    def generic_get_entity(entity_id: str):
        return entity.get_entity(entity_id)

    return generic_get_entity


def generate_delete_entity(entity: Entity):
    @rest_catalog_bp.delete(f"/{entity.name}/<entity_id>")
    @rest_catalog_bp.input(schema.DeleteRequest, location="query")
    @rest_catalog_bp.output(schema.DeleteResponse, status_code=200)
    @rest_catalog_bp.doc(
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
        responses=error_responses([400, 403, 404, 409, 500]),
    )
    @token_active
    @render_api_output
    @rename_endpoint(f"api_delete_{entity.name}")
    def generic_delete_entity(entity_id: str, query_data: Optional[bool] = False):
        logger.error("Cannot get here! fot the love of god")
        logger.info(f"Deleting {entity.name} {entity_id} with purge={query_data}")
        purge = query_data.get("purge", False)
        return entity.delete_entity(entity_id, purge=purge)


def generate_create_entity(entity: Entity):
    """Generates the entity create endpoints"""

    @rest_catalog_bp.post(f"/{entity.name}")
    @rest_catalog_bp.input(schema.Dataset, location="json")
    @rest_catalog_bp.output(schema.APIResponse, status_code=200)
    @rest_catalog_bp.doc(
        summary=f"Create {entity.name}",
        description=f"""Create and publish a {entity.name} in the Data Catalog. \\  
        This route allows clients to publish {entity.name} by sending metadata in the request body. \\
        It supports the inclusion of basic, extra, and profile metadata for the {entity.name}. \\
        """,
        tags=["RESTful Publishing Operations"],
        security=security_doc,
        responses=error_responses([400, 403, 404, 500]),
    )
    @token_active
    @render_api_output
    @rename_endpoint(f"api_create_{entity.name}")
    def TODO():
        pass


GROUP = Entity("group", "groups")
ORGANIZATION = Entity("organization", "organizations")

DATASET = Entity("datset", "datsets", ckan_name="package")
DATASET.ckan_api_purge = "dataset_purge"

RESOURCE = Entity("resource", "resources")


for e in [GROUP, ORGANIZATION, DATASET, RESOURCE]:
    e.endpoints["list"] = generate_list_entities(e)
    e.endpoints["get"] = generate_get_entity(e)
    e.endpoints["delete"] = generate_delete_entity(e)
