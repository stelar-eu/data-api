from __future__ import annotations

import json

# Auxiliary custom functions & SQL query templates for ranking
import logging
from typing import TYPE_CHECKING

from apiflask import APIBlueprint, abort
from flask import current_app, jsonify, request, session

import cutils
import kutils

# Input schema for validating and structuring several API requests
import schema
from auth import admin_required, auth, security_doc, token_active

if TYPE_CHECKING:
    from requests import Response

logger = logging.getLogger(__name__)

rest_catalog_bp = APIBlueprint(
    "rest_catalog_blueprint", __name__, tag="RESTful Publishing Operations"
)

#########################################################
##################### DATASETS ##########################
#########################################################


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
        - 'limit' (int): Optional, The number of datasets to return. If not specified all datasets will be returned.
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


#########################################################
##################### RESOURCES #########################
#########################################################


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
        filter (str, Optional): __'owned'__ for resources that have the 'owned' relation with the dataset or __'profile'__ for generated profile resources.

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


def rename_endpoint(name):
    """To be used as a decorator to rename generic endpoint functions.

    Flask requires distinct paths to be mapped to distinct function names.
    This decorator does this. It should be applied to a function before
    Flask sees it.
    """

    def do_rename(func):
        func.__name__ = name
        return func

    return do_rename


class Entity:
    def __init__(self, name, collection_name, ckan_name=None, extras=True):
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

        if extras:
            self.has_extras = True
            self.has_tags = True

        # Store the endpoint functions
        self.endpoints = {}

    def ckan_list_extra_args(self):
        return {}

    def load_from_ckan(self, ci):
        if self.has_tags and "tags" in ci:
            # N.B. THIS IS WRONG FOR VOCABULARY TAGS!!!!!!!
            tags = [cutils.tag_object_to_string(tagobj) for tagobj in ci["tags"]]
            ci["tags"] = tags

        if self.has_extras and "extras" in ci:
            extras = {e["key"]: e["value"] for e in ci["extras"]}
            ci["extras"] = extras

        return ci


def generic_error_500(entity: Entity, operation: str, exc: Exception):
    import traceback

    return {
        "help": request.url,
        "success": False,
        "error": {
            "message": f"{operation} {entity.name} failed to access Data Catalog",
            "detail": traceback.format_exc(),
        },
    }, 500


def generic_ckan_error(entity: Entity, operation: str, resp: Response):
    return {
        "help": request.url,
        "success": False,
        "error": {
            "message": f"{operation} {entity.name} failed: {resp.json()['error']['__type']}",
            "detail": f"{resp.json()['error']['message']}",
            "extra_data": resp.json()["error"],
        },
    }, resp.status_code


def generate_entity_list(entity: Entity):
    """This method generates the entity "list" endpoints"""

    @rest_catalog_bp.get(f"/{entity.collection_name}")
    @rest_catalog_bp.doc(tags=["RESTful Search Operations"], security=security_doc)
    @rest_catalog_bp.input(schema.PaginationParameters, location="query")
    @rest_catalog_bp.output(schema.EntityListResponse, status_code=200)
    @token_active
    @rename_endpoint(f"api_list_{entity.collection_name}")
    def generic_list_entities(query_data):
        limit = query_data.get("limit", None)
        offset = query_data.get("offset", None)

        try:
            hresp = cutils.raw_request(entity.ckan_api_list, limit=limit, offset=offset)

            response = hresp.json()

            if response["success"]:
                entity_list = response["result"]

                return {
                    "help": request.url,
                    "success": True,
                    "result": entity_list,
                }
            else:
                return generic_ckan_error(entity, "list", hresp)

        except Exception as e:
            return generic_error_500(entity, "list")

    return generic_list_entities


def generate_entity_get(entity: Entity):
    """Generates the entity get endpoints"""

    @rest_catalog_bp.get(f"/{entity.name}/<entity_id>")
    @rest_catalog_bp.doc(tags=["RESTful Search Operations"], security=security_doc)
    @rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
    @token_active
    @rename_endpoint(f"api_get_{entity.name}")
    def generic_list_entities(entity_id: str):
        try:
            hresp = cutils.raw_request(entity.ckan_api_show, id=entity_id)

            response = hresp.json()

            if response["success"]:
                instance = entity.load_from_ckan(response["result"])
                return {
                    "help": request.url,
                    "success": True,
                    "result": instance,
                }
            else:
                return generic_ckan_error(entity, "get", hresp)

        except Exception as e:
            return generic_error_500(entity, "get")

    return generic_list_entities


GROUP = Entity("group", "groups")
ORGANIZATION = Entity("organization", "organizations")
DSET = Entity("dset", "dsets", ckan_name="package")

for e in [GROUP, ORGANIZATION, DSET]:
    e.endpoints["list"] = generate_entity_list(e)
    e.endpoints["get"] = generate_entity_get(e)
