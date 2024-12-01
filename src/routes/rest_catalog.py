from flask import request, jsonify, current_app
from apiflask import APIBlueprint
from src.auth import auth, security_doc, admin_required, token_active
# Auxiliary custom functions & SQL query templates for ranking
import logging 
# Input schema for validating and structuring several API requests
import schema
import json
import cutils
import kutils

rest_catalog_bp = APIBlueprint('rest_catalog_blueprint', __name__, tag='RESTful Publishing Operations')

#########################################################
##################### DATASETS ##########################
#########################################################

@rest_catalog_bp.route("/datasets", methods=["GET"])
@rest_catalog_bp.doc(tags=['RESTful Search Operations'], security=security_doc)
@rest_catalog_bp.input(schema.PaginationParameters, location='query')
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
        offset = query_data.get('offset', 0)
        limit = query_data.get('limit', 0)

        resp = cutils.get_packages(limit=limit, offset=offset, tag_filter="Workflow", filter_mode='discard')
        return {
                "success":True, 
                "result":{
                    "count": len(resp),
                    "datasets": resp
                },
                "help": request.url
        }, 200
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500



@rest_catalog_bp.route("/datasets/list", methods=["GET"])
@rest_catalog_bp.doc(tags=['RESTful Search Operations'], security=security_doc)
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
        return {
                "success":True, 
                "result":{
                    "datasets": resp
                },
                "help": request.url
        }, 200
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500

@rest_catalog_bp.route("/datasets/<dataset_id>", methods=["GET"])
@rest_catalog_bp.doc(tags=['RESTful Search Operations'], security=security_doc)
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
        return {
                "success":True, 
                "result":{
                    "dataset": resp
                },
                "help": request.url
        }, 200
    
    except ValueError as ve:
        return {
                "success":False, 
                "error":{
                    "name": f"Error: {ve}",
                    "__type":"Dataset Entity Not Found"
                },
                "help": request.url
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500

@rest_catalog_bp.route("/datasets", methods=["POST"])
@rest_catalog_bp.input(schema.Dataset, location='json')
@rest_catalog_bp.output(schema.ResponseAmbiguous, status_code=200)
@rest_catalog_bp.doc(tags=['RESTful Publishing Operations'], security=security_doc)
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

        if specs.get('basic_metadata'):
            user = kutils.get_user_by_token(access_token=request.headers.get('Authorization').split(" ")[1])
            if user:
                specs.get('basic_metadata')['author'] = user.get('username')
                specs.get('basic_metadata')['author_email'] = user.get('email')
        
        resp = cutils.create_package(specs.get('basic_metadata'), specs.get('extra_metadata'), specs.get('profile_metadata'))
        return {
                "success":True, 
                "result":{
                    "dataset": resp
                },
                "help": request.url
        }, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                '__type': 'Missing Parameters Error',
            },
            "success": False
        }, 400
    except AttributeError as ae:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ae}",
                '__type': 'Package Name Already Exists Error',
            },
            "success": False
        }, 409
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500


@rest_catalog_bp.route("/datasets/<dataset_id>",methods=["PATCH"])
@rest_catalog_bp.doc(tags=['RESTful Publishing Operations'], security=security_doc)
@rest_catalog_bp.input(schema.Package, location='json')
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
        return {
                "success":True, 
                "result":{
                    "dataset": resp
                },
                "help": request.url
        }, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                '__type': 'Dataset Entity Not Found',
            },
            "success": False
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500


@rest_catalog_bp.route("/datasets/<dataset_id>",methods=["DELETE"])
@rest_catalog_bp.doc(tags=['RESTful Publishing Operations'], security=security_doc)
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
        return {
                "success":True, 
                "result":{
                    "dataset": resp
                },
                "help": request.url
        }, 200
    
    except ValueError as ve:
        return {
                "success":False, 
                "error":{
                    "name": f"Error: {ve}",
                    "__type":"Package Entity Not Found"
                },
                "help": request.url
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500

#########################################################
##################### RESOURCES #########################
#########################################################

@rest_catalog_bp.route("/datasets/<dataset_id>/resources", methods=["GET"])
@rest_catalog_bp.route("/datasets/<dataset_id>/resources/<filter>", methods=["GET"])
@rest_catalog_bp.doc(tags=['RESTful Search Operations'], security=security_doc)
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
                "success":True, 
                "result":{
                    "count": len(resp),
                    "resources": resp
                },
                "help": request.url
        }, 200
    
    except ValueError as ve:
        return {
                "success":False, 
                "error":{
                    "name": f"Error: {ve}",
                    "__type":"Package Entity Not Found"
                },
                "help": request.url
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500

@rest_catalog_bp.route("/datasets/<dataset_id>/resource", methods=["POST"])
@rest_catalog_bp.doc(tags=['RESTful Publishing Operations'], security=security_doc)
@rest_catalog_bp.input(schema.Resource, location='json')
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
        return {
                "success":True, 
                "result":{
                    "resource": resp
                },
                "help": request.url
        }, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                '__type': 'Dataset Entity Not Found',
            },
            "success": False
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500


@rest_catalog_bp.route("/resources/<resource_id>",methods=["GET"])
@rest_catalog_bp.doc(tags=['RESTful Search Operations'], security=security_doc)
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
        return {
                "success":True, 
                "result":{
                    "resource": resp
                },
                "help": request.url
        }, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                '__type': 'Resource Entity Not Found',
            },
            "success": False
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500


@rest_catalog_bp.route("/resources/<resource_id>",methods=["DELETE"])
@rest_catalog_bp.doc(tags=['RESTful Publishing Operations'], security=security_doc)
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
        return {
                "success":True, 
                "result":{
                    "resource": resp
                },
                "help": request.url
        }, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                '__type': 'Resource Entity Not Found',
            },
            "success": False
        }, 404
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500

@rest_catalog_bp.route("/resources/<resource_id>",methods=["PATCH"])
@rest_catalog_bp.doc(tags=['RESTful Publishing Operations'], security=security_doc)
@rest_catalog_bp.input(schema.Resource, location='json')
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
        return {
                "success":True, 
                "result":{
                    "resource": resp
                },
                "help": request.url
        }, 200
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                '__type': 'Resource Entity Not Found',
            },
            "success": False
        }, 404
    except AttributeError as ae:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ae}",
                '__type': 'Resource Parameters Missing',
            },
            "success": False
        }, 400
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Unknown Error',
            },
            "success": False
        }, 500