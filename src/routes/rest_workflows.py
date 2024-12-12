from flask import request, jsonify, current_app
from apiflask import APIBlueprint
import requests
from src.auth import auth, security_doc, admin_required, token_active
# Auxiliary custom functions & SQL query templates for ranking
import utils
import logging 
import json
# Input schema for validating and structuring several API requests
import schema
import cutils
import kutils
import wxutils

logging.basicConfig(level=logging.DEBUG)


rest_workflows_bp = APIBlueprint('rest_workflows_blueprint', __name__, tag='RESTful Workflow Operations')

#########################################################
##################### WORKFLOWS #########################
#########################################################

@rest_workflows_bp.route("/workflows",methods=["POST"])
@rest_workflows_bp.input(schema.Workflow, location='json')
@rest_workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@rest_workflows_bp.doc(tags=['RESTful Workflow Operations'])
@token_active
def api_rest_create_workflow(json_data):
    """
    Endpoint to create and publish a workflow in the Data Catalog.

    This route allows clients to publish workflows by sending metadata in the request body.
    It supports only basic metadata

    Request Body:
        - basic_metadata: Mandatory metadata for the workflow (e.g., title, notes, tags).

    Responses:
        - 200: Dataset successfully created and returned.
        - 400: Missing required metadata or invalid parameters.
        - 409: Dataset name already exists in the catalog.
        - 500: An unknown error occurred.

    Args:
        json_data (dict): The validated JSON input containing workflow metadata.

    Returns:
        dict: A JSON response containing success status, the newly created workflow, or error details.
    """
    try:
        specs = json.loads(request.data.decode("utf-8"))
        wf = specs.get('workflow_metadata')
        wf["tags"].append("Workflow")
        resp = cutils.create_package(specs.get('workflow_metadata'))
        return {
                "success":True, 
                "result":{
                    "workflow": resp
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

@rest_workflows_bp.route("/workflows",methods=["GET"])
@rest_workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@rest_workflows_bp.doc(tags=['RESTful Workflow Operations'])
@token_active
def api_rest_get_datasets():
    try:
        resp = cutils.get_packages(tag_filter="Workflow", filter_mode='keep')
        return {
                "success":True, 
                "result":{
                    "count": len(resp),
                    "workflows": resp
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

@rest_workflows_bp.route("/workflows/<workflow_id>",methods=["GET"])
@rest_workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@rest_workflows_bp.doc(tags=['RESTful Workflow Operations'])
@token_active
def api_rest_get_dataset(workflow_id: str):
    """
    Endpoint to retrieve a workflow from the CKAN catalog by its ID.

    This route allows clients to query the catalog and fetch details of a workflow 
    using its unique workflow ID (`workflow_id`).

    Args:
        workflow_id (str): The unique identifier for the workflow to retrieve.

    Responses:
        - 200: workflow successfully retrieved.
        - 404: workflow not found in the catalog.
        - 500: An unknown error occurred.

    Returns:
        dict: A JSON response containing the dataset details or error information.
    """
    try:
        resp = cutils.get_package(workflow_id)
        return {
                "success":True, 
                "result":{
                    "workflow": resp
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

@rest_workflows_bp.route("/workflows/<wid>",methods=["PUT"])
@rest_workflows_bp.doc(tags=['RESTful Workflow Operations'])
@token_active
def api_rest_update_dataset(wid):
    print("Hello")


@rest_workflows_bp.route("/tasks", methods=["POST"])
@rest_workflows_bp.doc(tags=['RESTful Workflow Operations'])
@rest_workflows_bp.input(schema.Task_Input_v2, location='json')
@rest_workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_create_task(json_data):
    try:
        access_token = request.headers.get('Authorization').split(" ")[1]
        resp = wxutils.create_task(json_data,access_token)
        return {
                "success":True, 
                "result":{
                    "task": resp
                },
                "help": request.url
            }, 200

    except ValueError as ve:
        return {
                "success":False, 
                "error":{
                    "name": f"Error: {ve}",
                    "__type":"Use could not be registered as task creator due to token error."
                },
                "help": request.url
        }, 400
    except AttributeError as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Workflow Already Committed Error',
            },
            "success": False
        }, 403
    except RuntimeError as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                '__type': 'Task Creation Runtime Error',
            },
            "success": False
        }, 500
           
