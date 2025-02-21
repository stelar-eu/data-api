import logging

from apiflask import APIBlueprint
from flask import request

import schema
import tools
import wflow
import wxutils
from auth import token_active

# Input schema for validating and structuring several API requests
from routes.generic import generate_endpoints

logger = logging.getLogger(__name__)

workflows_bp = APIBlueprint(
    "rest_workflows_blueprint", __name__, tag="RESTful Workflow Operations"
)

#########################################################
##################### WORKFLOWS #########################
#########################################################

logger.info(f"Generating endpoints for process")
generate_endpoints(wxutils.PROCESS, workflows_bp, logger)
generate_endpoints(tools.TOOL, workflows_bp, logger)
generate_endpoints(wflow.WORKFLOW, workflows_bp, logger)


#########################################################
######################## TASKS ##########################
#########################################################


@workflows_bp.route("/tasks/<task_id>", methods=["GET"])
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_get_task_metadata(task_id):
    """Return the metadata of the specific Task Execution. This JSON contains the task's state, metrics, messages, image, and other details.

    Args:
        task_id: The unique identifier of the Task Execution.
    Returns:
        A JSON with the task metadata
    Responses:
        - 200: Task metadata successfully returned.
        - 404: Task is not found
        - 500: An unknown error occurred
    """
    try:
        resp = wxutils.get_task_metadata(task_id)
        return {"success": True, "result": {"task": resp}, "help": request.url}, 200

    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Task Not Found Error"},
            "help": request.url,
        }, 404
    except RuntimeError as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Task Creation Runtime Error",
            },
            "success": False,
        }, 500


@workflows_bp.route("/tasks", methods=["POST"])
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@workflows_bp.input(schema.Task_Input_v2, location="json")
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_create_task(json_data):
    """Create a new Task Execution in the Workflow Execution Engine.
    Args:
        task_spec: The validated JSON input containing task metadata.

    Returns:
        A JSON response containing success status, the newly created task, or error details.
    Responses:
        - 200: Task successfully created and returned.
        - 400: Missing required metadata or invalid parameters.
        - 403: Workflow already committed.
        - 500: An unknown error occurred.
    """
    try:
        access_token = request.headers.get("Authorization").split(" ")[1]
        resp = wxutils.create_task(json_data, access_token)
        return {"success": True, "result": {"task": resp}, "help": request.url}, 200

    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Task Creation Error"},
            "help": request.url,
        }, 400
    except AttributeError as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Workflow Already Committed Error",
            },
            "success": False,
        }, 403
    except RuntimeError as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Task Creation Runtime Error",
            },
            "success": False,
        }, 500


@workflows_bp.route("/tasks/<task_id>/input", methods=["GET"])
@workflows_bp.route("/tasks/<task_id>/<signature>/input", methods=["GET"])
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_rest_get_task_input(task_id, signature=None):
    """Return the input JSON of the specific Task Execution.

    This JSON is given to the tool during its initialization.

    Args:
        id: The unique identifier of the Task Execution.

    Returns:
        A JSON with the inputs, parameters & MinIO credentials

    Responses:
        - 200: Task input JSON successfully returned.
        - 400: Task ID is not valid.
        - 404: Task is not found.
        - 500: An unknown error occurred.
    """
    try:
        access_token = request.headers.get("Authorization").split(" ")[1]
        resp = wxutils.get_task_input_json(
            task_id=task_id, signature=signature, access_token=access_token
        )
        return {"success": True, "result": resp, "help": ""}, 200
    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Task Not Found"},
            "help": "",
        }, 404
    except AttributeError as e:
        return {
            "help": "",
            "error": {
                "name": f"Error: {e}",
                "__type": "Not valid Task ID",
            },
            "success": False,
        }, 400
    except RuntimeError as e:
        return {
            "help": "",
            "error": {
                "name": f"Error: {e}",
                "__type": "Task Fetch Runtime Error",
            },
            "success": False,
        }, 500


@workflows_bp.route("/tasks/<task_id>/<signature>/output", methods=["POST"])
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@workflows_bp.input(schema.Task_Output, location="json")
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
def api_rest_post_task_output(task_id, signature, json_data):
    """
    Handles the output of a task execution. Accepts the output files created by the tool, the metrics
    and the logs generated during the execution. The files are validated and metadata are generated
    based on the specifications provided in the tool creation request.

    Args:
        task_id: The unique identifier of the Task.
        signature: The unique signature of the Task Execution, acting as the authentication mechanism.
    Returns:
        A JSON response containing success status, or error details.
    Responses:
        - 200: Task output successfully posted.
        - 400: Invalid task ID or missing parameters.
        - 401: Invalid signature. Access denied.
        - 404: Task not found.
        - 500: An unknown error occurred.
    """
    try:
        resp = wxutils.get_task_output_json(
            task_id=task_id, signature=signature, output_json=json_data
        )
        return {
            "success": True,
            "result": {"task_id": task_id, "output_published": resp},
            "help": "",
        }, 200
    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Task Not Found"},
            "help": request.url,
        }, 404
    except AttributeError as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Not valid Task ID",
            },
            "success": False,
        }, 400
    except AssertionError as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Invalid Signature",
            },
            "success": False,
        }, 401
    except RuntimeError as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Task Fetch Runtime Error",
            },
            "success": False,
        }, 500


@workflows_bp.route("/tasks/<task_id>/logs", methods=["GET"])
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_get_task_logs(task_id):
    """Return the logs of the specific Task Execution.

    This JSON contains the logs of the task fetched from the Execution Engine.

    Args:
        task_id: The unique identifier of the Task Execution.
    Returns:
        A JSON with the logs of the task.
    Responses:
        - 200: Task logs successfully returned.
        - 500: An unknown error occurred.
    """
    try:
        logs = wxutils.get_task_logs(task_id)
        return {"success": True, "result": {"logs": logs}, "help": request.url}, 200
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@workflows_bp.route("/tasks/<task_id>/jobs", methods=["GET"])
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_get_task_jobs(task_id):
    """Return the information of jobs for a specific task.

    This JSON contains the logs, status and other information
    of the task fetched from the Execution Engine.

    Args:
        task_id: The unique identifier of the Task Execution.
    Returns:
        A JSON with the runtime info of the task.
    Responses:
        - 200: Task logs successfully returned.
        - 500: An unknown error occurred.
    """
    try:
        logs = wxutils.get_task_info(task_id)
        return {"success": True, "result": {"jobs": logs}, "help": request.url}, 200
    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {e}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@workflows_bp.route("/tasks/<task_id>", methods=["DELETE"])
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_delete_task(task_id):
    """Delete a Task Execution from the Workflow Execution Engine.
    Args:
        task_id: The unique identifier of the Task Execution.
    Returns:
        A JSON response containing success status, or error
    Responses:
        - 200: Task successfully deleted.
        - 404: Task not found.
        - 500: An unknown error occurred.
    """
    try:
        resp = wxutils.delete_task(task_id)
        return {"success": True, "result": {task_id: resp}, "help": request.url}, 200
    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Task Not Found Error"},
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


@workflows_bp.route("/tasks/<task_id>", methods=["PATCH"])
@workflows_bp.input(schema.WorkflowState, location="json")
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@token_active
def api_update_task_state(task_id, json_data):
    """Update the state of a task given its unique identifier.
    Args:
        task_id: The unique identifier of the Task Execution.
        json_data: The validated JSON input containing the new state of the task. Only the state field is required.
        The state must be one of the following: 'failed', 'succeeded', 'running'.
    Returns:
        A JSON response containing success status, or error
    Responses:
        - 200: Task successfully deleted.
        - 404: Task not found.
        - 500: An unknown error occurred.
    """
    try:
        is_updated, state = wxutils.update_task_state(task_id, json_data.get("state"))
        if is_updated:
            return {
                "success": True,
                "result": {"task_id": task_id, "state": state},
                "help": request.url,
            }, 200
        else:
            return {
                "help": request.url,
                "error": {
                    "name": f"Error: Task State {state} not valid",
                    "__type": "Task State Update Error",
                },
                "success": False,
            }, 400
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Task Not Found Error",
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
