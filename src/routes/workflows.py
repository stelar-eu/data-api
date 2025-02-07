import json
import logging

from apiflask import APIBlueprint
from flask import request, session

import cutils
import kutils
import schema
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


@workflows_bp.route("/workflows", methods=["POST"])
@workflows_bp.input(schema.Workflow, location="json")
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@token_active
def api_rest_create_workflow(json_data):
    """
    Endpoint to create a process and publish a workflow package in the Data Catalog and the Workflow Metadata Database.

    This route allows clients to publish workflows by sending metadata in the request body.


    Request Body:
        - workflow_metadata: Mandatory metadata for the workflow (e.g., title, notes, tags).
        - workflow: Optional metadata for the workflow (e.g., tags).

    Responses:
        - 200: Workflow successfully created and returned.
        - 400: Missing required metadata or invalid parameters.
        - 409: Package name already exists in the catalog.
        - 500: An unknown error occurred.

    Args:
        json_data (dict): The validated JSON input containing workflow metadata.

    Returns:
        dict: A JSON response containing success status, the newly created workflow, or error details.
    """
    try:
        specs = json.loads(request.data.decode("utf-8"))
        wf = specs.get("workflow_metadata")

        if wf:
            if request.headers.get("Authorization"):
                user = kutils.get_user_by_token(
                    access_token=request.headers.get("Authorization").split(" ")[1]
                )
            else:
                user = kutils.get_user_by_token(
                    access_token=session.get("access_token")
                )
            if user:
                specs.get("workflow_metadata")["author"] = user.get("username")
                specs.get("workflow_metadata")["author_email"] = user.get("email")

            wf["tags"].append("Workflow")
            # Create the package in the Data Catalog
            package = cutils.create_package(specs.get("workflow_metadata"))

            # Fetch the ID of the newly created package to link it with the process created afterwards.
            package_id = package.get("id")

            process_tags = dict()

            if specs.get("workflow"):
                process_tags.update(specs.get("workflow").get("tags"))

            process_tags["package_id"] = package_id
            # Create the workflow process in the workflow metadata database.
            process_id = wxutils.create_workflow_process(
                user.get("username"), package_id, process_tags
            )

            resp = dict()
            resp["workflow_process_id"] = process_id
            resp["workflow_package_id"] = package_id
            return {
                "success": True,
                "result": {"workflow": resp},
                "help": request.url,
            }, 200

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


@workflows_bp.route("/workflows/<workflow_id>", methods=["PATCH"])
@workflows_bp.input(schema.WorkflowState, location="json")
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@token_active
def api_rest_update_workflow_state(workflow_id, json_data):
    """Update the state of a workflow process in the Workflow Metadata Database.
    Args:
        workflow_id: The unique identifier of the workflow process.
        json_data: The validated JSON input containing the new state of the workflow process. Only the state field is required. The state must be one of the following: 'failed', 'succeeded', 'running'.
    Returns:
        A JSON response containing success status, the updated workflow state, or error details.
    Responses:
        - 200: Workflow state successfully updated.
        - 400: Invalid state or missing parameters.
        - 404: Workflow not found.
        - 500: An unknown error occurred.
    """
    try:
        is_updated, state = wxutils.update_workflow_state(
            workflow_id, json_data.get("state")
        )
        if is_updated:
            return {
                "success": True,
                "result": {"workflow_id": workflow_id, "state": state},
                "help": request.url,
            }, 200
        else:
            return {
                "help": request.url,
                "error": {
                    "name": f"Error: Workflow State {state} not valid",
                    "__type": "Workflow State Update Error",
                },
                "success": False,
            }, 400
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Workflow Not Found Error",
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


@workflows_bp.route("/workflows/<workflow_id>", methods=["DELETE"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@token_active
def api_rest_delete_workflow(workflow_id):
    """Delete a workflow process from the Workflow Metadata Database.
    Args:
        workflow_id: The unique identifier of the workflow process.
    Returns:
        A JSON response containing success status, or error details.
    Responses:
        - 200: Workflow successfully deleted.
        - 400: Invalid workflow ID.
        - 404: Workflow not found.
        - 500: An unknown error occurred.
    """
    try:
        is_deleted = wxutils.delete_workflow_process(workflow_id)
        if is_deleted:
            return {
                "success": True,
                "result": {"workflow_id": workflow_id},
                "help": request.url,
            }, 200
        else:
            return {
                "help": request.url,
                "error": {
                    "name": f"Error: Workflow {workflow_id} not deleted",
                    "__type": "Workflow Not Deleted Error",
                },
                "success": False,
            }, 500

    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Workflow Not Found Error",
            },
            "success": False,
        }, 404
    except AttributeError as ae:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ae}",
                "__type": "Workflow Process Not Valid ID Error",
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


@workflows_bp.route("/workflows/process", methods=["POST"])
@workflows_bp.input(schema.WorkflowProcess, location="json")
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@token_active
def api_rest_create_workflow_process(json_data):
    """
    Endpoint to create a workflow process in the Workflow Metadata Database and link it to an existing package in the Data Catalog.

    This route allows clients to publish workflows by sending metadata in the request body,

    Request Body:
        - tags: Optional tags for the workflow process.
        - package_id: Mandatory package_id for the workflow process.

    Responses:
        - 200: Workflow successfully created and returned.
        - 400: Missing required metadata or invalid parameters.
        - 404: Package ID not found in the catalog.
        - 500: An unknown error occurred.

    Args:
        json_data (dict): The validated JSON input containing workflow metadata.

    Returns:
        dict: A JSON response containing success status, the newly created workflow, or error details.
    """
    try:
        specs = json.loads(request.data.decode("utf-8"))
        wf = specs.get("workflow_metadata")
        if request.headers.get("Authorization"):
            user = kutils.get_user_by_token(
                access_token=request.headers.get("Authorization").split(" ")[1]
            )
        else:
            user = kutils.get_user_by_token(access_token=session.get("access_token"))

        package_id = specs.get("package_id")
        if cutils.get_package(package_id):
            process_tags = dict()
            process_tags["package_id"] = specs.get("package_id")

            # Create the workflow process in the workflow metadata database.
            process_id = wxutils.create_workflow_process(
                user.get("username"), specs.get("package_id"), process_tags
            )

            resp = dict()
            resp["workflow_process_id"] = process_id
            resp["workflow_package_id"] = package_id
            return {
                "success": True,
                "result": {"workflow": resp},
                "help": request.url,
            }, 200
        else:
            return {
                "help": request.url,
                "error": {
                    "name": f"Error: Package ID {package_id} not found",
                    "__type": "Package Not Found Error",
                },
                "success": False,
            }, 404

    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Missing Parameters Error",
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


@workflows_bp.route("/workflows", methods=["GET"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@token_active
def api_get_workflows():
    """Return the list of workflows in the Workflow Metadata Database.
    Returns:
        A JSON with the list of workflows.
    Responses:
        - 200: Workflows successfully returned.
        - 500: An unknown error occurred.
    """
    try:
        resp = wxutils.get_workflows()
        return {
            "success": True,
            "result": {"count": len(resp), "workflows": resp},
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


@workflows_bp.route("/workflows/<workflow_id>", methods=["GET"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@token_active
def api_get_workflow_metadata(workflow_id: str):
    """
    Endpoint to retrieve a workflow process from the Workflow Metadata Database.

    This route allows clients to query the workflow metadata database for a specific workflow process.

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
        resp = wxutils.get_workflow_process(workflow_id)
        return {"success": True, "result": {"workflow": resp}, "help": request.url}, 200
    except AttributeError as ae:
        return {
            "success": False,
            "error": {
                "name": f"Error: {ae}",
                "__type": "Workflow Process ID Not Valid Error",
            },
            "help": request.url,
        }, 400
    except ValueError as ve:
        return {
            "success": False,
            "error": {
                "name": f"Error: {ve}",
                "__type": "Workflow Process Not Found Error",
            },
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


@workflows_bp.route("/workflows/<workflow_id>/tasks", methods=["GET"])
@workflows_bp.output(schema.ResponseAmbiguous, status_code=200)
@workflows_bp.doc(tags=["RESTful Workflow Operations"])
@token_active
def api_get_workflow_tasks(workflow_id: str):
    """
    Endpoint to retrieve tasks of a workflow process from the Workflow Metadata Database.

    This route allows clients to query the workflow metadata database for tasks of a specific workflow process.

    Args:
        workflow_id (str): The unique identifier of the workflow process to retrieve tasks from.

    Responses:
        - 200: workflow tasks successfully retrieved.
        - 404: workflow not found in the catalog.
        - 500: An unknown error occurred.

    Returns:
        dict: A JSON response containing the dataset details or error information.
    """
    try:
        resp = wxutils.get_workflow_tasks(workflow_id)
        return {"success": True, "result": {"tasks": resp}, "help": request.url}, 200
    except AttributeError as ae:
        return {
            "success": False,
            "error": {
                "name": f"Error: {ae}",
                "__type": "Workflow Process ID Not Valid Error",
            },
            "help": request.url,
        }, 404
    except ValueError as ve:
        return {
            "success": False,
            "error": {"name": f"Error: {ve}", "__type": "Workflow Process Not Found"},
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
    """Return the input JSON of the specific Task Execution. This JSON is given to the tool during its initialization.

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
    """Return the logs of the specific Task Execution. This JSON contains the logs of the task fetched from the Execution Engine. (e.g., Kubernetes)
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
    """Return the information of jobs for a specific task. This JSON contains the logs, status and other information of the task fetched from the Execution Engine. (e.g., Kubernetes)
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
        json_data: The validated JSON input containing the new state of the task. Only the state field is required. The state must be one of the following: 'failed', 'succeeded', 'running'.
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
