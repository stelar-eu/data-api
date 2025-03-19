import logging

from apiflask import APIBlueprint
from flask import request

import schema
import tools
import wflow
import processes
import tasks
import kutils
from auth import token_active

# Input schema for validating and structuring several API requests
from routes.generic import generate_endpoints, render_api_output

logger = logging.getLogger(__name__)

workflows_bp = APIBlueprint("rest_workflows_blueprint", __name__, tag="Task Operations")

# --------------------------------------------------------
# ---------------------- WORKFLOWS -----------------------
# --------------------------------------------------------

logger.info("Generating endpoints for process")
generate_endpoints(processes.PROCESS, workflows_bp, logger)
generate_endpoints(tools.TOOL, workflows_bp, logger)
generate_endpoints(wflow.WORKFLOW, workflows_bp, logger)

# --------------------------------------------------------
# ------------------------ TASKS -------------------------
# --------------------------------------------------------


@workflows_bp.route("/task/<entity_id>", methods=["GET"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@token_active
@render_api_output(logger)
def api_get_task_metadata(entity_id):
    """Return the metadata of the specific Task. This JSON contains the task's state, metrics, messages, image, and other details.

    Args:
        task_id: The unique identifier of the Task Execution.
    Returns:
        A JSON with the task metadata
    Responses:
        - 200: Task metadata successfully returned.
        - 404: Task is not found
        - 500: An unknown error occurred
    """
    return tasks.TASK.get_entity(entity_id)


@workflows_bp.route("/task", methods=["POST"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.input(tasks.TaskSchema, location="json")
@workflows_bp.output(schema.APIResponse, status_code=200)
@token_active
@render_api_output(logger)
def api_rest_create_task(json_data):
    """Create a new Task Execution in the Workflow Execution Engine.
    Args:
        task_spec: The validated JSON input containing task spec.
    Returns:
        A JSON response containing success status, the newly created task, or error details.
    """
    return tasks.TASK.create_entity(json_data)


@workflows_bp.route("/task/<entity_id>", methods=["DELETE"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@token_active
@render_api_output(logger)
def api_delete_task(entity_id):
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
    return tasks.TASK.delete_entity(entity_id)


@workflows_bp.route("/task/<entity_id>", methods=["PATCH"])
@workflows_bp.input(schema.WorkflowState, location="json")
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@token_active
@render_api_output(logger)
def api_update_task_state(entity_id, json_data):
    """Update the state of a task given its unique identifier.
    Args:
        task_id: The unique identifier of the Task Execution.
        The state must be one of the following: 'failed', 'succeeded', 'running'.
    Returns:
        A JSON response containing success status, or error
    Responses:
        - 200: Task successfully deleted.
        - 404: Task not found.
        - 500: An unknown error occurred.
    """
    return tasks.TASK.patch_entity(entity_id, json_data.get("state"))


@workflows_bp.route("/task/<task_id>/input", methods=["GET"])
@workflows_bp.route("/task/<task_id>/<signature>/input", methods=["GET"])
@workflows_bp.route("/tasks/<task_id>/<signature>/input", methods=["GET"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@token_active
@render_api_output(logger)
def api_rest_get_task_input(task_id, signature=None):
    """Return the input JSON of the specific Task Execution.

    This JSON is given to the tool during its initialization.

    Args:
        id: The unique identifier of the Task Execution.

    Returns:
        A JSON with the inputs, outputs, parameters & MinIO credentials
    """
    return tasks.TASK.get_input(task_id, kutils.current_token(), signature=signature)


@workflows_bp.route("/task/<task_id>/<signature>/output", methods=["POST"])
@workflows_bp.route("/tasks/<task_id>/<signature>/output", methods=["POST"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.input(schema.Task_Output, location="json")
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
def api_post_task_output(task_id, signature, json_data):
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
    return tasks.TASK.save_output(task_id, signature, json_data)


@workflows_bp.route("/task/<task_id>/logs", methods=["GET"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
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
    return tasks.TASK.get_logs(task_id)


@workflows_bp.route("/task/<task_id>/jobs", methods=["GET"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
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
    return tasks.TASK.get_job_info(task_id)
