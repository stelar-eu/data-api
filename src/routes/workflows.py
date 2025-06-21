import logging

from apiflask import APIBlueprint
from flask import request

import kutils
import processes
import schema
import tasks
import tools
import wflow
from auth import token_active
from qutils import REGISTRY

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
# ----------------------- REGISTRY -----------------------
# --------------------------------------------------------
@workflows_bp.route("/registry/credentials", methods=["GET"])
@workflows_bp.doc(tags=["Registry Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_get_registry_credentials():
    """Returns the application credentials of the current user.

    Returns:
        A JSON with the application credentials for the current user.
    Responses:
        - 200: Registry credentials successfully returned.
        - 500: An unknown error occurred.
    """
    return REGISTRY.get_app_tokens()


@workflows_bp.route("/registry/credentials/<token_id>", methods=["GET"])
@workflows_bp.doc(tags=["Registry Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_get_registry_credential(token_id):
    """Returns the detail for a set of application credentials of the current user.

    Returns:
        A JSON with the application credentials for the current user.
    Responses:
        - 200: Registry credentials successfully returned.
        - 500: An unknown error occurred.
    """
    return REGISTRY.get_app_token(token_id)


@workflows_bp.route("/registry/credentials", methods=["POST"])
@workflows_bp.doc(tags=["Registry Operations"])
@workflows_bp.input(schema.RegistryCredentials, location="json")
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_create_registry_credentials(json_data):
    """Creates a new application token for the current user.
    Args:
        json_data: The validated JSON input containing the application token spec.
    Returns:
        A JSON with the application token details.
    """
    return REGISTRY.generate_app_token(json_data["title"])


@workflows_bp.route("/registry/credentials/<token_id>", methods=["DELETE"])
@workflows_bp.doc(tags=["Registry Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_revoke_registry_credentials(token_id):
    """Revokes an application token for the current user.
    Args:
        token_id: The unique identifier of the application token.
    Returns:
        A JSON with the details of the revoked application token.
    """
    return REGISTRY.revoke_app_token(token_id)


# --------------------------------------------------------
# ----------------------- IMAGES -------------------------
# --------------------------------------------------------
@workflows_bp.route("/tool/<entity_id>/manifests", methods=["GET"])
@workflows_bp.doc(tags=["Tool Image Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_get_tool_image_manifests(entity_id):
    """Returns the image manifests of the specific Tool. This JSON contains the manifest digests.

    Args:
        entity_id: The unique identifier of the Tool.
    Returns:
        A JSON with the image tag manifests
    Responses:
        - 200: Tool image manifests successfully returned.
        - 404: Tool is not found
        - 500: An unknown error occurred
    """
    return REGISTRY.get_hashes(tools.TOOL.get_entity(entity_id)["repository"])


@workflows_bp.route("/tool/<entity_id>/image/<image_tag>", methods=["GET"])
@workflows_bp.doc(tags=["Tool Image Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_get_tag_manifest(entity_id, image_tag):
    """Returns the tag manifest of the specific Tool.
    Args:
        entity_id: The unique identifier of the Tool.
        image_tag: The tag of the image.
    Returns:
        A JSON with the image tag manifest
    Responses:
        - 200: Tool image manifest successfully returned.
        - 404: Tool is not found
        - 500: An unknown error occurred
    """
    return REGISTRY.get_manifest(
        tools.TOOL.get_entity(entity_id)["repository"], image_tag
    )


@workflows_bp.route("/tool/<entity_id>/image", methods=["GET"])
@workflows_bp.doc(tags=["Tool Image Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_get_tool_repository(entity_id):
    """Returns the image repository of the specific Tool. This JSON contains the image repository.
    Args:
        entity_id: The unique identifier of the Tool.
    Returns:
        A JSON with the image repository metadata
    Responses:
        - 200: Tool image repository successfully returned.
        - 404: Tool is not found
        - 500: An unknown error occurred
    """
    return REGISTRY.get_repository(tools.TOOL.get_entity(entity_id)["repository"])


# --------------------------------------------------------
# ------------------------ TASKS -------------------------
# --------------------------------------------------------
@workflows_bp.route("/tasks", methods=["GET"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.input(schema.TaskListQuery, location="query")
@workflows_bp.output(schema.APIResponse, status_code=200)
@token_active
@render_api_output(logger)
def api_get_tasks(query_data):
    """Return the list of all Task Executions, optionally per state.
    The administrator can get all tasks, while other users can only get their own tasks.

    Returns:
        A JSON with the list of tasks
    Responses:
        - 200: Tasks successfully returned.
        - 500: An unknown error occurred.
    """
    return tasks.TASK.list_entities(
        query_data.get("state"), query_data.get("limit"), query_data.get("offset")
    )


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


@workflows_bp.route("/task/<task_id>/input", methods=["GET"])
@workflows_bp.route("/task/<task_id>/<signature>/input", methods=["GET"])
@workflows_bp.route("/tasks/<task_id>/<signature>/input", methods=["GET"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@token_active
@render_api_output(logger, lambda req: "Hidden for security reasons")
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
@render_api_output(logger, lambda req: "Hidden for security reasons")
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


@workflows_bp.route("/task/<task_id>/terminate", methods=["POST"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_post_task_terminate(task_id):
    """Terminate a Task Execution.
    This will stop the task execution in the Workflow Execution Engine and mark it as failed.

    Args:
        task_id: The unique identifier of the Task Execution.
    Returns:
        A JSON response containing success status, or error details.
    Responses:
        - 200: Task successfully terminated.
        - 404: Task not found.
        - 500: An unknown error occurred.
    """
    return tasks.TASK.terminate(task_id)


@workflows_bp.route("/task/<task_id>/signature", methods=["GET"])
@workflows_bp.doc(tags=["Task Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_get_task_signature(task_id):
    """Return the signature of the specific Task Execution.

    This signature is used to authenticate the task output submission.
    The administrator can get the signature of any task. Other users
    can only get the signature of their own tasks.

    Args:
        task_id: The unique identifier of the Task Execution.
    Returns:
        A JSON with the signature of the task.
    Responses:
        - 200: Task signature successfully returned.
        - 404: Task is not found
        - 500: An unknown error occurred
    """
    return tasks.TASK.get_signature(task_id)


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
