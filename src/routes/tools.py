import logging

from apiflask import APIBlueprint
from flask import request

import schema
import tools
from qutils import REGISTRY
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
# ----------------------- REGISTRY -----------------------
# --------------------------------------------------------


# --------------------------------------------------------
# ------------------------ TOOLS -------------------------
# --------------------------------------------------------
@workflows_bp.route("/tool/<entity_id>/manifests", methods=["GET"])
@workflows_bp.doc(tags=["Tool Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_get_tool_image_manifests(entity_id):
    """Return the image manifests of the specific Tool. This JSON contains the manifest digests.

    Args:
        entity_id: The unique identifier of the Tool.
    Returns:
        A JSON with the image tag manifests
    Responses:
        - 200: Tool image manifests successfully returned.
        - 404: Tool is not found
        - 500: An unknown error occurred
    """
    return REGISTRY.get_hashes(tools.TOOL.get_entity(entity_id)["repository_name"])


@workflows_bp.route("/tool/<entity_id>/manifest/<image_tag>", methods=["GET"])
@workflows_bp.doc(tags=["Tool Operations"])
@workflows_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
def api_get_tag_manifest(entity_id, image_tag):

    return REGISTRY.get_manifest(
        tools.TOOL.get_entity(entity_id)["repository_name"], image_tag
    )
