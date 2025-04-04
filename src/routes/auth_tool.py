import logging
import uuid

import yaml
from apiflask import APIBlueprint
from flask import Response, jsonify, request, session

import authz_module
import kutils
import kutils as ku
import monitor_module as mon
import mutils as mu
import reconciliation_module as rec
import schema
import sql_utils
from auth import admin_required, auth, security_doc, token_active
from authz_module import AuthorizationModule
from data_module import DataModule
from routes.generic import render_api_output

auth_tool_bp = APIBlueprint(
    "auth_tool_blueprint", __name__, tag="Authorization Management"
)


logger = logging.getLogger(__name__)

#TODO: update documentation to match the new implementation

@auth_tool_bp.route("/policy", methods=["POST"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@auth_tool_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
@admin_required
def create_roles_function():
    """
    Accepts a YAML in the body desribing the desired roles and permissions to be applied to the Keycloak instance
    the KLMS cluster is connected to. The roles yaml representation describes which roles can perform the specified actions
    in which resources in the MinIO instance
    For documentation see more on: ....

    Args:
        - roles representation (YAML):  In request body with header `application/x-yaml`

    Returns:
        - policy (JSON): The policy JSON object containing the ID of the newly created policy.
    """
    return authz_module.create_authorization_schema(request.data)
    
    


@auth_tool_bp.route("/policy/representation/<policy_filter>", methods=["GET"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@token_active
@admin_required
def get_policy_function(policy_filter):
    """Returns the YAML representation of a policy in the response body as
    application/x-yaml. Requires admin role.

    Args:
        - policy_filter: The UUID of any policy or the keyword 'active' for the currently applied policy.

    Returns:
        - policy (application/x-yaml): The policy YAML in the response body.

    Responses:
        - 200: Policy YAML fetched.
        - 500: Error occured while fetching data.
    """
    return authz_module.retrieve_policy_from_db(policy_filter)
    


@auth_tool_bp.route("/policy/<policy_filter>", methods=["GET"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@auth_tool_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
@admin_required
def get_policy_info_function(policy_filter):
    """Returns the policy metadata in the response body as application/x-yaml. Requires admin role.

    Args:
        - policy_filter: The UUID of any policy or the keyword 'active' for the currently applied policy.

    Returns:
        - JSON: The policy metadata as JSON in the response body.

    Responses:
        - 200: Policy metadata JSON fetched.
        - 500: Error occured while fetching data.
    """

    return authz_module.retrieve_policy_info_from_db(policy_filter)
    

@auth_tool_bp.route("/policy", methods=["GET"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@auth_tool_bp.output(schema.APIResponse, status_code=200)
@render_api_output(logger)
@token_active
@admin_required
def api_list_all_policies():
    """
    Returns a list containing the metadata of all authorization policies applied in the KLMS in the past. Requires admin role.

    Returns:
        - JSON: Policy metadata for all policies.

    Responses:
        - 200: Policies fetched succesfully
        - 500: Error occured while fetching data.
    """
    return authz_module.retrieve_policies_list_from_db()
    