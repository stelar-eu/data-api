import uuid

import yaml
from apiflask import APIBlueprint
from flask import (
    Response,
    jsonify,
    request,
    session,
)
import logging
import kutils
import kutils as ku
import monitor_module as mon
import mutils as mu
import reconciliation_module as rec
import schema
import sql_utils
from authz_module import AuthorizationModule
from data_module import DataModule
from auth import admin_required, auth, security_doc

auth_tool_bp = APIBlueprint(
    "auth_tool_blueprint", __name__, tag="Authorization Management"
)


logger = logging.getLogger(__name__)


@auth_tool_bp.route("/layout", methods=["POST"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@auth_tool_bp.output(schema.ResponseAmbiguous, status_code=200)
@auth.verify_token
@admin_required
def create_data_layout():
    """
    Accepts a YAML in the body desribing the desired layout to be applied to the MinIO instance
    the KLMS cluster is connected to. The layout describes the bucket and the paths that the organization
    requires. For documentation see more on: ....

    Args:
        - layout (YAML):  In request body with header `application/x-yaml`

    Returns:
        - layout (JSON): The layout parsed and applied to the object store.
    """

    if request.content_type != "application/x-yaml":
        return {
            "help": request.url,
            "error": {
                "name": f"Error: The 'Content-Type' header should be 'application/x-yaml'",
                "__type": "Incorrect Headers Error",
            },
            "success": False,
        }, 400

    try:
        keycloak_openid = ku.initialize_keycloak_openid()

        token = keycloak_openid.token(grant_type="client_credentials")
        print(token["access_token"])

        credentials = mu.get_temp_minio_credentials(token["access_token"])

        minio_admin = mu.initialize_minio_admin(
            ac_key=credentials["AccessKeyId"],
            sec_key=credentials["SecretAccessKey"],
            token=credentials["SessionToken"],
        )

        # Read the file content and load it as a dictionary
        yaml_content = yaml.safe_load(request.data)

        resources_list = []

        for res in yaml_content["resources"]:
            for buck in res["subfolders"]:
                res_dict = {
                    "bucketname": res["name"],
                    "subfolders": res["subfolders"],
                }
            resources_list.append(res_dict)

        for item in resources_list:
            mu.create_bucket_and_subfolders(minio_admin, item)

        return {
            "help": request.url,
            "result": {"layout": yaml_content},
            "success": True,
        }, 200
    except yaml.YAMLError as e:
        return jsonify({"error": "Failed to parse YAML", "details": str(e)}), 400


@auth_tool_bp.route("/policy", methods=["POST"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@auth_tool_bp.output(schema.ResponseAmbiguous, status_code=200)
@auth.verify_token
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

    if request.content_type != "application/x-yaml":
        return {
            "help": request.url,
            "error": {
                "name": f"Error: The 'Content-Type' header should be 'application/x-yaml'",
                "__type": "Incorrect Headers Error",
            },
            "success": False,
        }, 400

    try:
        try:
            access_token = request.headers.get("Authorization").split(" ")[1]
        except:
            try:
                access_token = session.get("access_token")
            except:
                return {
                    "help": request.url,
                    "error": {
                        "name": f"Error: The new policy will not be applied",
                        "__type": "Policy Not Stored Error",
                    },
                    "success": False,
                }, 401
            
        logger.info(f"callling authz module")
        yaml_str = request.data
        yaml_content = AuthorizationModule(config=request.data)()
        DataModule(config=request.data)
        ####################################################################################
        ########################## store policy file to db #################################
        logger.info(f"store policy file to db")
        policy_id = str(uuid.uuid4())
        user_id = ""

        user = kutils.get_user_by_token(access_token)
        if user:
            user_id = user.get("username")

        if sql_utils.policy_version_create(
            policy_id, "Not specified", True, str(yaml_str), user_id
        ):
            return {
                "help": request.url,
                "result": {"policy": yaml_content},
                "success": True,
            }, 200
        else:
            return {
                "help": request.url,
                "error": {
                    "name": f"Error: The new policy was not stored in the database",
                    "__type": "Policy Not Stored Error",
                },
                "success": False,
            }, 500               

    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {str(e)}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@auth_tool_bp.route("/policy/representation/<policy_filter>", methods=["GET"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@auth.verify_token
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

    try:
        policy_repr = sql_utils.policy_representation_read(policy_filter)
        if policy_repr.startswith("b'"):
            policy_repr = policy_repr[2:-1]

        formatted_yaml_string = policy_repr.encode("utf-8").decode("unicode_escape")

        # parsed_data, data_format = utils.detect_and_parse(formatted_yaml_string)

        # if data_format == 'JSON':
        #     # formatted_yaml_string = json.loads(parsed_data)
        #     formatted_yaml_string = yaml.dump(parsed_data, default_flow_style=False)

        if formatted_yaml_string != None:
            return Response(
                formatted_yaml_string, status=200, content_type="application/x-yaml"
            )

        else:
            return {
                "help": request.url,
                "error": {
                    "name": f"Error: The policy not found in the database",
                    "__type": "Policy Not Found Error",
                },
                "success": False,
            }, 500

    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {str(e)}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@auth_tool_bp.route("/policy/<policy_filter>", methods=["GET"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@auth.verify_token
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
    try:
        policy_info = sql_utils.policy_info_read(policy_filter)

        if policy_info != None:
            return {
                "help": request.url,
                "result": {"policy": policy_info},
                "success": True,
            }, 200
        else:
            return {
                "help": request.url,
                "error": {
                    "name": f"Error: The info for this policy not found in the database",
                    "__type": "Policy Info Not Found Error",
                },
                "success": False,
            }, 500

    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {str(e)}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500


@auth_tool_bp.route("/policy", methods=["GET"])
@auth_tool_bp.doc(tags=["Authorization Management"], security=security_doc)
@auth_tool_bp.output(schema.ResponseAmbiguous, status_code=200)
@auth.verify_token
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

    try:
        policies = sql_utils.list_policies()
        if policies is not None:
            return {
                "help": request.url,
                "result": {"count": len(policies), "policies": policies},
                "success": True,
            }, 200
        else:
            return {
                "help": request.url,
                "error": {
                    "name": f"Error: Could not fetch policies",
                    "__type": "Policies Not Fetched Error",
                },
                "success": False,
            }, 500

    except Exception as e:
        return {
            "help": request.url,
            "error": {
                "name": f"Error: {str(e)}",
                "__type": "Unknown Error",
            },
            "success": False,
        }, 500
