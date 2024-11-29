from flask import request, jsonify, current_app, session, make_response, render_template
from apiflask import APIBlueprint
import mutils as mu
import kutils as ku
import monitor_module as mon
import reconciliation_module as rec
from src.auth import auth, security_doc, admin_required
import yaml
import schema
import sql_utils
import uuid
import kutils

auth_tool_bp = APIBlueprint('auth_tool_blueprint', __name__, tag='Authorization Management')

@auth_tool_bp.route('/layout', methods=['POST'])
@auth_tool_bp.doc(tags=['Authorization Management'], security=security_doc)
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

    if request.content_type != 'application/x-yaml':
        return {
            "help": request.url,
            "error": {
                "name": f"Error: The 'Content-Type' header should be 'application/x-yaml'",
                '__type': 'Incorrect Headers Error',
            },
            "success": False
        }, 400

    try:
    
        keycloak_openid = ku.initialize_keycloak_openid()

        token = keycloak_openid.token(grant_type="client_credentials")
        print(token['access_token'])

        credentials = mu.get_temp_minio_credentials(token["access_token"])

        minio_admin = mu.initialize_minio_admin(ac_key=credentials["AccessKeyId"],sec_key=credentials["SecretAccessKey"],token=credentials["SessionToken"])

        # Read the file content and load it as a dictionary
        yaml_content = yaml.safe_load(request.data)

        resources_list = []

        for res in yaml_content['resources']:
            for buck in res['subfolders']:
                res_dict = {
                    "bucketname": res['name'],
                    "subfolders": res['subfolders'],
                }
            resources_list.append(res_dict)

        for item in resources_list:
            mu.create_bucket_and_subfolders(minio_admin,item)

        return {
                'help' : request.url,
                'result': {
                    'layout':yaml_content
                },
                'success': True
            }, 200
    except yaml.YAMLError as e:


        return jsonify({"error": "Failed to parse YAML", "details": str(e)}), 400
    
    
@auth_tool_bp.route('/policy', methods=['POST'])
@auth_tool_bp.doc(tags=['Authorization Management'], security=security_doc)
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

    if request.content_type != 'application/x-yaml':
        return {
            "help": request.url,
            "error": {
                "name": f"Error: The 'Content-Type' header should be 'application/x-yaml'",
                '__type': 'Incorrect Headers Error',
            },
            "success": False
        }, 400

    try:
        #initialize keycloak admin through service accounts
        keycloak_admin = ku.init_admin_client_with_credentials()

        # #get minio client id
        client_id = keycloak_admin.get_client_id("minio")

        # Read the file content and load it as a dictionary
        yaml_content = yaml.safe_load(request.data)
        yaml_str = request.data

        roles_list = []

        # Process roles
        for role in yaml_content['roles']:
            for perm in role['permissions']:
                role_dict = {
                    "name": role['name'],
                    "permissions": role['permissions'],
                    # "resource": perm['resource']
                }
            roles_list.append(role_dict)
        
        existing_realm_roles = mon.get_current_realm_roles(keycloak_admin)
        existing_policies = mon.get_current_policies()
        existing_client_roles = mon.get_current_client_roles(keycloak_admin)

        roles_to_delete = rec.update_roles_from_yaml(roles_list,existing_realm_roles)
        ku.delete_realm_roles(keycloak_admin,roles_to_delete)

        policies_to_delete,policy_names_set = rec.update_policies_from_yaml(roles_list,existing_policies)
        mu.delete_policies(policies_to_delete)

        client_roles_to_delete = rec.update_client_roles(policy_names_set,existing_client_roles)
        ku.delete_client_roles(keycloak_admin,client_roles_to_delete)

        for item in roles_list:
            role_name = item.get("name")
            realm_role_name = ku.create_realm_role(keycloak_admin, role_name)
            policy_name_list = mu.create_policy(item['permissions'])
            for policy in policy_name_list:
                client_role_name = ku.create_client_role(keycloak_admin, "minio", client_id, policy) ##check on that
                keycloak_admin.add_composite_realm_roles_to_role(realm_role_name,[keycloak_admin.get_client_role(client_id,client_role_name)])
        
        policy_id = str(uuid.uuid4())
        user_id = ""

        user = kutils.get_user_by_token(access_token=request.headers.get('Authorization').split(" ")[1])
        if user:
            user_id = user.get('username')

        if sql_utils.policy_version_create(policy_id, "Not specified", True, str(yaml_str), user_id):
            return {
                'help' : request.url,
                'result': {
                    'policy':yaml_content
                },
                'success': True
            }, 200
        else:
             return {
                "help": request.url,
                "error": {
                    "name": f"Error: The new policy was not stored in the database",
                    '__type': 'Policy Not Stored Error',
                },
                "success": False
            }, 500

    except Exception as e:
        return {
                "help": request.url,
                "error": {
                    "name": f"Error: {str(e)}",
                    '__type': 'Unknown Error',
                },
                "success": False
            }, 500