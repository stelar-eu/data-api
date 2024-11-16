from flask import request, jsonify, current_app, session, make_response, render_template
from apiflask import APIBlueprint
import mutils as mu
import kutils as ku
import monitor_module as mon
import reconciliation_module as rec
from src.auth import auth, security_doc
import yaml


auth_tool_bp = APIBlueprint('auth_tool_blueprint', __name__, tag='Authorization Tool')


@auth_tool_bp.route('/data_layout', methods=['POST'])
def create_data_layout_function():
    # Check if the request contains a file
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    # Retrieve the file from the request
    file = request.files['file']

    # Ensure it's a YAML file
    if not file.filename.endswith(('.yaml', '.yml')):
        return jsonify({"error": "File format not supported. Please upload a YAML file."}), 400

    try:
    
        keycloak_openid = ku.initialize_keycloak_openid()

        ####### ADD ConsoleAdmin client role to service-account-minio user


        token = keycloak_openid.token(grant_type="client_credentials")
        print(token['access_token'])

        credentials = mu.get_temp_minio_credentials(token["access_token"])

        minio_admin = mu.initialize_minio_admin(ac_key=credentials["AccessKeyId"],sec_key=credentials["SecretAccessKey"],token=credentials["SessionToken"])

        # Read the file content and load it as a dictionary
        yaml_content = yaml.safe_load(file.read())

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

        
        return jsonify({"parsed_yaml": yaml_content}), 200
    except yaml.YAMLError as e:
        return jsonify({"error": "Failed to parse YAML", "details": str(e)}), 400
    
    
@auth_tool_bp.route('/create_roles', methods=['POST'])
def create_roles_function():
    # Check if the request contains a file
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400

    # Retrieve the file from the request
    file = request.files['file']

    # Ensure it's a YAML file
    if not file.filename.endswith(('.yaml', '.yml')):
        return jsonify({"error": "File format not supported. Please upload a YAML file."}), 400

    try:
        #initialize keycloak admin through service accounts
        keycloak_admin = ku.init_admin_client_with_credentials()

        # #get minio client id
        client_id = keycloak_admin.get_client_id("minio")

        # Read the file content and load it as a dictionary
        yaml_content = yaml.safe_load(file.read())

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
        
        return jsonify({"parsed_yaml": yaml_content}), 200
    except yaml.YAMLError as e:
        return jsonify({"error": "Failed to parse YAML", "details": str(e)}), 400