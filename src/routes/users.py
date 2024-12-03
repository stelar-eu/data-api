from flask import request, jsonify, current_app, url_for
from apiflask import APIBlueprint
import requests
from src.auth import auth, security_doc, admin_required, token_active
# Auxiliary custom functions & SQL query templates for ranking
import utils
import logging 
# Input schema for validating and structuring several API requests
import schema
import xml.etree.ElementTree as ET
import kutils
import mutils
from email_validator import validate_email, EmailNotValidError
import smtplib
import ssl

from demo_t import get_demo_ckan_token

"""
    This .py file contains the endpoints attached to the blueprint
    responsible for all operations related to the lifecycle of
    users in the ecosystem.

    Follows the REST logic.
"""

logging.basicConfig(level=logging.DEBUG)

# The users operations blueprint for all operations related to the lifecycle of a user
users_bp = APIBlueprint('users_blueprint', __name__, tag={'name':'User Management','description':'Operations related to management of users (CRUD, Authentication)'})


@users_bp.route('/', methods=['GET'])
@users_bp.doc(tags=['User Management'], security=security_doc)
@users_bp.input(schema.PaginationParameters, location='query')
@users_bp.output(schema.ResponseAmbiguous, status_code=200, example={"help":"http://klms.stelar.gr/stelar/docs","success":True,"result":{"count":2,"users":[{"active":True,"email":"user1@example.com","fullname":"User One","joined_date":"01-01-2024","roles":["admin"],"user_id":"uuid-1234","username":"userone"},{"active":True,"email":"user2@example.com","fullname":"User Two","joined_date":"01-01-2024","roles":["user"],"user_id":"uuid-5678","username":"usertwo"}]}})
@token_active
@admin_required
def get_users(query_data):
    """
        Returns all users of the STELAR KLMS in a JSON. Requires admin role. Supports pagination.

        Returns:
            - dict():  The JSON containing the users

        Args optionally:
            - limit: Maximum number of users returned per request, if limit is 0 all users are returned.
            - offset: Offset of the result by #offset user.
    """
    try:
        offset = query_data.get('offset', 0)
        limit = query_data.get('limit', 0)
        
        users = kutils.get_users_from_keycloak(offset=offset, limit=limit)
        
        return {
            'help': request.url,
            'result':  { 
                'users': users,
                'count': len(users)
            },
            'success': True
        }, 200    
    except ValueError as ve:
        return {
                'help' : request.url,
                'result': {str(e)},
                'success': False
        }, 400
    except Exception as e:
        return {
                'help' : request.url,
                'result': {str(e)},
                'success': False
        }, 500

@users_bp.route('/token', methods=['POST'])
@users_bp.input(schema.NewToken, location='json', example={"username": "dpetrou", "password": "mypassword"})
@users_bp.output(schema.ResponseOK, example={"help":"https://klms.stelar.gr/stelar/docs","result":{"token":"$$$ACCESS_TOKEN$$$","refresh_token":"$$$REFRESH_TOKEN$$$"},"success":True}, status_code=200)
@users_bp.doc(tags=['User Management'])
def api_token_create(json_data):
    """
    Generate an OAuth2.0 token for an existing user.
    Args in a JSON:
        - username: The username of the user
        - password: The user's secret password

    Returns:
        - A JSON response with the OAuth2.0 token or an error message.
    """

    try:
        username = json_data.get('username')
        password = json_data.get('password')
        token = kutils.get_token(username, password)
        if token:
            return {
                'help' : request.url,
                'result': {
                    'token': token['access_token'],
                    'refresh_token': token['refresh_token']
                },
                'success': True
            }, 200
        else:
            return {
                'help' : request.url,
                'result': {},
                'success': False
            }, 400
    except Exception:
        return {
                'help' : request.url,
                'result': {},
                'success': False
        }, 400


@users_bp.route('/token', methods=['PUT'])
@users_bp.input(schema.RefreshToken, location='json', example={"refresh_token": "$$$REFRESH_TOKEN$$$"})
@users_bp.output(schema.ResponseOK, example={"help":"https://klms.stelar.gr/stelar/docs","result":{"token":"$$$ACCESS_TOKEN$$$","refresh_token":"$$$REFRESH_TOKEN$$$"},"success":True}, status_code=200)
@users_bp.doc(tags=['User Management'])
def api_token_refresh(json_data):
    """
    Refresh an OAuth2.0 token using a refresh token.

    Args in a JSON:
        - refresh_token: (In JSON) : The refresh token retrieved during the token issuance.

    Returns:
        - A JSON response with the OAuth2.0 token or an error message.
    """

    try:
        reftoken = json_data.get('refresh_token')

        token = kutils.refresh_access_token(reftoken)

        if token:
            return {
                'help' : request.url,
                'result': {
                    'token': token['access_token'],
                    'refresh_token': token['refresh_token']
                },
                'success': True
            }, 200
        else:
            return {
                'help' : request.url,
                'result': {},
                'success': False
            }, 400
    except Exception as e:
        return {
                'help' : request.url,
                'result': {},
                'success': False
        }, 400

@users_bp.route('/', methods=['POST'])
@users_bp.input(schema.NewUser, location='json')
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@token_active
@admin_required
def api_create_user(json_data):
    """
    Creates a new user in the STELAR KLMS. Requires admin role.

    Args:
        - New user description in JSON in the request body.

    JSON Fields (validated against schema.NewUser):
        - username (str): The username for the new user. Should be unique.
        - email (str): The user's email address. Should be unique.
        - firstName (str): The user's first name.
        - lastName (str): The user's last name.
        - password (str): The user's password.
        - enabled (bool): Whether the user account should be enabled.
    """
    try:
        username = json_data["username"]
        email = json_data["email"]
        first_name = json_data["firstName"]
        last_name = json_data["lastName"]
        password = json_data["password"]
        enabled = json_data.get("enabled", True)  
        attributes = json_data.get("attributes", {})

        user_id = kutils.create_user_with_password(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password=password,
            enabled=enabled)

        if not user_id:
            raise RuntimeError("Failed to create user. Please check the logs for details.")

        # Retrieve and return the newly created user representation
        user_rep = kutils.get_user(user_id)

        if user_rep:
            return {
                'help': request.url,
                'result': {
                    'user': user_rep
                },
                'success': True
            }, 200
        else:
            raise AttributeError(f"Failed to find user with identifier: {user_id}")

    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Validation error: {ve}",
                '__type': 'User Entity Error',
            },
            "success": False
        }, 400
    
    except AttributeError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'User Entity Not Found',
            },
            "success": False
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


@users_bp.route('/<user_id>', methods=['GET'])
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@token_active
@admin_required
def api_get_user(user_id):
    """Get information about a specific STELAR KLMS User by ID. Requires admin role.
       
       Args:
       - user_id: The UUID of the user in STELAR KLMS or the username.
    """

    try:
        user_rep = kutils.get_user(user_id=user_id)
        if user_rep:
            return {
                'help': request.url,
                'result': {
                    'user': user_rep
                },
                'success': True
            }, 200
        else:
            raise AttributeError(f"Failed to find user with identifier: {user_id}")

    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Validation error: {ve}",
                '__type': 'User Entity Error',
            },
            "success": False
        }, 400

    except AttributeError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'User Entity Not Found',
            },
            "success": False
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



@users_bp.route('/<user_id>', methods=['PATCH'])
@users_bp.input(schema.UpdatedUser, location='json')
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@token_active
def api_put_user(user_id, json_data):
    """
    Update information of a specific STELAR KLMS User by ID. Requires admin role.

    Args:
        - The UUID or the username of the user to be updated.

    JSON Fields:
        - username (str) (Optional): The username for the new user. Should be unique.
        - email (str) (Optional): The user's email address. Should be unique.
        - firstName (str) (Optional): The user's first name.
        - lastName (str) (Optional): The user's last name.
        - enabled (bool) (Optional): Whether the user account should be enabled.
    
    Returns:
        - A JSON with the updated user
    """

    try:
        username = json_data.get("username")
        email = json_data.get("email")
        first_name = json_data.get('firstName')
        last_name = json_data.get("lastName")
        enabled = json_data.get("enabled", True)  

        user_upd = kutils.update_user(user_id=user_id,
                                      username=username,
                                      first_name=first_name,
                                      last_name=last_name,
                                      email=email,
                                      enabled=enabled)
        if user_upd:
            return {
                "success":True, 
                "result":{
                    "user": user_upd
                },
                "help": request.url
            }, 200
        else:
            raise AttributeError(f"User with ID or username: {user_id} not found")
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Validation error: {ve}",
                '__type': 'User Entity Error',
            },
            "success": False
        }, 400
    except AttributeError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'User Entity Not Found',
            },
            "success": False
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

@users_bp.route('/<user_id>', methods=['DELETE'])
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@token_active
def api_delete_user(user_id):
    """
    Delete a specific STELAR KLMS User by ID or by username. Requires admin role.

    Args:
     - The UUID or the username of the user to be deleted.

    Returns:
     - The UUID of the deleted user
    """

    try:
        id = kutils.delete_user(user_id)
        if id:
            return {
                "success":True, 
                "result":{
                    "deleted_id": id
                },
                "help": request.url
            },200

    except AttributeError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'User Entity Not Found',
            },
            "success": False
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



@users_bp.route('/roles', methods=['GET'])
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['Authorization Management'], security=security_doc)
@token_active
@admin_required
def api_get_roles():
    """
    Get roles existing in the STELAR KLMS. Requires admin role.

    Returns:
        - A JSON containing the roles present inside the KLMS with.
    """

    try:
        roles = kutils.get_realm_roles()

        return {
            "success":True, 
            "result":{
                "roles": roles
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


@users_bp.route('/<user_id>/roles/<role_id>', methods=['POST'])
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['Authorization Management'], security=security_doc)
@token_active
@admin_required
def api_assign_role(user_id, role_id):
    """Assign role to a specific STELAR KLMS User by ID and by Role ID. Requires admin role.

    Args:
        - user_id: The UUID of the user or the username.
        - role_id: The UUID of the role or the name of it.
        
    Returns:
        - JSON: the updated user description
    """

    try:
        user = kutils.assign_role_to_user(user_id, role_id)
        return {
            "success":True, 
            "result":{
                "user": user
            },
            "help": request.url
        }, 200
    except AttributeError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Uniqueness error: {ve}",
                '__type': 'Entity Already Present',
            },
            "success": False
        }, 400
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'Entity Not Found',
            },
            "success": False
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


@users_bp.route('/<user_id>/roles/<role_id>', methods=['DELETE'])
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['Authorization Management'], security=security_doc)
@token_active
@admin_required
def api_delete_role(user_id, role_id):
    """Unassign role from a specific STELAR KLMS User by ID. Requires admin role.

    Args:
        - user_id: The UUID of the user or the username.
        - role_id: The UUID of the role or the name of it.

    Returns:
        - JSON: the updated user description
    """
    try:
        user = kutils.unassign_role_from_user(user_id, role_id)
        return {
            "success":True, 
            "result":{
                "user": user
            },
            "help": request.url
        }, 200
    except AttributeError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'Entity Not Present',
            },
            "success": False
        }, 400
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'Entity Not Found',
            },
            "success": False
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


@users_bp.route('/<user_id>/roles', methods=['POST'])
@users_bp.input(schema.RolesInput, location='json')
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['Authorization Management'], security=security_doc)
@token_active
@admin_required
def api_assign_roles(user_id, json_data):
    """
    Assing lot-of roles to a specific STELAR KLMS User by id. Requires admin role.
    This will not remove any roles already assigned to the user.
    Args:
        - user_id: The UUID of the user or the username.
        - roles: A list containing the role name or role IDs to be assigned.
    Returns:
        - JSON: the updated user description
    """ 
    try:
        user = kutils.assign_roles_to_user(user_id, json_data.get("roles"))
        return {
            "success":True, 
            "result":{
                "user": user
            },
            "help": request.url
        }, 200
    except AttributeError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'Entity Not Present',
            },
            "success": False
        }, 400
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'Entity Not Found',
            },
            "success": False
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


@users_bp.route('/<user_id>/roles', methods=['PATCH'])
@users_bp.input(schema.RolesInput, location='json')
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['Authorization Management'], security=security_doc)
@token_active
@admin_required
def api_patch_roles(user_id, json_data):
    """Patch the roles of a user in the STELAR KLMS. Requires admin role.
       This will remove any roles not present in the input JSON and assign 
       the ones specified. 

       Args:
       - user_id: The UUID or the username of the user.
       - roles: A list containing the role name or role IDs to be patched.

       Returns:
       - JSON: the updated user description
    """

    try:
        user = kutils.patch_user_roles(user_id=user_id, role_ids=json_data['roles'])
        return {
            "success":True, 
            "result":{
                "user": user
            },
            "help": request.url
        }, 200
    except AttributeError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'Entity Not Present',
            },
            "success": False
        }, 400
    except ValueError as ve:
        return {
            "help": request.url,
            "error": {
                "name": f"Existence error: {ve}",
                '__type': 'Entity Not Found',
            },
            "success": False
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
        
@users_bp.route('/s3/credentials', methods=['GET'])
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@token_active
def api_acquire_s3_creds():
    """Returns a set of STS S3 Credentials for the user to use within the STELAR Client's context. 

       Returns:
       - JSON: Containing the S3 API URL and the STS credentials.
       
    """
    
    try:
        access_token = request.headers['Authorization'].replace("Bearer ","")
        config = current_app.config['settings']
        minio_url = "https://"+config['MINIO_API_SUBDOMAIN']+"."+config['KLMS_DOMAIN_NAME']
        creds = mutils.get_temp_minio_credentials(access_token=access_token)
        creds['S3Url'] = minio_url
        return {
            "success":True, 
            "result":{
                "creds": creds
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


@users_bp.route('/activation', methods=['POST'])
@users_bp.input(schema.ActivationInput, location='json')
@users_bp.output(schema.ResponseAmbiguous, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@token_active
@admin_required
def send_activation_email(json_data):

    id = json_data.get('id')
    try:
        user = kutils.get_user(id)
    except:
        return
    
    fullname = user.get('fullname')
    username = user.get('username')
    email = user.get('email')
     

    """
    Sends the activation email to the specified email address with a subject and sender name.
    SMTP settings are fetched from Flask's app config.
    """
    config = current_app.config['settings']  # Fetch SMTP settings from app config

    smtp_server = config['SMTP_SERVER']
    smtp_port = config['SMTP_PORT']
    sender_email = config['SMTP_EMAIL']
    sender_password = config['SMTP_PASSWORD']

    # Email subject and sender name
    subject = "Your Account Is Activated"
    sender_name = "STELAR KLMS"

    # Plain text message without headers (headers will be handled separately)
    plain_message = f"""\
Dear {fullname},

Your username is: {username}

Your account has been activated. Visit the KLMS and sign in below using the password you set during your registration: 

https://{config['MAIN_INGRESS_SUBDOMAIN']}.{config['KLMS_DOMAIN_NAME']}{url_for('dashboard_blueprint.login')}

If you received this email by accident, please ignore it.

Kind Regards,
STELAR KLMS
"""
    # Create the full email message with subject, sender, and receiver
    full_message = f"Subject: {subject}\nFrom: {sender_name} <{sender_email}>\nTo: {email}\n\n{plain_message}"

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL(smtp_server, int(smtp_port), context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, full_message)
            return {
                "success":True, 
                "result":{
                    "id": id
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


##################################################################
#   Up to this point (^) the endpoints have become Keycloak 
#   compatible. 
##################################################################

def api_user_editor():
    """Finds the organization(s) where the given user is assigned a role (admin/editor/member) in CKAN.

    Args:
        None; it assumes the user corresponding to the specified API Token.

    Returns:
        The organization(s) where this user has been assigned a role.
    """
    #EXAMPLE: curl -X POST -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/catalog/user/organization

    config = current_app.config['settings']

    if request.method == 'POST' and request.headers:
        if request.headers:
            package_headers, resource_headers = utils.create_CKAN_headers(
                get_demo_ckan_token()
            )
            # Make a POST request to the CKAN API using this API token for user identification
            response = requests.post(config['CKAN_API']+'organization_list_for_user', headers=resource_headers)  #auth=HTTPBasicAuth(config.username, config.password))  
            return response.json()
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the user.']}}
        return jsonify(response)