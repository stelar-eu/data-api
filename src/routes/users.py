from flask import request, jsonify, current_app
from apiflask import APIBlueprint, HTTPTokenAuth
import requests
import json
from src.auth import auth, security_doc
# Auxiliary custom functions & SQL query templates for ranking
import utils

import logging 
# Input schema for validating and structuring several API requests
import schema

import kutils


from demo_t import get_demo_ckan_token

"""
    This .py file contains the endpoints attached to the blueprint
    responsible for all operations related to the lifecycle of
    users in the ecosystem.

    Follows the REST logic.
"""

logging.basicConfig(level=logging.DEBUG)

# The users operations blueprint for all operations related to the lifecycle of a user
# The blueprint preempts the 
users_bp = APIBlueprint('users_blueprint', __name__,tag='User Management')


@users_bp.route('/', methods=['GET'])
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
def get_users():
    """
        Returns all users of the STELAR KLMS in a JSON 
        if token given is related to an admin account

        Returns:
        dict():  The JSON containing the users

        Error: Returns error message
    """

    # Obtain the admin token from request headers
    admin_token = request.headers.get('Authorization')
    if not admin_token:
        response = {
            'success': False, 
            'help': request.url,
            'error': {'__type': 'Authorization Error', 'name': ['No Authorization Bearer Token specified. Please verify the is one present in the headers of your request.']}
        }
        return jsonify(response), 401
    try:
        # Get query parameters from the request
        access_token = request.headers.get('Authorization').split(" ")[1]
        offset = int(request.args.get('offset', 0)) 
        limit = int(request.args.get('limit',0))  

        users = kutils.get_users_from_keycloak(access_token, offset=offset, limit=limit)
       
        result = {
            "help": request.url,
            "result": users,
            "success": True
        }
        
        return jsonify(result), 200

    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400 
    except RuntimeError as re:
        return jsonify({'error': str(re)}), 500 
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@users_bp.route('/token', methods=['POST'])
@users_bp.input(schema.NewToken, location='json', example={"username": "dpetrou", "password": "mypassword"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
def api_token_create(json_data):
    """
    Generate an OAuth2.0 token for an existing user.
    Args:
        In a JSON:
        username: The username of the user
        password: The user's secret password

    Returns:
        A JSON response with the OAuth2.0 token or an error message.
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


@users_bp.route('/users', methods=['POST'])
@users_bp.input(schema.NewUser, location='json', example={"name":"test_user", "email":"test@example.com","password":"test_pass", "fullname":"Jane Doe", "about":"Testing the Keycloak API endpoint for creating another new user", "image_url":"https://commons.wikimedia.org/wiki/File:Example.jpg"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
def api_user_create(json_data):
    """Create a new user in Keycloak. Requires admin role to create new users."""

    # Obtain the admin token from request headers
    admin_token = request.headers.get('Authorization')
    if not admin_token:
        response = {
            'success': False, 
            'help': request.url,
            'error': {'__type': 'Authorization Error', 'name': ['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}
        }
        return jsonify(response)
    
    config = current_app.config['settings']
    keycloak_url = config['KEYCLOAK_URL']
    keycloak_admin_url = f"{keycloak_url}/admin/realms/{config['REALM_NAME']}/users"

    headers = {
        'Authorization': f"{admin_token}",
        'Content-Type': 'application/json'
    }

    user_metadata = {
        "username": json_data['name'],
        "email": json_data['email'],
        "enabled": True,
        "firstName": json_data.get('fullname', ''),
        "credentials": [{
            "type": "password",
            "value": json_data['password'],
            "temporary": False
        }]
    }

    response = requests.post(keycloak_admin_url, headers=headers, json=user_metadata)

    if response.status_code == 201:
        return {"success": True, "message": "User created successfully"}
    else:
        return {"success": False, "error": response.json()}, response.status_code



@users_bp.route('/user/update', methods=['POST'])
@users_bp.input(schema.ChangedUser, location='json', example={"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "about" : "Updated user information"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@auth.login_required
def api_user_update(json_data):
    """Update information for an existing user in Keycloak."""

    admin_token = request.headers.get('Api-Token')
    if not admin_token:
        response = {
            'success': False,
            'help': request.url,
            'error': {'__type': 'Authorization Error', 'name': ['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}
        }
        return jsonify(response)

    config = current_app.config['settings']
    keycloak_url = config['KEYCLOAK_URL']
    user_id = json_data['id']

    keycloak_user_url = f"{keycloak_url}/admin/realms/{config['REALM_NAME']}/users/{user_id}"

    headers = {
        'Authorization': f"Bearer {admin_token}",
        'Content-Type': 'application/json'
    }

    user_metadata = {
        "attributes": {
            "about": json_data.get('about', ''),
            "image_url": json_data.get('image_url', '')
        }
    }

    response = requests.put(keycloak_user_url, headers=headers, json=user_metadata)

    if response.status_code == 204:
        return {"success": True, "message": "User updated successfully"}
    else:
        return {"success": False, "error": response.json()}, response.status_code


@users_bp.route('/user/delete', methods=['POST'])
@users_bp.input(schema.Identifier, location='json', example={"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@auth.login_required
def api_user_delete(json_data):
    """Delete an existing user from Keycloak."""

    admin_token = request.headers.get('Api-Token')
    if not admin_token:
        response = {
            'success': False,
            'help': request.url,
            'error': {'__type': 'Authorization Error', 'name': ['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}
        }
        return jsonify(response)

    config = current_app.config['settings']
    keycloak_url = config['KEYCLOAK_URL']
    user_id = json_data['id']

    keycloak_user_url = f"{keycloak_url}/admin/realms/{config['REALM_NAME']}/users/{user_id}"

    headers = {
        'Authorization': f"Bearer {admin_token}",
        'Content-Type': 'application/json'
    }

    response = requests.delete(keycloak_user_url, headers=headers)

    if response.status_code == 204:
        return {"success": True, "message": "User deleted successfully"}
    else:
        return {"success": False, "error": response.json()}, response.status_code

##################################################################
#   Up to this point (^) the endpoints have become Keycloak 
#   compatible. 
##################################################################


@users_bp.route('/user/organization', methods=['POST'])
#@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'], security=security_doc)
@auth.login_required
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