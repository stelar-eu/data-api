from flask import request, jsonify, current_app
from apiflask import APIBlueprint, HTTPTokenAuth
import requests
import utils
import json

# Auxiliary custom functions & SQL query templates for ranking
import utils

# Input schema for validating and structuring several API requests
import schema


auth = HTTPTokenAuth(scheme='ApiKey', header='Api-Token')


"""
    This .py file contains the endpoints attached to the blueprint
    responsible for all operations related to the lifecycle of
    users in the ecosystem.
"""


# The users operations blueprint for all operations related to the lifecycle of a user
# The blueprint preempts the 
users_bp = APIBlueprint('users_blueprint', __name__,tag='User Management')


# Endpoint to return configuration as JSON
@users_bp.route('/user/config', methods=['GET'])
@users_bp.doc(tags=['User Management'])
def get_config():
    return jsonify(current_app.config['settings'])


@users_bp.route('/user/create', methods=['POST'])
@users_bp.input(schema.NewUser, location='json', example={"name":"test_user5", "email":"test5@example.com","password":"test_pass5", "fullname":"Jane Doe", "about":"Testing the CKAN API for creating another new user", "image_url":"https://commons.wikimedia.org/wiki/File:Example.jpg"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
@users_bp.auth_required(auth)
def api_user_create(json_data):
    """Create a new user in CKAN. Requires admin role in CKAN to create new users.

    Args:
        data: A JSON with user metadata.

    Returns:
        A JSON with the response to this request.
    """

    #EXAMPLE: curl -X POST --header 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX'  http://127.0.0.1:9055/api/v1/catalog/user/create -d '{"name":"test_user5", "email":"test5@example.com","password":"test_pass5", "fullname":"Jane Doe", "about":"Testing the CKAN API for creating another new user", "image_url":"https://upload.wikimedia.org/wikipedia/en/f/fc/Thanasis_Veggos.jpg"}'
    
    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        user_metadata = json.loads(request.data.decode("utf-8"))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No specifications provided to create a new user in the Data Catalog. Please specify at least a username, a password and email.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(config['CKAN_API']+'user_create', json=user_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()



@users_bp.route('/user/update', methods=['POST'])
@users_bp.input(schema.ChangedUser, location='json', example={"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "about" : "Testing the CKAN API for patching information about an existing user", "image_url":"https://commons.wikimedia.org/wiki/File:JPEG_example_flower.jpg"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
@users_bp.auth_required(auth)
def api_user_update(json_data):
    """Update (patch) information an existing user in CKAN. Requires admin role in CKAN for such updates.

    Args:
        data: A JSON specifying changes in user's metadata.

    Returns:
        A JSON with the response to this request.
    """

    #EXAMPLE: curl -X POST --header 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/catalog/user/update -d '{"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "about" : "Testing the CKAN API for patching information about an existing user"}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        user_metadata = json.loads(request.data.decode("utf-8"))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No specifications provided for updating an existing user in the Data Catalog. Please specify the identifier of the user and values for the properties you wish to update.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(config['CKAN_API']+'user_patch', json=user_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@users_bp.route('/user/delete', methods=['POST'])
@users_bp.input(schema.Identifier, location='json', example={"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
@users_bp.auth_required(auth)
def api_user_delete(json_data):
    """Delete an existing user from CKAN. Requires admin role in CKAN for performing deletions.

    Args:
        data: A JSON with user's id or username.

    Returns:
        A JSON with the response to this request.
    """

    #EXAMPLE: curl -X POST --header 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX'  http://127.0.0.1:9055/api/v1/catalog/user/delete -d '{"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6"}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        user_metadata = json.loads(request.data.decode("utf-8"))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No specifications provided for deleting an existing user in the Data Catalog. Please specify the identifier of this user.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(config['CKAN_API']+'user_delete', json=user_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@users_bp.route('/user/role/assign', methods=['POST'])
@users_bp.input(schema.UserRole, location='json', example={"id": "athenarc", "username":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "role":"editor"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
@users_bp.auth_required(auth)
def api_user_role(json_data):
    """Assign a role for an existing user as a member of an organization in CKAN. Requires admin role in CKAN for such assignments.

    Args:
        data: A JSON with user metadata. Must include the id of the organization, the user id, and the role to be assigned (member/editor/admin).

    Returns:
        A JSON with the response to this request.
    """

    #EXAMPLE: curl -X POST --header 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/catalog/user/role/assign -d '{"id": "athenarc", "username":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "role":"editor"}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        member_metadata = json.loads(request.data.decode("utf-8"))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No specifications provided to assign role for a user in the Data Catalog. Please specify the id of the organization, the user id, and the role to be assigned (member/editor/admin).']}}
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(config['CKAN_API']+'organization_member_create', json=member_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@users_bp.route('/user/token/create', methods=['POST'])
@users_bp.input(schema.NewToken, location='json', example={"user": "test_user5", "name": "test5_API_token"})
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
@users_bp.auth_required(auth)
def api_token_create(json_data):
    """Generate an API token for an existing user in CKAN. Requires authentication of the user in CKAN to generate a token.

    Args:
        data: A JSON with user identifier (or name) and the name to be given to the new token.

    Returns:
        A JSON with the response to this request, containing the generated API token.
    """

    #EXAMPLE: curl -X POST --header 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/catalog/user/token/create -d '{"user": "test_user5", "name": "test5_API_token"}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        token_metadata = json.loads(request.data.decode("utf-8"))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No specifications provided to create API token for an existing user in the Data Catalog. Please specify the username and a name for the new API token.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(config['CKAN_API']+'api_token_create', json=token_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()



@users_bp.route('/user/organization', methods=['GET'])
@users_bp.input(schema.Identifier, location='query', example="778bc28b-627c-472f-9d78-4d3617733218")
#@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
def api_user_organization(query_data):
    """Finds the organization(s) where the given user is assigned a role (admin/editor/member) in CKAN.

    Args:
        id (string): The id of the user in CKAN.

    Returns:
        The organization(s) where this user has been assigned a role.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/catalog/user/organization?id=778bc28b-627c-472f-9d78-4d3617733218

    config = current_app.config['settings']

    if request.method == 'GET' and 'id' in query_data:
        # Check if a user ID (name) was provided as argument
        id = query_data['id']
        # Make a GET request to the CKAN API with the parameters
        # IMPORTANT! CKAN requires NO authentication for GET requests
        response = requests.get(config['CKAN_API']+'organization_list_for_user?id='+id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  
        return response.json()
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the user.']}}
        return jsonify(response)


@users_bp.route('/user/organization', methods=['POST'])
#@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
@users_bp.auth_required(auth)
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
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
            # Make a POST request to the CKAN API using this API token for user identification
            response = requests.post(config['CKAN_API']+'organization_list_for_user', headers=resource_headers)  #auth=HTTPBasicAuth(config.username, config.password))  
            return response.json()
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the user.']}}
        return jsonify(response)








########################################################
# TO-DO: THIS PATH WONT WORK DUE TO THE PREEMPTION OF
#        THE PREFIX '/api/v1/catalog' FOR ALL ENDPOINTS
#        IN THIS BLUEPRINT. DECIDE HOW TO SOLVE THIS.
########################################################
@users_bp.route('/api/v1/user', methods=['GET'])
@users_bp.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@users_bp.output(schema.ResponseOK, status_code=200)
@users_bp.doc(tags=['User Management'])
def api_user_id(query_data):
    """Get all metadata publicly available for the user (excluding password and tokens).

    Args:
        id: The unique identifier or account name of the user as listed in CKAN.

    Returns:
        A JSON with metadata maintained in CKAN for the specified user.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/user?id=6dc36257-abb6-45b5-b3bb-5f94160fc2ee

    config = current_app.config['settings']

    # Check if an ID (name) for a user was provided as argument
    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id or account name of the requested user.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'user_show?id='+id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    return response.json()