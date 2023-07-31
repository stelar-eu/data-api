import flask
import requests
import json
import re
import sys
import psycopg2
import yaml
import mlflow as mfl

from flask import request, jsonify, current_app
from apiflask import APIFlask, HTTPTokenAuth

# Auxiliary custom functions
import functions

# Input schemata for validating several API requests
import schema

# Create an instance of this API; by default, its OpenAPI-compliant specification will be generated under folder /specs
app = APIFlask(__name__, spec_path='/specs', docs_path ='/docs')



################################## AUTHENTICATION ########################################

# Authenticate API requests using tokens (issued by CKAN)
auth = HTTPTokenAuth(scheme='ApiKey', header='Api-Token')


@auth.verify_token
def api_verify_token(token):
    """Register a callback to verify that the token is valid for POST requests that require authentication. GET requests do not require authentication in CKAN.

    Args:
        token: A token issued by the user through the CKAN GUI.

    Returns:
        A boolean: True, if the token is valid; False, otherwise.
    """

    config = current_app.config['settings']

    user_headers = { 'X-CKAN-API-Key' : token }

    # Make a POST request to the CKAN API with the token to check access to user information
    response = requests.post(config['CKAN_API']+'user_show', headers=user_headers) 

    if response.json()['success']:
        return True
    else:
        return True


################################## DATABASE CONNECTOR ########################################

def execSql(sql):
    """Opens a connection to a PostgreSQL database and executes the given SQL command.

    Args:
        sql (String): The SQL command to be executed in the database.

    Returns:
    """

    config = current_app.config['settings']

    conn = psycopg2.connect(dbname=config['dbname'], user=config['dbuser'], password=config['dbpass'], host=config['dbhost'], port=config['dbport']) #, sslmode=config['sslmode'])
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()



################################## ENTRY POINT ########################################


@app.route('/', methods=['GET'])
@app.output(schema.ResponseOK, status_code=200)
@app.doc(responses=[404], tags=['KLMS Data API'])   # ,summary='Entry point to the API'
def home():
    """Entry point to the Data API of Knowledge Lake Management System.

    Args:

    Returns:
        A JSON with basic information about the API.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/ 
    
    response = {'help': request.base_url, 'success': True, 'result': {'message':'Prototype Data API for managing resources in STELAR Knowledge Lake Management System.', 'OpenAPI specifications':request.base_url+'specs', 'Swagger UI':request.base_url+'docs'}}

    return jsonify(response)

#    return '''<h1>STELAR Knowledge Lake Management System</h1><p>Prototype Data API for managing KLMS resources.</p><p>API specification is available <a href='/specs'>here</a>.<p>Interactive API documentation (Swagger UI) is available <a href='/docs'>here</a>.</p>'''



################################## CATALOG USER MANAGEMENT ########################################


@app.route('/api/v1/catalog/user/create', methods=['POST'])
@app.input(schema.NewUser, location='json', example={"name":"test_user5", "email":"test5@example.com","password":"test_pass5", "fullname":"Jane Doe", "about":"Testing the CKAN API for creating another new user", "image_url":"https://commons.wikimedia.org/wiki/File:Example.jpg"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User management'])
@app.auth_required(auth)
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
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
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


@app.route('/api/v1/catalog/user/update', methods=['POST'])
@app.input(schema.ChangedUser, location='json', example={"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "about" : "Testing the CKAN API for patching information about an existing user", "image_url":"https://commons.wikimedia.org/wiki/File:JPEG_example_flower.jpg"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User management'])
@app.auth_required(auth)
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
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
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


@app.route('/api/v1/catalog/user/delete', methods=['POST'])
@app.input(schema.Identifier, location='json', example={"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User management'])
@app.auth_required(auth)
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
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
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


@app.route('/api/v1/catalog/user/role/assign', methods=['POST'])
@app.input(schema.UserRole, location='json', example={"id": "athenarc", "username":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "role":"editor"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User management'])
@app.auth_required(auth)
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
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
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


@app.route('/api/v1/catalog/user/token/create', methods=['POST'])
@app.input(schema.NewToken, location='json', example={"user": "test_user5", "name": "test5_API_token"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User management'])
@app.auth_required(auth)
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
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
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



@app.route('/api/v1/catalog/user/organization', methods=['GET'])
@app.input(schema.Identifier, location='query', example="778bc28b-627c-472f-9d78-4d3617733218")
#@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User management'])
def api_user_organization(id):
    """Finds the organization(s) where the given user is assigned a role (admin/editor/member) in CKAN.

    Args:
        id (string): The id of the user in CKAN.

    Returns:
        The organization(s) where this user has been assigned a role.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/catalog/user/organization?id=778bc28b-627c-472f-9d78-4d3617733218

    config = current_app.config['settings']

    if request.method == 'GET' and 'id' in request.args:
        # Check if a user ID (name) was provided in the request
        id = request.args['id']
        # Make a GET request to the CKAN API with the parameters
        # IMPORTANT! CKAN requires NO authentication for GET requests
        response = requests.get(config['CKAN_API']+'organization_list_for_user?id='+id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  
        return response.json()
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the user.']}}
        return jsonify(response)


@app.route('/api/v1/catalog/user/organization', methods=['POST'])
#@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User management'])
@app.auth_required(auth)
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
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
            # Make a POST request to the CKAN API using this API token for user identification
            response = requests.post(config['CKAN_API']+'organization_list_for_user', headers=resource_headers)  #auth=HTTPBasicAuth(config.username, config.password))  
            return response.json()
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the user.']}}
        return jsonify(response)


################################## SEARCH OPERATIONS ########################################

@app.route('/api/v1/catalog/tags', methods=['GET'])
#@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_tags():
    """List all tags associated with datasets (packages) maintained in CKAN.

    Args:

    Returns:
        A JSON with all available tags.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/catalog/tags

    config = current_app.config['settings']

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'tag_list') #, headers=config.package_headers) # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()



@app.route('/api/v1/catalog/vocabularies', methods=['GET'])
#@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_vocabularies():
    """List all vocabularies employed in metadata for datasets (packages) maintained in CKAN.

    Args:

    Returns:
        A JSON with all available vocabularies.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/catalog/vocabularies

    config = current_app.config['settings']

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'vocabulary_list') #, headers=config.package_headers) # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()



@app.route('/api/v1/catalog/all', methods=['GET'])
#@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_datasets():
    """List the identifiers of all datasets (packages) maintained in CKAN that are accessible by the user.

    Args:

    Returns:
        A JSON with the names of all datasets accessible by the user.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/catalog/all

    config = current_app.config['settings']

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'package_list') #, headers=config.package_headers) # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()



@app.route('/api/v1/catalog', methods=['GET'])
@app.input(schema.Identifier, location='query', example="cf0c3c59-fc41-48c9-a529-6b9feff42991")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_dataset_id(id):
    """Get all metadata available for a dataset (i.e., CKAN package) that is accessible by the user.

    Args:
        id: The unique identifier of the dataset as listed in CKAN.

    Returns:
        A JSON with all metadata maintained in CKAN for the specified dataset.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/catalog?id=lakes-of-greece
    #     OR: curl -X GET http://127.0.0.1:9055/api/v1/catalog?id=cf0c3c59-fc41-48c9-a529-6b9feff42991

    config = current_app.config['settings']

    # Check if an ID (name) for a dataset was provided in the request
    if 'id' in request.args:
        id = request.args['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the requested dataset.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'package_show?id='+id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    return response.json()



@app.route('/api/v1/catalog/search', methods=['POST'])
@app.input(schema.Query, location='json', example={"q":{"Topic":"POI", "INSPIRE theme":"Location", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
@app.auth_required(auth)
def api_catalog_search(q):
    """Submit a search request to the Data Catalog.

    Args:
        q: A JSON with filtering criteria for searching in the Data Catalog. Keys should match properties specified in the STELAR Ontology.

    Returns:
        A JSON with all metadata available in the Catalog for each dataset qualifying to the filtering criteria and accessible by the user.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:9055/api/v1/catalog/search -d '{"q":{"Topic":"POI", "INSPIRE theme":"Location", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}}'

    config = current_app.config['settings']

    if request.data:
        filter = request.data
        specs = json.loads(filter.decode("utf-8"))
        if 'q' in specs:
            q = functions.format_CKAN_filter(specs['q'])
            print(q)
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Incorrect specifications','name':['Incorrect or no filters provided to search in the Data Catalog. Please specify at least one filtering criterion in a dictionary.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No filters provided to search in the Data Catalog. Please specify at least one filtering criterion in a dictionary.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'package_search'+q) #, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@app.route('/api/v1/dataset/search', methods=['GET'])
@app.input(schema.ComplexFilter, location='query', example="q=Lakes&ext_bbox=20,35,30,42")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_package_search(q):
    """Submit a search request against CKAN packages (datasets).

    Args:
        q: Filtering criteria for searching in CKAN. Search may concern either metadata values (?q=) or facets (?fc=) or spatial extents (?ext_bbox=) only. One argument (?q= or ?fq= or ?ext_bbox) must be specified per request. Syntax must follow <a href="https://docs.ckan.org/en/latest/api/#ckan.logic.action.get.package_search">SOLR specifications for filtering</a>. 

    Returns:
        A JSON with all metadata available in CKAN for each dataset qualifying to the filtering criteria and accessible by the user.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/dataset/search?q=Topic:*POI*
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/dataset/search?fq=organization:athenarc
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/dataset/search?q=Lakes&ext_bbox=20,35,30,42

    config = current_app.config['settings']

    # Multiple criteria can be correctly passed with argument ?q 
    if 'q' in request.args:      	# Search on various metadata
        q = '?q=' + request.args['q']
    elif 'ext_bbox' in request.args:  	# Search on spatial extent only
        q = '?ext_bbox=' + request.args['ext_bbox']
    elif 'fq' in request.args:   	# Search on facets only
        q = '?fq=' + request.args['fq']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No filtering criteria provided to search for datasets in the Catalog. Please specify at least one filter as argument.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'package_search'+q) #, headers=config.package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@app.route('/api/v1/resource', methods=['GET'])
@app.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_resource_id(id):
    """Get all metadata available for a resource that is accessible by the user.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with all metadata maintained in CKAN for the specified resource.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/resource?id=6dc36257-abb6-45b5-b3bb-5f94160fc2ee

    config = current_app.config['settings']

    # Check if an ID (name) for a resource was provided in the request
    if 'id' in request.args:
        id = request.args['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the requested resource.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_show?id='+id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    return response.json()



@app.route('/api/v1/resource/search', methods=['GET'])
@app.input(schema.Filter, location='query', example="q=format:JSON")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_resource_search(q):
    """Submit a request to search among the CKAN resources accessible by the user.

    Args:
        q: Filtering criteria for searching in CKAN. Syntax must follow SOLR specifications for filtering. https://docs.ckan.org/en/latest/api/#ckan.logic.action.get.resource_search

    Returns:
        A JSON with all metadata available in CKAN for each dataset qualifying to the filtering criteria and accessible by the user.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/resource/search?q=format:JSON

    config = current_app.config['settings']

    if 'q' in request.args:
        q = request.args['q']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No filtering criteria provided to search for resources in the Catalog. Please specify at least one filter as argument.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_search?query='+q) #, headers=config.package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@app.route('/api/v1/graph/search', methods=['POST'])
@app.input(schema.Filter, location='json', example={"q": "PREFIX dct: <http://purl.org/dc/terms/> SELECT ?uri ?title ?publisher WHERE { ?uri dct:title ?title . ?uri dct:publisher ?publisher . } LIMIT 5"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
@app.auth_required(auth)
def api_sparql(q):
    """Submit a search request to the SPARQL endpoint.

    Args:
        q: A JSON with the SELECT query in SPARQL for searching the Knowledge Graph via Ontop. Syntax must follow SPARQL specifications for Ontop.

    Returns:
        A JSON with all RDF triples qualifying to the search criteria.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/text' http://127.0.0.1:9055/api/v1/graph/search -d '{"q":"PREFIX dct: <http://purl.org/dc/terms/> SELECT ?uri ?title ?publisher WHERE { ?uri dct:title ?title . ?uri dct:publisher ?publisher . } LIMIT 5"}' 

    config = current_app.config['settings']

    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        if 'q' in specs:
            sparql = specs['q']
            print(sparql)
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Incorrect specifications','name':['Incorrect or no filters provided to search in the Data Catalog. Please specify a valid SPARQL query command.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No SPARQL query provided to search in the Knowledge Graph. Please specify a valid SPARQL query command.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}

    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return response.json()


############################### PUBLISHING OPERATIONS ############################

@app.route('/api/v1/catalog/publish', methods=['POST'])
@app.input(schema.Dataset, location='json', example={"basic_metadata":{"title": "Test KLMS API 46", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Bavaria"}]},"custom_metadata":{"INSPIRE theme":"Imagery","Topic": "Landuse", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]},"startDate":"2023-01-31T11:33:54.132Z", "endDate":"2023-01-31T11:35:48.593Z"},"profile_metadata":{"url":"https://raw.githubusercontent.com/stelar-eu/data-profiler/main/examples/output/timeseries_profile.json", "name": "Time series profile in JSON", "description": "This is the profile of a time series in JSON format", "format": "JSON", "resource_tags": [{"key": "Resource type", "value": "Profile"}, {"key": "Process", "value": "Computed with STELAR Profiler"}]}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_dataset_publish(json_data):
    """Publish a new dataset in the Catalog.

    Registers metadata about a dataset and its associated resources (e.g., a data profile) in CKAN. The actual dataset will not be stored in the Catalog. The user will become the publisher of this dataset.

    Args:
        data: A JSON with metadata information provided by the publisher about the new dataset.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/catalog/publish -d '{"basic_metadata":{"title": "Test KLMS API 46", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Bavaria"}]},"custom_metadata":{"INSPIRE theme":"Imagery","Topic": "Landuse", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]},"startDate":"2023-01-31T11:33:54.132Z", "endDate":"2023-01-31T11:35:48.593Z"},"profile_metadata":{"file":"/data/examples/timeseries_profile.json", "name": "Time series profile in JSON", "description": "This is the profile of a time series in JSON format", "format": "JSON", "resource_tags": [{"key": "Resource type", "value": "Profile"}, {"key": "Process", "value": "Computed with STELAR Profiler"}]}}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        metadata=request.data
        specs = json.loads(metadata.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing in the Catalog. Please specify metadata for the dataset you wish to publish.']}}
        return jsonify(response)

    arr_resp = []

    # Register the new dataset with the basic metadata
    if specs.get('basic_metadata') != None:
        basic_metadata = specs['basic_metadata']
        # Also create the name of the new CKAN package from its title (assuming that this is unique)
        basic_metadata['name'] = re.sub(r'[\W_]+','_', basic_metadata['title']).lower()
        # Internal call to find the organization where the user belongs to (derived from API token)
        resp_org = api_user_editor()
        if resp_org['success']:
            org_json = resp_org['result']
            if len(org_json) > 0:  
                for item in org_json: 
                    if item['type'] == 'organization' and item['state'] == 'active' and item['capacity'] in ('admin','editor'):
                        basic_metadata['owner_org'] = org_json[0]['name']  # CAUTION! Taking the first organization where this user is editor
                        break

        # Make a POST request to the CKAN API with the basic metadata
        resp_basic = requests.post(config['CKAN_API']+'package_create', json=basic_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
        arr_resp.append(resp_basic.json())
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No basic metadata provided for publishing in the Catalog. Please specify some basic metadata (title, description, tags, etc.) for the dataset you wish to publish.']}}
        return jsonify(response)

    # Get the id of the newly created package in order to associate any remaining information (extras, resources)
    if resp_basic.status_code == 200:
        package_id = resp_basic.json()['result']['id']
#        print("package_id: ", package_id)
    else:
        return resp_basic.json()  # Failed to publish the dataset with the basic metadata provided; CKAN response will specify the reason

    # Handle custom metadata as extras
    # Also store values in custom tables for profiles in KLMS schema in the database
    if specs.get('custom_metadata') != None:
        custom_metadata = specs['custom_metadata']
        # Convert this metadata to a JSON array with {"key":"...", "value":"..."} pairs as required to be stored as extras in CKAN
        extra_metadata = {}
        extra_metadata['id'] = package_id   # Must specify the id of the newly created package
        extra_metadata['extras'] = functions.handle_extras(custom_metadata)
        # Make a POST request to the CKAN API to patch the newly created package with the extra metadata
        resp_extras = requests.post(config['CKAN_API']+'package_patch', json=extra_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
        arr_resp.append(resp_extras.json())
    else:
        resp_extras = {'success':True, 'help': request.url, 'warning':{'__type':'No specifications','name':['Warning: No custom metadata provided for publishing this dataset in the Catalog. You may still apply a CKAN package_patch request to include such extra metadata to this dataset in the future.']}}
        arr_resp.append(resp_extras)

    # Handle profile metadata as a resource    
    if specs.get('profile_metadata') != None:
        resource_metadata = specs['profile_metadata']
        resource_metadata['package_id'] = package_id   # Must specify the id of the newly created package
        if resource_metadata.get('file') != None:
            # Make a POST request to the CKAN API to upload the file from the specified path
            with open(resource_metadata['file'], 'rb') as f:
#                print('Resource file found!')
                resp_resource = requests.post(config['CKAN_API']+'resource_create', data=resource_metadata, headers=resource_headers, files=[('upload', f)])
                arr_resp.append(resp_resource.json())
                # Also ingest profile information into PostgreSQL according to KLMS schema
                resource_id = resp_resource.json()['result']['id']
#                print("RESOURCE ID: ", resource_id)
                f1 = open(resource_metadata['file'])
                profile = json.load(f1)
                # Distinguish handling according to Profile type
                sql_commands = functions.extractProfileProperties(resource_id, profile)
                for sql in sql_commands:
                    execSql(sql)
        elif resource_metadata.get('url') != None:
            # Make a POST request to the CKAN API to link the file from the specified URL
            resp_resource = requests.post(config['CKAN_API']+'resource_create', data=resource_metadata, headers=resource_headers)
            arr_resp.append(resp_resource.json())
        else:
            resp_resource = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No profile metadata were associated with this dataset in the Catalog. Please provide a path or a publicly accessible URL where this file is available.']}}
            arr_resp.append(resp_resource)
    else:
        resp_resource = {'success':True, 'help': request.url, 'warning':{'__type':'No specifications','name':['Warning: No profile metadata will be associated with this dataset in the Catalog. You may still apply a resource/upload request to attach such profiling information to this dataset in the future.']}}
        arr_resp.append(resp_resource)

    # Examine collected responses to compose the overall response
    success = True
    result = []
    for idx, resp in enumerate(arr_resp):
        success &= resp['success']
        result.append(resp)

    response = {'success':success, 'help': request.url, 'result':result}        
    return jsonify(response)



@app.route('/api/v1/dataset/register', methods=['POST'])
@app.input(schema.Package, location='json', example={"package_metadata": {"title": "Test KLMS API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Berlin"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}],"name": "test_klms_api_1","private": "false","version": "0.3","owner_org": "athenarc"}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_dataset_register(json_data):
    """Register a new dataset in CKAN. The user will become the publisher of this dataset.

    Args:
        data: A JSON with basic metadata information provided by the publisher about the new dataset.

    Returns:
        A JSON with the CKAN response to the registration request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/dataset/register -d '{"package_metadata": {"title": "Test KLMS API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Berlin"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}],"name": "test_klms_api_1","private": "false","version": "0.3","owner_org": "athenarc"}}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        metadata = json.loads(request.data.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
        if 'package_metadata' in metadata:
            package_metadata = metadata['package_metadata']
        else:
            response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No metadata provided for publishing in the Catalog. Please specify at least some basic metadata (title, notes, tags, etc.) for the dataset you wish to publish.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing in the Catalog. Please specify at least some basic metadata (title, notes, tags, etc.) for the dataset you wish to publish.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(config['CKAN_API']+'package_create', json=package_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@app.route('/api/v1/dataset/patch', methods=['POST'])
@app.input(schema.Package, location='json', example={"package_metadata": {"id": "test_klms_api_1", "tags": [{"name": "Patch"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}] }})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_dataset_patch(json_data):
    """Patch more metadata to an existing dataset in CKAN. The user will become the publisher of this dataset.

    Args:
        data: A JSON with additional metadata information provided by the publisher about the new dataset.

    Returns:
        A JSON with the CKAN response to the patch request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/dataset/patch -d '{"package_metadata": {"id": "test_klms_api_1", "tags": [{"name": "Patch"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}] }}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        metadata = json.loads(request.data.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
        if 'package_metadata' in metadata:
            package_metadata = metadata['package_metadata']
        else:
            response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No metadata provided for updating this dataset in the Catalog. Please specify metadata for the dataset you wish to patch.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for updating this dataset in the Catalog. Please specify metadata for the dataset you wish to patch.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API to patch the newly created package with the extra metadata
    response = requests.post(config['CKAN_API']+'package_patch', json=package_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
    return response.json()



@app.route('/api/v1/resource/upload', methods=['POST'])
@app.input(schema.Resource, location='json', example={"resource_metadata": {"package_id": "test_klms_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": [{"key": "Resource type", "value": "Profile"}, {"key": "Process", "value": "Computed with STELAR Profiler"}]}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_resource_upload(json_data):
    """Upload a resource to an existing dataset in CKAN. The user will become the publisher of this resource.

    Args:
        data: A JSON with all metadata information provided by the publisher about the new resource.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/resource/upload -d '{"resource_metadata": {"package_id": "test_klms_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": [{"key": "Resource type", "value": "Profile"}, {"key": "Process", "value": "Computed with STELAR Profiler"}]}}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        metadata = json.loads(request.data.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
        if 'resource_metadata' in metadata:
            resource_metadata = metadata['resource_metadata']
        else:
            response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No metadata provided for updating this resource in the Catalog. Please specify metadata for the resource you wish to upload.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing this resource in the Catalog. Please specify metadata for the resource you wish to upload.']}}
        return jsonify(response)

    # Get file path to access the resource, but remove it from the JSON
    file = resource_metadata['file']
    resource_metadata.pop('file', None)    # will not crash if this JSON has no key 'file'

    # Make a POST request to the CKAN API with the parameters
    with open(file, 'rb') as f:
#        print('Resource file found!')
        response = requests.post(config['CKAN_API']+'resource_create', data=resource_metadata, headers=resource_headers, files=[('upload', f)])
        return response.json()

    response = {'success':False, 'help': request.url, 'error':{'__type':'Not found','name':['The specified file resource is not found or could not be accessed.']}}
    return jsonify(response)



@app.route('/api/v1/resource/link', methods=['POST'])
@app.input(schema.Resource, location='json', example={"resource_metadata": {"package_id": "test_klms_api_1", "url":"https://data.smartdublin.ie/dataset/09870e46-26a3-4dc2-b632-4d1fba5092f9/resource/40a718a8-cb99-468d-962b-af4fed4b0def/download/bleeperbike_map.geojson", "name": "Test GeoJSON resource", "description": "This is the test resource in GeoJSON format", "format": "GeoJSON", "resource_tags": [{"key": "Resource type", "value": "Link to external resource"}, {"key": "Process", "value": "Found in the Web"}]}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_resource_link(json_data):
    """Associate a resource (with its URL) to an existing dataset in CKAN. The user will become the publisher of this resource.

    Args:
        data: A JSON with all metadata information provided by the publisher about the new resource.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/resource/link -d '{"resource_metadata": {"package_id": "test_klms_api_1", "url":"https://data.smartdublin.ie/dataset/09870e46-26a3-4dc2-b632-4d1fba5092f9/resource/40a718a8-cb99-468d-962b-af4fed4b0def/download/bleeperbike_map.geojson", "name": "Test GeoJSON resource", "description": "This is the test resource in GeoJSON format", "format": "GeoJSON", "resource_tags": [{"key": "Resource type", "value": "Link to external resource"}, {"key": "Process", "value": "Found in the Web"}]}}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        metadata = json.loads(request.data.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
        if 'resource_metadata' in metadata:
            resource_metadata = metadata['resource_metadata']
        else:
            response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No metadata provided for publishing this resource in the Catalog. Please specify metadata for the resource you wish to publish.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing this resource in the Catalog. Please specify metadata for the resource you wish to publish.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(config['CKAN_API']+'resource_create', data=resource_metadata, headers=resource_headers)
    return response.json()



@app.route('/api/v1/artifact/publish', methods=['POST'])
@app.input(schema.Artifact, location='json', example={"package_metadata":{"package_id": "test_klms_api_46"},"artifact_metadata":{"url":"s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv", "run_uuid":"d63a2b507bf6b6eadcb2c8de378c0370", "name": "Results of deduplication task", "description": "This is the test artifact uploaded to minio S3 in CSV format", "format": "CSV", "resource_tags": ["Artifact","MLFlow"]}})
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_artifact_publish(json_data):
    """Publish an artifact created by a workflow execution.

    If a package id is provided, associate the artifact (with its URL) to this package in CKAN. Otherwise, create a new package in CKAN to make this association. The user will become the publisher of this resource.

    Args:
        data: A JSON with all metadata information provided by the publisher about the new artifact.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/artifact/publish -d '{"package_metadata":{"title":"Results of Airflow dag mycalc", "tags":[{"name": "Artifact"}, {"name": "Workflow"}], "extras":[{"key":"dag_id", "value":"mycalc"}, {"key":"run_id", "value":"scheduled__2023-07-11T00:00:00+00:00"}], "notes": "My calculation using AirFlow"},"artifact_metadata":{"url":"s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv", "run_uuid":"d63a2b507bf6b6eadcb2c8de378c0370", "name": "Results of deduplication task", "description": "This is the test artifact uploaded to minio S3 in CSV format", "format": "CSV", "resource_tags": ["Artifact","MLFlow"]}}'
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'API_TOKEN: XXXXXXXXX' http://127.0.0.1:9055/api/v1/artifact/publish -d '{"package_metadata":{"package_id": "test_klms_api_46"},"artifact_metadata":{"url":"s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv", "run_uuid":"d63a2b507bf6b6eadcb2c8de378c0370", "name": "Results of deduplication task", "description": "This is the test artifact uploaded to minio S3 in CSV format", "format": "CSV", "resource_tags": ["Artifact","MLFlow"]}}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        metadata = request.data
        specs = json.loads(metadata.decode("utf-8"))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing this artifact in the Catalog. Please specify metadata for the artifact you wish to publish.']}}
        return jsonify(response)

    if specs.get('artifact_metadata') != None:
        artifact_metadata = specs['artifact_metadata']
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing this artifact in the Catalog. Please specify metadata for the artifact you wish to publish.']}}
        return jsonify(response)

    # Check if a new package needs to be created with the basic metadata
    if specs.get('package_metadata') != None:
        package_metadata = specs['package_metadata']
        if package_metadata.get('package_id') != None:
            # Make a POST request to the CKAN API to associate this artifact to an existing dataset (CKAN package)
            artifact_metadata['package_id'] = package_metadata['package_id']
            resp_resource = requests.post(config['CKAN_API']+'resource_create', data=artifact_metadata, headers=resource_headers)
            result = {'package_id': artifact_metadata['package_id']}
            if resp_resource.status_code == 200:
                resource_id = resp_resource.json()['result']['id']
                result['resource_id'] = resource_id
#                print("resource_id: ", resource_id)
            else:
                return resp_resource.json()
            response = {'success':True, 'help': request.url, 'result':result} 
            return jsonify(response)
        else:
        # Register a new package with some basic metadata
            arr_resp = []
            # Also create the name of the new CKAN package from its title (assuming that this is unique)
            package_metadata['name'] = re.sub(r'[\W_]+','_',package_metadata['title']).lower()
            # Internal call to find the organization where the user belongs to (derived from API token)
            resp_org = api_user_editor()
            if resp_org['success']:
                org_json = resp_org['result']
                if len(org_json) > 0:  
                    for item in org_json: 
                        if item['type'] == 'organization' and item['state'] == 'active' and item['capacity'] in ('admin','editor'):
                            package_metadata['owner_org'] = org_json[0]['name']  # CAUTION! Taking the first organization where this user is editor
                            break

            # Make a POST request to the CKAN API with the basic metadata
            resp_basic = requests.post(config['CKAN_API']+'package_create', json=package_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
            arr_resp.append(resp_basic.json())

            result = {}
            # Get the id of the newly created package in order to associate the artifact as a resource
            if resp_basic.status_code == 200:
                package_id = resp_basic.json()['result']['id']
                result['package_id'] = package_id
#                print("package_id: ", package_id)
            else:
                return resp_basic.json()

            artifact_metadata['package_id'] = package_id
            # Make a POST request to the CKAN API to link the artifact as a resource
            resp_resource = requests.post(config['CKAN_API']+'resource_create', data=artifact_metadata, headers=resource_headers)
            arr_resp.append(resp_resource.json())

            if resp_resource.status_code == 200:
                resource_id = resp_resource.json()['result']['id']
                result['resource_id'] = resource_id
#                print("resource_id: ", resource_id)
            else:
                return resp_resource.json()

            # Examine collected responses to compose the overall response
            success = True   
            for idx, resp in enumerate(arr_resp):
                success &= resp['success']
#                result.append(resp)

            response = {'success':success, 'help': request.url, 'result':result}     
            return jsonify(response)



@app.route('/api/v1/artifact', methods=['GET'])
@app.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_artifact_id(query_data):
    """Get the file path of an artifact. 

    Provides the path to the file (URL, S3 bucker or local file) where an artifact (stored as a resource) is available. User may need credentials to access this file.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with the file path for the specified resource as maintained in CKAN.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/artifact?id=6dc36257-abb6-45b5-b3bb-5f94160fc2ee

    config = current_app.config['settings']

    # Check if an ID (name) for a resource was provided in the request
    if 'id' in request.args:
        id = request.args['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the unique id of the requested artifact.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_show?id='+id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    # Get the path of this artifact 
    if response.status_code == 200:
        path = response.json()['result']['url']
        response = {'success':True, 'help': request.url, 'result':{'path':path}}
        return jsonify(response)
    else:
        return response.json()




@app.route('/api/v1/dataset/delete', methods=['POST'])
@app.input(schema.Identifier, location='json', example={"id":"test_klms_api_46"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Catalog Management'])
@app.auth_required(auth)
def api_dataset_purge(json_data):
    """Delete an existing dataset from the Catalog.

    Completely removes the metadata and any associated resources (e.g., profiles) of an existing dataset from the CKAN database. The user must have admin role in order to delete datasets.

    Args:
        data: A JSON with the id of an existing dataset.

    Returns:
        A JSON with the CKAN response to the delete request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/dataset/delete -d '{"id": "test_klms_api_1"}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        metadata=request.data
        delete_metadata = json.loads(metadata.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for deleting a dataset from the Catalog. Please specify the id of the dataset you wish to permanently delete.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API to purge an existing dataset
    response = requests.post(config['CKAN_API']+'dataset_purge', json=delete_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
    return response.json()


@app.route('/api/v1/dataset/unpublish', methods=['POST'])
@app.input(schema.Identifier, location='json', example={"id":"test_klms_api_46"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Catalog Management'])
@app.auth_required(auth)
def api_dataset_unpublish(json_data):
    """Unpublish an existing dataset from the Catalog.

    Marks an existing dataset as inactive in CKAN. The package remains in the CKAN database with "deleted" status, but does not appear in the GUI and is not included in search results.

    Args:
        data: A JSON with the id of an existing dataset.

    Returns:
        A JSON with the CKAN response to the unpublish request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/dataset/unpublish -d '{"id": "test_klms_api_46"}'

    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = functions.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    if request.data:
        metadata=request.data
        unpublish_metadata = json.loads(metadata.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for unpublishing a dataset from the Catalog. Please specify the id of the dataset you wish to unpublish.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API to unpublish an existing package
    response = requests.post(config['CKAN_API']+'package_delete', json=unpublish_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
    return response.json()



@app.route('/api/v1/track', methods=['POST'])
@app.input(schema.Tracking, location='json', example={'params': {'experiment': 'Downloading_GDELT_Demo_download', 'title': 'Workflow for Downloading_GDELT_Demo 20230713', 'path': 's3://gdelt-bucket/download_gdelt_20230713.csv', 'log': {'metrics': {'downloaded_files': 5, 'filtered_no_articles': 20, 'original_files': 5, 'original_no_articles': 9588, 'time': 20.359771966934204}, 'parameters': {'date': '20230713'}}}, 'settings': {'dag_id': 'Downloading_GDELT_Demo', 'run_id': 'scheduled__2023-07-13T00:00:00+00:00', 'user': 'azeakis'}} )
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_track(json_data):
    """Keep track of a workflow execution.

    Logs the parameters and metrics of a specific run in MLFlow and publishes all produced artifacts in the Catalog.

    Args:
        data: A JSON with the corresponding information to track.

    Returns:
        A JSON with the response to the track request.
    """
    
    config = current_app.config['settings']

    if request.headers:
        if request.headers.get('Api-Token') != None:
            headers = request.headers
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    args = request.json
    
    log = args['params']['log']
    input_path = args['params']['path']
    experiment = args['params']['experiment']
    package_id = args['params'].get('package_id')
    title = args['params'].get('title')
    
    dag_id = args['settings']['dag_id']
    run_id = args['settings']['run_id']
    user = args['settings']['user']
    
    mfl.set_tracking_uri(config['MLFLOW_ENDPOINT'])
    if user is not None:
        mfl.set_tag("user", user)


    exp = mfl.get_experiment_by_name(experiment)
    if exp is None:
        exp = mfl.create_experiment(experiment)
    else:
        exp = exp.experiment_id


    if mfl.active_run():
        mfl.end_run()

    with mfl.start_run(experiment_id=exp) as run:
        for key, val in log['parameters'].items():
            if key == 'input':
                val = [v['resource_id'] for v in val]
                val = ','.join(val)
            mfl.log_param(key, val)                    
        mfl.log_param('dag_id', dag_id)
        mfl.log_param('run_id', run_id)
        for key, val in log['metrics'].items():
            mfl.log_metric(key, val)
            
            
        # Inserting to CKAN
        ftype = input_path.split('/')[-1].split(".")[-1].upper()
        d = { "artifact_metadata":{
                    "url":input_path,
                    "run_uuid": run.info.run_uuid,
                    # 'host': args['settings']['urls']['minio'],
                    "name": f"Results of {experiment} task",
                    "description": f"This is the test artifact uploaded to minio S3 in {ftype} format",
                    "format": ftype,
                    "resource_tags":["Artifact","MLFlow"]
                                }
            }
        if package_id is None:
            d["package_metadata"] = {
                    "title": title,
                    "tags":[{"name":"Artifact"},{"name":"Workflow"}],
                    "extras":[{"key":"dag_id","value": dag_id},
                              {"key":"run_id","value": run_id,}],
                    "notes":"This is the test artifact uploaded to minio S3.",}

        else:
            d["package_metadata"] = {
               "package_id": package_id
            }

        host = request.host.split(':')[0]
        publish_url = f"http://{host}/api/v1/artifact/publish"
        # port = request.host.split(':')[1] if ':' in request.host else 80  # Default to port 80 if no port is specified in the request
        # publish_url = f"http://{host}:{port}/api/v1/artifact/publish"
        
        # url = args['settings']['klms_api']['endpoint_url'] + 'api/v1/artifact/publish'
        response = requests.post(publish_url, json=d, headers=headers)
        
        resource_id = ""
        package_id = ""
        
        if response.status_code == 200:
            j = response.json()
            
            if j['success']:
                resource_id = j['result']['resource_id']
                package_id = j['result']['package_id']
            else:
                return jsonify({'help': request.url, 'success': False,
                                'error': 'An error occurred during data processing. Cannot insert file into CKAN'})
        else:
            return jsonify({'help': request.url, 'success': False,
                            'error': 'An error occurred during data processing. Cannot insert file into CKAN'})
            
        mfl.log_param('output', resource_id)
    return jsonify({'help': request.url, 'success': True,
                    'result': {'resource_id': resource_id, 'package_id': package_id}})



def json_config(config_file):
    """Load configuration settings for interacting with CKAN, Ontop, and the PostgreSQL database.

    Args:
        config_file: Path to a JSON file with the configuration settings.

    Returns:
        A dictionary with all configuration settings.
    """

    with open(config_path, 'r') as f:
        config_data = json.load(f)
    return config_data


def yaml_config(config_file):
    """Load configuration settings for interacting with CKAN, Ontop, and the PostgreSQL database.

    Args:
        config_file: Path to a YAML file with the configuration settings.

    Returns:
        A dictionary with all configuration settings.
    """

    with open(config_path, 'r') as f:
        config_data = yaml.safe_load(f)
    return config_data



# Deploy service at the specific host and port
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python klms_api.py <config_file>")
        sys.exit(1)

    # Get configuration settings specified in YAML or JSON
    config_path = sys.argv[1]
    app.config['settings'] = yaml_config(config_path)
#    app.config['settings'] = json_config(config_path)

    # Apply configuration settings for this API
    app.title = app.config['settings']['API_TITLE']
    app.version = app.config['settings']['API_VERSION']

    #app.config['LOCAL_SPEC_PATH'] = 'specs'
    app.config['SPEC_FORMAT'] = app.config['settings']['API_SPEC_FORMAT']
    app.config['AUTO_SERVERS'] = app.config['settings']['API_AUTO_SERVERS']
    app.config['AUTO_TAGS'] = app.config['settings']['API_AUTO_TAGS']
    app.config['AUTO_OPERATION_SUMMARY'] = app.config['settings']['API_AUTO_OPERATION_SUMMARY']
    app.config['AUTO_OPERATION_DESCRIPTION'] = app.config['settings']['API_AUTO_OPERATION_DESCRIPTION']
    app.config['TAGS'] = app.config['settings']['API_TAGS']
    app.config['DESCRIPTION'] = app.config['settings']['API_DESCRIPTION']
    app.config['TERMS_OF_SERVICE'] = app.config['settings']['API_TERMS_OF_SERVICE']

    app.config['CONTACT'] = app.config['settings']['API_CONTACT']
    app.config['LICENSE'] = app.config['settings']['API_LICENSE']
    app.config['SECURITY_SCHEMES'] = app.config['settings']['API_SECURITY_SCHEMES']

    # Deploy the API
    app.run(host=app.config['settings']['FLASK_RUN_HOST'],
            port=app.config['settings']['FLASK_RUN_PORT'],
            debug=app.config['settings']['FLASK_DEBUG'])
