import flask
import requests
import json
import re
import sys
import psycopg2
import yaml
import mlflow as mfl
import pandas as pd
import uuid
import datetime
import os
import subprocess
import docker

from psycopg2.extras import RealDictCursor
from flask import request, jsonify, current_app, redirect, url_for
from apiflask import APIFlask, HTTPTokenAuth
from apiflask.fields import Dict, Nested

from flask.json import JSONEncoder
from datetime import date, datetime


# Auxiliary custom functions & SQL query templates for ranking
import utils

# Input schemata for validating several API requests
import schema


# Custom class to retain original ISO format like 'yyyy-mm-dd hh:mm:ss.m' in date/time/timestamp values
class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        try:
            if isinstance(obj, date):
                return obj.isoformat()
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        return JSONEncoder.default(self, obj)


# Create an instance of this API; by default, its OpenAPI-compliant specification will be generated under folder /specs
app = APIFlask(__name__, spec_path='/specs', docs_path ='/docs')
app.json_encoder = CustomJSONEncoder


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
        return False


################################## DATABASE CONNECTOR ########################################

def execSql(sql):
    """Opens a connection to a PostgreSQL database and executes the given SQL command.

    Args:
        sql (String): The SQL command to be executed in the database.

    Returns:
        A JSON with the retrieved query results for SELECT commands; a JSON with the final execution status (True/False) for INSERT/UPDATE commands.
    """

    config = current_app.config['settings']

    data = None
    try:
        with psycopg2.connect(dbname=config['dbname'], user=config['dbuser'], password=config['dbpass'], host=config['dbhost'], port=config['dbport']) as conn:
            with conn.cursor() as cur:
                # Execute the SQL statement
                cur.execute(sql)

                # Handle the response                
                desc = cur.description

                if desc:  # SELECT commands
                    column_names = [col[0] for col in desc]
                    data = [dict(zip(column_names, row))  
                            for row in cur.fetchall()]
                else:     # INSERT, UPDATE commands
                    data = {}
                    # obtain the inserted rows
                    if cur.rowcount > 0:
                        data['status'] = True
                    else:
                        data['status'] = False

                # Commit the changes to the database
                conn.commit()
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)    
    finally:
        return data


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
@app.doc(tags=['User Management'])
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


@app.route('/api/v1/catalog/user/update', methods=['POST'])
@app.input(schema.ChangedUser, location='json', example={"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "about" : "Testing the CKAN API for patching information about an existing user", "image_url":"https://commons.wikimedia.org/wiki/File:JPEG_example_flower.jpg"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User Management'])
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


@app.route('/api/v1/catalog/user/delete', methods=['POST'])
@app.input(schema.Identifier, location='json', example={"id":"02568a6c-9970-4650-87d7-26d4f7d64fd6"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User Management'])
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


@app.route('/api/v1/catalog/user/role/assign', methods=['POST'])
@app.input(schema.UserRole, location='json', example={"id": "athenarc", "username":"02568a6c-9970-4650-87d7-26d4f7d64fd6", "role":"editor"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User Management'])
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


@app.route('/api/v1/catalog/user/token/create', methods=['POST'])
@app.input(schema.NewToken, location='json', example={"user": "test_user5", "name": "test5_API_token"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User Management'])
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



@app.route('/api/v1/catalog/user/organization', methods=['GET'])
@app.input(schema.Identifier, location='query', example="778bc28b-627c-472f-9d78-4d3617733218")
#@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User Management'])
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


@app.route('/api/v1/catalog/user/organization', methods=['POST'])
#@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User Management'])
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


@app.route('/api/v1/user', methods=['GET'])
@app.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['User Management'])
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
def api_dataset_id(query_data):
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
    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the requested dataset.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'package_show?id='+id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    return response.json()



@app.route('/api/v1/dataset/export_zenodo', methods=['GET'])
@app.input(schema.Identifier, location='query', example="cf0c3c59-fc41-48c9-a529-6b9feff42991")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_export_zenodo_dataset_id(query_data):
    """Export all metadata available for a dataset (i.e., CKAN package) in order to published to Zenodo.

    Args:
        id: The unique identifier of the dataset as listed in CKAN.

    Returns:
        A JSON with metadata compliant with DataCite's Metadata Schema employed by Zenodo.
    """

    config = current_app.config['settings']

    # Check if an ID (name) for a dataset was provided as argument
    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the requested dataset.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'package_show?id='+id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  
    resp_json = response.json()

    zenodo_metadata = {}
    if resp_json['success']:
        dataset = resp_json['result']
        creator_id = dataset['creator_user_id']

        # Make another GET request to the CKAN API to get details about the creator of the CKAN package
        # IMPORTANT! CKAN requires NO authentication for GET requests
        resp_creator = requests.get(config['CKAN_API']+'user_show?id='+creator_id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  
        json_creator = resp_creator.json()
    
        # Internal call to find the organization where the creator of the dataset belongs to
#        resp_org = requests.get(api_user_organization, params = {'id':creator_id})
#        params = {'id':creator_id}
#        resp_org = redirect(url_for('api_user_organization', query_data=creator_id))

        # Make a GET request to the CKAN API to find the organization where the creator of the dataset belongs to
        # IMPORTANT! CKAN requires NO authentication for GET requests
        resp_org = requests.get(config['CKAN_API']+'organization_list_for_user?id='+creator_id) #, headers=config.package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  
        json_org = resp_org.json()

        if json_org['success']:
            # Formulate metadata according to Zenodo specifications; no DOI specified
            zenodo_metadata = utils.prepareZenodoMetadata(dataset, json_creator['result']['display_name'], json_org['result'][0]['title'], None)

    return jsonify(zenodo_metadata)



@app.route('/api/v1/catalog/search', methods=['POST'])
@app.input(schema.Query, location='json', example={"q":{"Topic":"POI", "INSPIRE theme":"Location", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
@app.auth_required(auth)
def api_catalog_search(json_data):
    """Submit a search request to the Data Catalog.

    Args:
        json_data: A JSON with filtering criteria for searching in the Data Catalog. Keys should match properties specified in the STELAR Ontology.

    Returns:
        A JSON with all metadata available in the Catalog for each dataset qualifying to the filtering criteria and accessible by the user.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:9055/api/v1/catalog/search -d '{"q":{"Topic":"POI", "INSPIRE theme":"Location", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}}'

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
        filter = request.data
        specs = json.loads(filter.decode("utf-8"))
        if 'q' in specs:
            q = utils.format_CKAN_filter(specs['q'])
#            print(q)
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Incorrect specifications','name':['Incorrect or no filters provided to search in the Data Catalog. Please specify at least one filtering criterion in a dictionary.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No filters provided to search in the Data Catalog. Please specify at least one filtering criterion in a dictionary.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! Although CKAN generally requires NO authentication for GET requests, it is important in order to also retrieve private datasets of the user's organization
    response = requests.get(config['CKAN_API']+'package_search'+q+'&include_private=True&fl=*,score', headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@app.route('/api/v1/dataset/search', methods=['GET'])
@app.input(schema.ComplexFilter, location='query', example="q=Lakes&ext_bbox=20,35,30,42")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_package_search(query_data):
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

#    if request.headers:
#        if request.headers.get('Api-Token') != None:
#            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
#        else:
#            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
#            return jsonify(response)
#    else:
#        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
#        return jsonify(response)

    # Multiple criteria can be correctly passed with argument ?q 
    if 'q' in query_data:      		# Search on various metadata
        q = '?q=' + query_data['q']
    elif 'ext_bbox' in query_data:  	# Search on spatial extent only
        q = '?ext_bbox=' + query_data['ext_bbox']
    elif 'fq' in query_data:   		# Search on facets only
        q = '?fq=' + query_data['fq']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No filtering criteria provided to search for datasets in the Catalog. Please specify at least one filter as argument.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! Although CKAN generally requires NO authentication for GET requests, it is important in order to also retrieve private datasets of the user's organization
    # IMPORTANT! To return all available results, must specify the max number of rows
    response = requests.get(config['CKAN_API']+'package_search'+q+'&include_private=True&fl=*,score&rows='+str(config['RANK_MAX_TOPK'])+'&start=0') #, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    # Pass an empty data frame to report the original SOLR scores; no facet specs need be added
    return utils.assign_scores(response, pd.DataFrame(), {}, {})  



@app.route('/api/v1/resource', methods=['GET'])
@app.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_resource_id(query_data):
    """Get all metadata available for a resource that is accessible by the user.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with all metadata maintained in CKAN for the specified resource.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/resource?id=6dc36257-abb6-45b5-b3bb-5f94160fc2ee

    config = current_app.config['settings']

    # Check if an ID (name) for a dataset was provided as argument
    if 'id' in query_data:
        id = query_data['id']
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
def api_resource_search(query_data):
    """Submit a request to search among the CKAN resources accessible by the user.

    Args:
        q: Filtering criteria for searching in CKAN. Syntax must follow SOLR specifications for filtering. https://docs.ckan.org/en/latest/api/#ckan.logic.action.get.resource_search

    Returns:
        A JSON with all metadata available in CKAN for each dataset qualifying to the filtering criteria and accessible by the user.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/resource/search?q=format:JSON

    config = current_app.config['settings']

    # Check if filtering criteria was provided as argument
    if 'q' in query_data:
        q = query_data['q']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No filtering criteria provided to search for resources in the Catalog. Please specify at least one filter as argument.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_search?query='+q) #, headers=config.package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@app.route('/api/v1/workflow/input/dataset', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=82aaa2df-be92-46ee-a36b-cc59122a5d5b")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_workflow_input_dataset(query_data):
    """Submit a request to identify in which workflow(s) a dataset (CKAN package) has been given as input to any of the involved tasks.

    Args:
        id: The identifier (UUID) assigned to the dataset by the Catalog (CKAN).

    Returns:
        A JSON with metadata about the workflow(s) where this dataset has been given as input.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/input/dataset?id=82aaa2df-be92-46ee-a36b-cc59122a5d5b

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No dataset identifier provided to search in the Catalog. Please specify a valid identifier for the dataset.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('workflow_input_dataset_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))


@app.route('/api/v1/workflow/output/dataset', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=9232eef6-5acf-4280-b3e9-38d6c8935d7d")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_workflow_output_dataset(query_data):
    """Submit a request to identify in which workflow(s) the given dataset (CKAN package) has been issued as output in any of the involved tasks.

    Args:
        id: The identifier (UUID) assigned to the dataset by the Catalog (CKAN).

    Returns:
        A JSON with metadata about the workflow(s) where this dataset has been issued as output.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/output/dataset?id=9232eef6-5acf-4280-b3e9-38d6c8935d7d

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No dataset identifier provided to search in the Catalog. Please specify a valid identifier for the dataset.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('workflow_output_dataset_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))



@app.route('/api/v1/workflow/input/resource', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=6b077882-bd24-480b-896b-d7e8431338e5")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_workflow_input_resource(query_data):
    """Submit a request to identify in which workflow(s) a file (CKAN resource) has been given as input to any of the involved tasks.

    Args:
        id: The identifier (UUID) assigned to the resource by the Catalog (CKAN).

    Returns:
        A JSON with metadata about the workflow(s) where this file has been given as input.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/input/resource?id=6b077882-bd24-480b-896b-d7e8431338e5

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No resource identifier provided to search in the Catalog. Please specify a valid identifier for the resource.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('workflow_input_resource_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))



@app.route('/api/v1/workflow/output/resource', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=50156c05-6150-494d-b372-77d859f768d2")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_workflow_output_resource(query_data):
    """Submit a request to identify in which workflow(s) the given file (CKAN resource) has been issued as output in any of the involved tasks.

    Args:
        id: The identifier (UUID) assigned to the resource by the Catalog (CKAN).

    Returns:
        A JSON with metadata about the workflow(s) where this file has been issued as output.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/output/resource?id=50156c05-6150-494d-b372-77d859f768d2

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No resource identifier provided to search in the Catalog. Please specify a valid identifier for the resource.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('workflow_output_resource_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))



@app.route('/api/v1/workflow/tasks', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=UC_A3")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_workflow_tasks(query_data):
    """Submit a request to the Knowledge Graph to retrieve the tasks defined in a workflow.

    Args:
        id: The identifier assigned to the workflow.

    Returns:
        A JSON with the list of tasks included in the given workflow.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/tasks?id=UC_A3

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No identifier provided for the workflow in the Knowledge Graph. Please specify a valid identifier for the workflow.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('workflow_tasks_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))



@app.route('/api/v1/task/executions', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=entity_extraction")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_task_executions(query_data):
    """Submit a request to the Knowledge Graph to retrieve the executions performed for the given task.

    Args:
        id: The identifier assigned to the task in MLFlow.

    Returns:
        A JSON with the details of the task executions.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/executions?id=entity_extraction

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_executions_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))



@app.route('/api/v1/task/execution/input', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_task_execution_input(query_data):
    """Submit a request to the Knowledge Graph to retrieve the identifiers of dataset(s) given as input to the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the list of dataset identifiers (CKAN resources) collected in MLFlow for the specified task execution.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/input?id=0075f24c7b654246a65c12739e96b867

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_execution_input_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))



@app.route('/api/v1/task/execution/output', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_task_execution_output(query_data):
    """Submit a request to the Knowledge Graph to retrieve the identifiers of dataset(s) issued as output from the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the list of dataset identifiers (CKAN resources) collected as output in MLFlow for the specified task execution.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/output?id=0075f24c7b654246a65c12739e96b867

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_execution_output_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))




@app.route('/api/v1/task/execution/metrics', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_task_metrics(query_data):
    """Submit a request to the Knowledge Graph retrieve the metrics issued for the specified task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the metrics collected in MLFlow for the specified task execution.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/metrics?id=0075f24c7b654246a65c12739e96b867

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_execution_metrics_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))


@app.route('/api/v1/task/execution/parameters', methods=['GET'])
@app.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_task_parameters(query_data):
    """Submit a request to the Knowledge Graph retrieve the parameters specified for the task execution.

    Args:
        id: The identifier (UUID) assigned to the task execution in MLFlow.

    Returns:
        A JSON with the parameters specified in MLFlow for the specified task execution.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/parameters?id=0075f24c7b654246a65c12739e96b867

    config = current_app.config['settings']

    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution.']}}
        return jsonify(response)

    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
    # Formulate the SPARQL query with the given identifier
    sparql = utils.format_sparql_filter('task_execution_parameters_template', id)
#    print(sparql)
    # Make a POST request to the Ontop API with the given query
    # IMPORTANT! NO authentication required by public SPARQL endpoints
    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)

    return jsonify(json.loads(response.text))



@app.route('/api/v1/graph/search', methods=['POST'])
@app.input(schema.Filter, location='json', example={"q": "PREFIX dct: <http://purl.org/dc/terms/> SELECT ?uri ?title ?publisher WHERE { ?uri dct:title ?title . ?uri dct:publisher ?publisher . } LIMIT 5"})
#@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
@app.auth_required(auth)
def api_sparql(json_data):
    """Submit a search request to the SPARQL endpoint.

    Args:
        json_data: A JSON specifying the SELECT query in SPARQL for searching the Knowledge Graph via Ontop. Syntax must follow SPARQL specifications for Ontop.

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


@app.route('/api/v1/catalog/sql', methods=['POST'])
@app.input(schema.Filter, location='json', example={"q": "SELECT * FROM public.package LIMIT 5"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
@app.auth_required(auth)
def api_sql(json_data):
    """Submit a SELECT SQL command to the PostgreSQL database.

    Args:
        json_data: A JSON specifying the SELECT query in SQL for searching the Data Catalog in PostgreSQL. Syntax must follow SQL specifications for PostgreSQL.

    Returns:
        A JSON with all results qualifying to the search criteria.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/text' http://127.0.0.1:9055/api/v1/catalog/sql -d '{"q":"SELECT * FROM public.package LIMIT 5"}' 

    config = current_app.config['settings']

    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        if 'q' in specs:
            sql = specs['q']
#            print(sql)
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Incorrect specifications','name':['Incorrect or no filters provided to search in the Data Catalog. Please specify a valid SELECT query command in SQL.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No SQL query provided to search in the Data Catalog. Please specify a valid SELECT query command in SQL.']}}
        return jsonify(response)

    #sql_headers = {'Content-Type':'application/sql-query', 'Accept':'application/json'}

    conn = psycopg2.connect(dbname=config['dbname'], user=config['dbuser'], password=config['dbpass'], host=config['dbhost'], port=config['dbport']) #, sslmode=config['sslmode'])
    
    cur = conn.cursor(cursor_factory=RealDictCursor) 
    cur.execute(sql)
    results = cur.fetchall()
    conn.commit()

    return jsonify(results)


@app.route('/api/v1/catalog/facet/values', methods=['POST'])
@app.input(schema.Filter, location='json', example={"q": "format"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
@app.auth_required(auth)
def api_facet_values(json_data):
    """Submit a SELECT SQL command to the PostgreSQL database.

    Args:
        json_data: A JSON specifying the facet name (corresponding to an SQL view or table) to query in the PostgreSQL database of the Data Catalog.

    Returns:
        A JSON with all values available for the specified facet.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/text' http://127.0.0.1:9055/api/v1/catalog/facet/values -d '{"q":"format"}' 

    config = current_app.config['settings']

    if request.data:
        specs = json.loads(request.data.decode("utf-8"))
        # Identify the SQL view that corresponds to the specified facet
        if 'q' in specs and utils.sql_views.get(specs['q']):
            view_name = str(utils.sql_views.get(specs['q']))
            sql = 'SELECT * FROM ' + view_name
#            print(sql)
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Incorrect specifications','name':['Incorrect or no filters provided to fetch facet values from the Data Catalog. Please specify a valid name for SQL view.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No valid facet specified to fetch its values from the Data Catalog. Please specify a valid name for SQL view.']}}
        return jsonify(response)

    # Execute the SQL view to fetch the values
    #sql_headers = {'Content-Type':'application/sql-query', 'Accept':'application/json'}
    conn = psycopg2.connect(dbname=config['dbname'], user=config['dbuser'], password=config['dbpass'], host=config['dbhost'], port=config['dbport']) #, sslmode=config['sslmode'])
    cur = conn.cursor(cursor_factory=RealDictCursor) 
    cur.execute(sql)
    results = cur.fetchall()
    conn.commit()

    # Exclude identifiers from the returned results
    for res in results:
        if 'id' in res:
            del res['id']
        elif 'package_id' in res:
            del res['package_id']

    return jsonify(results)



################################## RANKING OPERATIONS ########################################

@app.route('/api/v1/catalog/rank', methods=['POST'])
@app.input(schema.Ranking, location='json', example={"rank_preferences":{"tags": ["Geospatial","POI"], "theme":["Land Use","Land Cover","Imagery"], "language":["en","el","fr"], "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}, "settings":{"k": 10, "algorithm": "threshold", "weights": [0.3,0.5,0.4] }})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Ranking Operations'])
@app.auth_required(auth)
def api_catalog_rank(json_data):
    """Submit a rank request regarding specific metadata attributes (facets) to the Data Catalog.

    Args:
        json_data: A JSON with facet preferences for searching in the Data Catalog. Facet name should match a property specified in the STELAR Ontology.

    Returns:
        A JSON with datasets ranked by the specified facet(s). The matching score per facet criterion is also listed per returned dataset.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' http://127.0.0.1:9055/api/v1/catalog/rank -d '{"q":{"theme":"POI"}}'

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

    sql = ''
    sql_id_filter = ''
    ids = []
    dict_df_facet_scores = {}   # dictionary with the returned input ranked lists per facet (key -> dataframe)
    k = config['RANK_MAX_TOPK']  # default top-k value (if not user-specified)
    if request.data:
        specs = json.loads(request.data.decode("utf-8"))

        # STAGE #1: text-based keyword search targets SOLR (search engine for CKAN)
        if 'keywords' in specs:   # CASE #1(a): new keyword search
            q = '?q=' + ",".join("'{0}'".format(kw) for kw in specs['keywords'])   
            # Submit a preliminary search request to CKAN to find packages qualifying to the specified keywords
            # Also include private datasets of the user's organization in the results
            resp_basic = requests.get(config['CKAN_API']+'package_search'+q+'&include_private=True&fl=*,score&rows='+str(config['RANK_MAX_TOPK'])+'&start=0', headers=package_headers)
            if resp_basic.status_code == 200:
                json_resp_basic = resp_basic.json()
                if json_resp_basic['success']:  # Results from keyword-based search only
                    results = json_resp_basic['result']['results']
                    ids = [res['id'] for res in results if 'id' in res]
#                    print('keyword results:',len(ids))
        elif 'ids' in specs:  # CASE #1(b): Identifiers of datasets already qualifying keyword search criteria
            if len(specs['ids']) > 0:
                ids = specs['ids']
        if len(ids) > 0:   # Specify the previously filtered items to be sent for ranking
            sql_id_filter, k = utils.format_sql_filter(ids)  
        else:   # No results from filtering, no sense to continue with further filtering
            response = {'help': request.url, 'result': {'count': 0, 'facets': {}, 'results': [],'sort': 'score desc, metadata_modified desc'}, 'success': True}
            return jsonify(response)

        # STAGE #2: Apply any filtering criteria (NOT participating in the ranking)
        if 'filter_preferences' in specs:
            filter_sql_commands = utils.format_facet_preferences(specs['filter_preferences'], sql_id_filter, config['RANK_MAX_TOPK'])
            # Submit each SELECT query to the PostgreSQL database with the respective parameters
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            for key in filter_sql_commands.keys():
                sql = filter_sql_commands[key]
                results = execSql(sql)
#                print(len(results), sql)
                filter_ids = [res['id'] for res in results if 'id' in res]
                if sql_id_filter == '':  # No keywords specified in search bar
                    ids = filter_ids
                else:  # Keep only matching id's
                    ids = [id for id in ids if id in filter_ids]
#                print(key, len(ids))
        if len(ids) > 0:   # Specify the previously filtered items to be sent for ranking
            sql_id_filter, k = utils.format_sql_filter(ids) 
        else:   # No results from filtering, no sense to apply ranking
            response = {'help': request.url, 'result': {'count': 0, 'facets': {}, 'results': [],'sort': 'score desc, metadata_modified desc'}, 'success': True}
            return jsonify(response)

        # STAGE #3: Prepare SQL queries for each of the ranking preferences 
        if 'rank_preferences' in specs:
            rank_sql_commands = utils.format_facet_preferences(specs['rank_preferences'], sql_id_filter, config['RANK_MAX_TOPK'])
            # FIXME: REMOVE IF HANDLED BY THE FRONT-END
            # Examine settings for ranking
#            if 'settings' in specs:
#                if not 'algorithm' in specs['settings']: # Apply default algorithm for rank aggregation
#                    specs['settings']['algorithm'] = config['RANK_AGG_ALGORITHM']
#                if 'k' in specs['settings']:
#                    k = specs['settings']['k']
#                else:
#                    specs['settings']['k'] = k    # Rank aggregation library requires the total number of items
#                    print(specs['settings']['k'])
#            else:  # Specify default values for rank aggregation
#                specs['settings'] = {}
#                specs['settings']['algorithm'] = config['RANK_AGG_ALGORITHM']
#                specs['settings']['k'] = k 

            # Submit each SELECT query to the PostgreSQL database with the respective parameters
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            input_lists = []
            for key in rank_sql_commands.keys():
                sql = rank_sql_commands[key]
#                print(key, '->', sql)
                results = execSql(sql)
#                print(len(results), len(ids))
                # Fill any missing scores in the partial list for this facet
                for id in ids:
                    if not id in [d['id'] for d in results if 'id' in d]:
                        results.append({'id':id, 'score':0.0})
                dict_df_facet_scores[key] = utils.read_list_json(results)
                input_lists.append(dict_df_facet_scores[key])

            # FIXME: REMOVE IF HANDLED BY THE FRONT-END    
            agg_scores = pd.DataFrame()   # No aggregated scores, report the original SOLR scores
    
            # Compute the final ranked list of all items applying the specified rank aggregation method (e.g., threshold)
#            agg_scores = ranking.combined_ranking(input_lists, specs['settings'])
#            ids = agg_scores.index.values  # In case no keywords and no filter criteria have been spcified; only rank preferences
#            print(agg_scores.index.values)
        elif 'settings' in specs:  # Settings for rank aggregation assume at least once facet specification
            response = {'success':False, 'help': request.url, 'error':{'__type':'Incorrect specifications','name':['Incorrect or no facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary.']}}
            return jsonify(response)
        else:   # No ranking to be applied; only search filters
            specs['rank_preferences'] = {}  # Facets for ranking not specified
            agg_scores = pd.DataFrame()   # No aggregated scores, report the original SOLR scores
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No facet preferences provided to rank items in the Data Catalog. Please specify at least one facet preference in a dictionary.']}}
        return jsonify(response)

    # Retrieve from CKAN all metadata for the datasets in the final (aggregated ranked) list
    # Also include private datasets of the user's organization in the results
    q='?q=' + ' OR '.join(['id:'+id for id in ids])
    response = requests.get(config['CKAN_API']+'package_search'+q+'&rows='+str(config['RANK_MAX_TOPK'])+'&start=0&include_private=True', headers=package_headers) 

    # Return the final list of results (the top-k ranked ones in case that ranking preferences are specified)
    return utils.assign_scores(response, agg_scores, dict_df_facet_scores, specs['rank_preferences'])


############################### PUBLISHING OPERATIONS ############################

@app.route('/api/v1/catalog/publish', methods=['POST'])
@app.input(schema.Dataset, location='json', example={"basic_metadata":{"title": "Test Data API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": ["STELAR","OpenStreetMap","Geospatial","Bavaria"]},"extra_metadata":{"INSPIRE theme":"Imagery", "theme": ["Earth Sciences", "Landuse", "http://eurovoc.europa.eu/4630"], "language": ["ca", "en", "es"], "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]},"temporal_start":"2023-01-31T11:33:54.132Z", "temporal_end":"2023-01-31T11:35:48.593Z"},"profile_metadata":{"url":"https://raw.githubusercontent.com/stelar-eu/data-profiler/main/examples/output/timeseries_profile.json", "name": "Time series profile in JSON", "description": "This is the profile of a time series in JSON format", "resource_type": "Tabular", "format": "JSON", "resource_tags": ["Profile", "Computed with STELAR Profiler"]}})
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

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/catalog/publish -d '{"basic_metadata":{"title": "Test Data API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Bavaria"}]},"extra_metadata":{"INSPIRE theme":"Imagery","theme": ["Earth Sciences", "Landuse", "http://eurovoc.europa.eu/4630"], "language": ["ca", "en", "es"], "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]},"startDate":"2023-01-31T11:33:54.132Z", "endDate":"2023-01-31T11:35:48.593Z"},"profile_metadata":{"file":"/data/examples/timeseries_profile.json", "name": "Time series profile in JSON", "description": "This is the profile of a time series in JSON format", "format": "JSON", "resource_tags": [{"key": "Resource type", "value": "Profile"}, {"key": "Process", "value": "Computed with STELAR Profiler"}]}}'

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
        # Convert the tags into the format required by CKAN 
        basic_metadata['tags'] = utils.handle_keywords(basic_metadata['tags'])
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
#        print(resp_basic.text)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No basic metadata provided for publishing in the Catalog. Please specify some basic metadata (title, description, tags, etc.) for the dataset you wish to publish.']}}
        return jsonify(response)

    # Get the id of the newly created package in order to associate any remaining information (extras, resources)
    if resp_basic.status_code == 200:
        package_id = resp_basic.json()['result']['id']
#        print("package_id: ", package_id)
    else:
        return resp_basic.json()  # Failed to publish the dataset with the basic metadata provided; CKAN response will specify the reason

    # Handle other user-specified metadata as extras
    # Also store values in custom tables for profiles in KLMS schema in the database
    if specs.get('extra_metadata') != None:
        # Convert this metadata to a JSON array with {"key":"...", "value":"..."} pairs as required to be stored as extras in CKAN
        extra_metadata = {}
        extra_metadata['id'] = package_id   # Must specify the id of the newly created package
        extra_metadata['extras'] = utils.handle_extras(specs['extra_metadata'])
        # Make a POST request to the CKAN API to patch the newly created package with the extra metadata
        resp_extras = requests.post(config['CKAN_API']+'package_patch', json=extra_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
        arr_resp.append(resp_extras.json())
    else:
        resp_extras = {'success':True, 'help': request.url, 'warning':{'__type':'No specifications','name':['Warning: No extra metadata provided for publishing this dataset in the Catalog. You may still apply a CKAN package_patch request to include such extra metadata to this dataset in the future.']}}
        arr_resp.append(resp_extras)

    # Handle profile metadata as a resource    
    # TODO: Replace with the respective API function?
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
                sql_commands = utils.extractProfileProperties(resource_id, profile)
                for sql in sql_commands:
#                    print(sql)
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
@app.input(schema.Package, location='json', example={"package_metadata": {"title": "Test Data API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Berlin"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}],"name": "test_data_api_1","private": "false","version": "0.3","owner_org": "athenarc"}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_dataset_register(json_data):
    """Register a new dataset according to CKAN specifications. The user will become the publisher of this dataset.

    Args:
        data: A JSON with basic metadata information (as required by CKAN) provided by the publisher about the new dataset.

    Returns:
        A JSON with the CKAN response to the registration request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/dataset/register -d '{"package_metadata": {"title": "Test Data API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Berlin"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}],"name": "test_data_api_1","private": "false","version": "0.3","owner_org": "athenarc"}}'

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
@app.input(schema.Package, location='json', example={"package_metadata": {"id": "test_data_api_1", "tags": [{"name": "Patch"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}] }})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_dataset_patch(json_data):
    """Patch more metadata to an existing dataset according to CKAN specifications. The user will become the publisher of this dataset.

    Args:
        data: A JSON with additional metadata information provided by the publisher about the new dataset.

    Returns:
        A JSON with the CKAN response to the patch request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/dataset/patch -d '{"package_metadata": {"id": "test_data_api_1", "tags": [{"name": "Patch"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}] }}'

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


@app.route('/api/v1/profile/publish', methods=['POST'])
@app.input(schema.Profile, location='json', example={"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_type": "Raster", "resource_tags": ["Profile","Computed with STELAR Profiler"]}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_profile_publish(json_data):
    """Upload a profile as a resource to an existing dataset in CKAN. The user will become the publisher of this profile.

    Args:
        data: A JSON with all metadata information provided by the publisher about the profile.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/profile/upload -d '{"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": ["Profile","Computed with STELAR Profiler"]}}'

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
        metadata = json.loads(request.data.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
        if 'profile_metadata' in metadata:
            resource_metadata = metadata['profile_metadata']
        else:
            response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No metadata provided for publishing this profile in the Catalog. Please specify metadata for the profile you wish to upload.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing this profile in the Catalog. Please specify metadata for the profile you wish to upload.']}}
        return jsonify(response)

    if resource_metadata.get('file') != None:
        # Make a POST request to the CKAN API to upload the file from the specified path
        with open(resource_metadata['file'], 'rb') as f:
#            print('Profile information found!')
            response = requests.post(config['CKAN_API']+'resource_create', data=resource_metadata, headers=resource_headers, files=[('upload', f)])
            # Also ingest profile information into PostgreSQL according to KLMS schema
            resource_id = response.json()['result']['id']
#            print("RESOURCE ID: ", resource_id)
            f1 = open(resource_metadata['file'])
            profile = json.load(f1)
            # Distinguish handling according to Profile type
            sql_commands = utils.extractProfileProperties(resource_id, profile)
            for sql in sql_commands:
#                print(sql)
                execSql(sql)
            return response.json()
    elif resource_metadata.get('url') != None:
        # Make a POST request to the CKAN API to link the file from the specified URL
        response = requests.post(config['CKAN_API']+'resource_create', data=resource_metadata, headers=resource_headers)
        return response.json()
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No profile metadata were associated with this dataset in the Catalog. Please provide a path or a publicly accessible URL where this file is available.']}}
        return response.json()


@app.route('/api/v1/resource/upload', methods=['POST'])
@app.input(schema.Resource, location='json', example={"resource_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": ["Profile","Computed with STELAR Profiler"]}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_resource_upload(json_data):
    """Upload a resource to an existing dataset according to CKAN specifications. The user will become the publisher of this resource.

    Args:
        data: A JSON with all metadata information provided by the publisher about the new resource.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/resource/upload -d '{"resource_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": ["Profile","Computed with STELAR Profiler"]}}'

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
@app.input(schema.Resource, location='json', example={"resource_metadata": {"package_id": "test_data_api_1", "url":"https://data.smartdublin.ie/dataset/09870e46-26a3-4dc2-b632-4d1fba5092f9/resource/40a718a8-cb99-468d-962b-af4fed4b0def/download/bleeperbike_map.geojson", "name": "Test GeoJSON resource", "description": "This is the test resource in GeoJSON format", "format": "GeoJSON", "resource_type": "Tabular", "resource_tags": ["Link to external resource", "Found in the Web"]}})
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

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/resource/link -d '{"resource_metadata": {"package_id": "test_data_api_1", "url":"https://data.smartdublin.ie/dataset/09870e46-26a3-4dc2-b632-4d1fba5092f9/resource/40a718a8-cb99-468d-962b-af4fed4b0def/download/bleeperbike_map.geojson", "name": "Test GeoJSON resource", "description": "This is the test resource in GeoJSON format", "format": "GeoJSON", "resource_tags": ["Link to external resource", "Found in the Web"]}}'

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

    if response.status_code == 200:
        # Also ingest profile information into PostgreSQL according to KLMS schema
        resource_id = response.json()['result']['id']
        # print("RESOURCE ID: ", resource_id)
        # Distinguish handling according to Profile type
        sql_commands = utils.extractResourceProperties(resource_id, resource_metadata)
        for sql in sql_commands:
            execSql(sql)

    return response.json()




@app.route('/api/v1/workflow/publish', methods=['POST'])
@app.input(schema.Package, location='json', example={"package_metadata": {"title": "Test workflow", "notes": "This workflow performs entity matching", "tags": ["STELAR", "Entity matching", "Entity resolution"]}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_workflow_publish(json_data):
    """Publish a new workflow as a CKAN package. The user will become the publisher of this workflow.

    Args:
        data: A JSON with basic metadata information (as required by CKAN) provided by the publisher about the new workflow.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/workflow/publish -d '{"package_metadata": {"title": "Test workflow", "notes": "This workflow performs entity matching", "tags": ["STELAR", "Entity matching", "Entity resolution"]}'

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
        metadata = json.loads(request.data.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
        if 'package_metadata' in metadata:
            package_metadata = metadata['package_metadata']
            # Also create the name of the new CKAN package from its title (assuming that this is unique)
            package_metadata['name'] = re.sub(r'[\W_]+','_', package_metadata['title']).lower()
            # Convert the tags into the format required by CKAN 
            package_metadata['tags'] = utils.handle_keywords(package_metadata['tags'])
            package_metadata['type'] = 'workflow'   # Must specify that this is not a dataset, but a workflow
            # Internal call to find the organization where the user belongs to (derived from API token)
            resp_org = api_user_editor()
            if resp_org['success']:
                org_json = resp_org['result']
                if len(org_json) > 0:  
                    for item in org_json: 
                        if item['type'] == 'organization' and item['state'] == 'active' and item['capacity'] in ('admin','editor'):
                            package_metadata['owner_org'] = org_json[0]['name']  # CAUTION! Taking the first organization where this user is editor
                            break
        else:
            response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No metadata provided for publishing in the Catalog. Please specify at least some basic metadata (title, notes, tags, etc.) for the workflow you wish to publish.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing in the Catalog. Please specify at least some basic metadata (title, notes, tags, etc.) for the workflow you wish to publish.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API with the parameters
    response = requests.post(config['CKAN_API']+'package_create', json=package_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    if response.status_code == 200:
        result = {}
        package_id = response.json()['result']['id']
        result['package_id'] = package_id     # Return the package_id only
        response = {'success':True, 'help': request.url, 'result':result} 
        return jsonify(response)
    else:
        return jsonify(response)



@app.route('/api/v1/artifact/publish', methods=['POST'])
@app.input(schema.Artifact, location='json', example={"package_metadata":{"package_id": "test_data_api_1"},"artifact_metadata":{"url":"s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv", "task_uuid":"d63a2b507bf6b6eadcb2c8de378c0370", "name": "Results of deduplication task", "description": "This is the test artifact uploaded to minio S3 in CSV format", "format": "CSV", "resource_tags": ["Artifact","MLFlow"]}})
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

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/artifact/publish -d '{"package_metadata":{"title":"Results of Airflow dag mycalc", "tags":[{"name": "Artifact"}, {"name": "Workflow"}], "extras":[{"key":"dag_id", "value":"mycalc"}, {"key":"run_id", "value":"scheduled__2023-07-11T00:00:00+00:00"}], "notes": "My calculation using AirFlow"},"artifact_metadata":{"url":"s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv", "task_uuid":"d63a2b507bf6b6eadcb2c8de378c0370", "name": "Results of deduplication task", "description": "This is the test artifact uploaded to minio S3 in CSV format", "format": "CSV", "resource_tags": ["Artifact","MLFlow"]}}'
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'API_TOKEN: XXXXXXXXX' http://127.0.0.1:9055/api/v1/artifact/publish -d '{"package_metadata":{"package_id": "test_data_api_1"},"artifact_metadata":{"url":"s3://mlflow-bucket/16/041d3882c0814e94968135525cbd5aa7/artifacts/20220805_duplicates.csv", "task_uuid":"d63a2b507bf6b6eadcb2c8de378c0370", "name": "Results of deduplication task", "description": "This is the test artifact uploaded to minio S3 in CSV format", "format": "CSV", "resource_tags": ["Artifact","MLFlow"]}}'

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



# @app.route('/api/v1/artifact', methods=['GET'])
# @app.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
# @app.output(schema.ResponseOK, status_code=200)
# @app.doc(tags=['Search Operations'])
# def api_artifact_id(query_data):
#     """Get the file path of an artifact. 

#     Provides the path to the file (URL, S3 bucket or local file) where an artifact (stored as a resource) is available. User may need credentials to access this file.

#     Args:
#         id: The unique identifier of the resource as listed in CKAN.

#     Returns:
#         A JSON with the file path for the specified resource as maintained in CKAN.
#     """

#     #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/artifact?id=6dc36257-abb6-45b5-b3bb-5f94160fc2ee

#     config = current_app.config['settings']

# #    if request.headers:
# #        if request.headers.get('Api-Token') != None:
# #            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
# #        else:
# #            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
# #            return jsonify(response)
# #    else:
# #        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
# #        return jsonify(response)

#     # Check if an ID (name) for a resource was provided as argument
#     if 'id' in query_data:
#         id = query_data['id']
#     else:
#         response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the unique id of the requested artifact.']}}
#         return jsonify(response)

#     # Make a GET request to the CKAN API with the parameters
#     # IMPORTANT! CKAN requires NO authentication for GET requests
#     response = requests.get(config['CKAN_API']+'resource_show?id='+id) #, headers=package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

#     # Get the path of this artifact 
#     if response.status_code == 200:
#         path = response.json()['result']['url']
#         response = {'success':True, 'help': request.url, 'result':{'path':path}}
#         return jsonify(response)
#     else:
#         return response.json()

@app.route('/api/v1/artifact', methods=['GET'])
@app.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_artifact_id(query_data):
    """Get the file path of an artifact. 

    Provides the path to the file (URL, S3 bucket or local file) where an artifact (stored as a resource) is available. User may need credentials to access this file.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with the file path for the specified resource as maintained in CKAN.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/artifact?id=6dc36257-abb6-45b5-b3bb-5f94160fc2ee

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

    # Check if an ID (name) for a resource was provided in the request
    if 'id' in request.args:
        id = request.args['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the unique id of the requested artifact.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_show?id='+id, headers=package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    # Get the path of this artifact 
    if response.status_code == 200:
        path = response.json()['result']['url']
        response = {'success':True, 'help': request.url, 'result':{'path':path}}
        return jsonify(response)
    else:
        return response.json()


@app.route('/api/v1/dataset/delete', methods=['POST'])
@app.input(schema.Identifier, location='json', example={"id":"test_data_api_1"})
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

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/dataset/delete -d '{"id": "test_data_api_1"}'

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
        metadata=request.data
        delete_metadata = json.loads(metadata.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for deleting a dataset from the Catalog. Please specify the id of the dataset you wish to permanently delete.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API to purge an existing dataset
    response = requests.post(config['CKAN_API']+'dataset_purge', json=delete_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
    return response.json()


@app.route('/api/v1/dataset/unpublish', methods=['POST'])
@app.input(schema.Identifier, location='json', example={"id":"test_data_api_1"})
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

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/dataset/unpublish -d '{"id": "test_data_api_1"}'

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
        metadata=request.data
        unpublish_metadata = json.loads(metadata.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for unpublishing a dataset from the Catalog. Please specify the id of the dataset you wish to unpublish.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API to unpublish an existing package
    response = requests.post(config['CKAN_API']+'package_delete', json=unpublish_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
    return response.json()



@app.route('/api/v1/resource/delete', methods=['POST'])
@app.input(schema.Identifier, location='json', example={"id":"aa2992aa-b589-463d-ae1e-8430d91206cb"})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Catalog Management'])
@app.auth_required(auth)
def api_resource_delete(json_data):
    """Delete an existing resource from the Catalog.

    Completely removes a resource (e.g., profile) associated with an existing dataset from the CKAN database. The user must have admin role or must be the publisher of this resource.

    Args:
        data: A JSON with the id of an existing resource.

    Returns:
        A JSON with the CKAN response to the delete request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/resource/delete -d '{"id": "aa2992aa-b589-463d-ae1e-8430d91206cb"}'

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
        metadata=request.data
        delete_metadata = json.loads(metadata.decode("utf-8"))   #json.loads(json.dumps(str(request.data)))
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for deleting a resource from the Catalog. Please specify the id of the resource you wish to permanently delete.']}}
        return jsonify(response)

    # Make a POST request to the CKAN API to purge an existing dataset
    response = requests.post(config['CKAN_API']+'resource_delete', json=delete_metadata, headers=package_headers)  # auth=HTTPBasicAuth(config.username, config.password))
    return response.json()


##################################################



def workflow_execution_create(workflow_exec_id, start_date, state, tags=None):
    """Records metadata for a new workflow execution in the database.

    Args:
        workflow_exec_id: UUID of the new workflow execution.
        start_date: Start timestamp of the new workflow execution.
        state: Initial state of the new workflow execution.
        tags: A JSON dictionary with workflow execution metadata as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for creating a new workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_create_template']   
    sql = sql.replace('_WORKFLOW_UUID', '\''+ workflow_exec_id +'\'').replace('_STATE', '\''+ state +'\'').replace('_START_TIMESTAMP', '\''+ start_date +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)
    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    # Compose the SQL command using the template for assigning tags to the new workflow execution 
    if tags:
        for key, value in tags.items():
            sql = utils.sql_workflow_execution_templates['workflow_insert_tags_template']   
            sql = sql.replace('_WORKFLOW_UUID', '\''+ workflow_exec_id +'\'').replace('_KEY', '\''+  key +'\'').replace('_VALUE', '\''+  value +'\'')
#            print(sql)

            # Execute the SQL command in the database
            resp = execSql(sql)
            if resp and 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True


def workflow_execution_update(workflow_exec_id, state, end_date=None):
    """Updates metadata regarding a workflow execution in the database.

    Args:
        task_exec_id: UUID of a workflow execution.
        state: Current state of this workflow execution.
        end_date: Timestamp marking the end of this workflow execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for updating a workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_update_template']   
    sql = sql.replace('_WORKFLOW_UUID', '\''+ workflow_exec_id +'\'').replace('_STATE', '\''+ state +'\'')
    if end_date:
        sql = sql.replace('_END_TIMESTAMP', '\''+ end_date +'\'')
    else:
        sql = sql.replace('_END_TIMESTAMP', 'NULL')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)

    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True


def workflow_execution_delete(workflow_exec_id):
    """Deletes all metadata regarding a workflow execution from the database. CAUTION! This also includes all metadata about task executions associated with this workflow execution.

    Args:
        workflow_exec_id: UUID of a workflow execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for deleting a workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_delete_template']   
    sql = sql.replace('_WORKFLOW_UUID', '\''+ workflow_exec_id +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)

    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True


def workflow_execution_read(workflow_exec_id):
    """Returns metadata recorded in the database about the given workflow execution. User-specified tags are included in the returned response.

    Args:
        task_exec_id: UUID of the workflow execution.

    Returns:
        A JSON with the workflow execution metadata.
    """

    # Compose the SQL command using the template for reading metadata about a workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_read_template']   
    sql = sql.replace('_WORKFLOW_UUID', '\''+ workflow_exec_id +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)

    if resp and len(resp)>0:
        workflow_specs = resp[0]  # List should contain specification of a single workflow execution (unique UUID)
        # Also include any user-specified tags in the response
        workflow_specs['tags'] = workflow_execution_tags_read(workflow_exec_id)
        return workflow_specs
    else:
        return None


def workflow_execution_tags_read(workflow_exec_id):
    """Returns tags recorded as (key, value) pairs in the database about the given workflow execution.

    Args:
        workflow_exec_id: UUID of the workflow execution.

    Returns:
        A JSON dictionary with the workflow execution tags.
    """

    # Compose the SQL command using the template for reading tags about a workflow execution
    sql = utils.sql_workflow_execution_templates['workflow_read_tags_template']   
    sql = sql.replace('_WORKFLOW_UUID', '\''+ workflow_exec_id +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)

    if resp and len(resp)>0:
        tag_dict = {tag['key']: tag['value'] for tag in resp}
        return tag_dict
    else:
        return None



def task_execution_create(task_exec_id, workflow_exec_id, start_date, state, tags=None, prev_task_exec_id=None):
    """Records metadata for a new task execution in the database.

    Args:
        workflow_exec_id: UUID of an existing workflow execution.
        task_exec_id: UUID of the new task execution.
        start_date: Start timestamp of the new task execution.
        state: Initial state of the new task execution.
        tags: A JSON dictionary with task execution metadata as (key, value) pairs.
        prev_task_exec_id: UUID of the exexcution of the previous task in the workflow pipeline.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for creating a new task execution
    sql = utils.sql_workflow_execution_templates['task_create_template']   
    sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'').replace('_WORKFLOW_UUID', '\''+ workflow_exec_id +'\'').replace('_STATE', '\''+ state +'\'').replace('_START_TIMESTAMP', '\''+ start_date +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)
    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    # Compose the SQL command using the template for specifying the previously executed task
    if prev_task_exec_id:
        sql = utils.sql_workflow_execution_templates['task_create_connection_template']   
        sql = sql.replace('_NEXT_TASK_UUID', '\''+ task_exec_id +'\'').replace('_TASK_UUID', '\''+ prev_task_exec_id +'\'')
#        print(sql)

        # Execute the SQL command in the database
        resp = execSql(sql)
        if resp and 'status' in resp:
            if not resp.get('status'):
                return False
        else:
            return False

    # Compose the SQL command using the template for assigning tags to the new task execution 
    if tags:
        for key, value in tags.items():
            sql = utils.sql_workflow_execution_templates['task_insert_tags_template']   
            sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'').replace('_KEY', '\''+  key +'\'').replace('_VALUE', '\''+  value +'\'')
#            print(sql)

            # Execute the SQL command in the database
            resp = execSql(sql)
            if resp and 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True


def task_execution_update(task_exec_id, state, end_date=None):
    """Updates metadata regarding a task execution in the database.

    Args:
        task_exec_id: UUID of a task execution.
        state: Current state of this task execution.
        end_date: Timestamp marking the end of this task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for updating a task execution
    sql = utils.sql_workflow_execution_templates['task_update_template']   
    sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'').replace('_STATE', '\''+ state +'\'')
    if end_date:
        sql = sql.replace('_END_TIMESTAMP', '\''+ end_date +'\'')
    else:
        sql = sql.replace('_END_TIMESTAMP', 'NULL')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)

    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True


def task_execution_delete(task_exec_id):
    """Deletes all metadata regarding a task execution from the database. CAUTION! This also includes all tags, parameters, and metrics associated with this task execution.

    Args:
        task_exec_id: UUID of a task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for deleting a task execution
    sql = utils.sql_workflow_execution_templates['task_delete_template']   
    sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)

    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True



def task_execution_insert_log(task_exec_id, log):
    """Records the log of a task execution in the database.

    Args:
        task_exec_id: UUID of the task execution.
        log: Text with the compiled logs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for inserting the log under tag "log" for this task execution 
    sql = utils.sql_workflow_execution_templates['task_insert_tags_template']   
    sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'').replace('_KEY', '\'log\'').replace('_VALUE', '\''+  log +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)
    if resp and 'status' in resp:
        if not resp.get('status'):
            return False
    else:
        return False

    return True



def task_execution_insert_input(task_exec_id, resource_ids):
    """Records in the database that the given dataset id was used as input in the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        resource_ids: Array of UUIDs of the dataset(s) (CKAN resources) used as input in this task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording input datasets
    for res_id in resource_ids:
        sql = utils.sql_workflow_execution_templates['task_insert_input_dataset_template']   
        sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'').replace('_RESOURCE_ID', '\''+ res_id +'\'')
#        print(sql)

        # Execute the SQL command in the database
        resp = execSql(sql)
        if resp and 'status' in resp:
            if not resp.get('status'):
                return False
        else:
            return False

    return True


def task_execution_insert_output(task_exec_id, resource_ids):
    """Records in the database that the given dataset id was issued as output from the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        resource_ids: Array of UUIDs of the dataset(s) (i.e.,CKAN resources) issued as output from this task execution.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording output datasets
    for res_id in resource_ids:
        sql = utils.sql_workflow_execution_templates['task_insert_output_dataset_template']   
        sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'').replace('_RESOURCE_ID', '\''+ res_id +'\'')
#        print(sql)

        # Execute the SQL command in the database
        resp = execSql(sql)
        if resp and 'status' in resp:
            if not resp.get('status'):
                return False
        else:
            return False

    return True


def task_execution_insert_parameters(task_exec_id, parameters):
    """Records in the database that the user-specified parameters for the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        parameters: A JSON dictionary with the task execution parametrization as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording parameters of a task execution 
    if parameters:
        for key, value in parameters.items():
            sql = utils.sql_workflow_execution_templates['task_insert_parameters_template']   
            sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'').replace('_KEY', '\''+  key +'\'').replace('_VALUE', '\''+  value +'\'')
#            print(sql)

            # Execute the SQL command in the database
            resp = execSql(sql)
            if 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True


def task_execution_insert_metrics(task_exec_id, metrics):
    """Records in the database that the metrics collected for the given task execution.

    Args:
        task_exec_id: UUID of the task execution.
        metrics: A JSON dictionary with the task execution metrics as (key, value) pairs.

    Returns:
        A boolean: True, if the statement executed successfully; otherwise, False.
    """

    # Compose the SQL command using the template for recording metrics about a task execution 
    if metrics:
        for key, value in metrics.items():
            sql = utils.sql_workflow_execution_templates['task_insert_metrics_template']   
            sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'').replace('_KEY', '\''+  key +'\'').replace('_VALUE', '\''+  value +'\'')
#            print(sql)

            # Execute the SQL command in the database
            resp = execSql(sql)
            if 'status' in resp:
                if not resp.get('status'):
                    return False
            else:
                return False

    return True



def task_execution_read(task_exec_id):
    """Returns metadata recorded in the database about the given task execution. User-specified tags are included in the returned response.

    Args:
        task_exec_id: UUID of the task execution.

    Returns:
        A JSON with the task execution metadata.
    """

    # Compose the SQL command using the template for reading metadata about a task execution
    sql = utils.sql_workflow_execution_templates['task_read_template']   
    sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)

    if resp and len(resp)>0:
        task_specs = resp[0]  # List should contain specification of a single task execution (unique UUID)
        # Also include any user-specified tags in the response
        task_specs['tags'] = task_execution_tags_read(task_exec_id)
        return task_specs
    else:
        return None


def task_execution_tags_read(task_exec_id):
    """Returns tags recorded as (key, value) pairs in the database about the given task execution.

    Args:
        task_exec_id: UUID of the task execution.

    Returns:
        A JSON dictionary with the task execution tags.
    """

    # Compose the SQL command using the template for reading tags about a task execution
    sql = utils.sql_workflow_execution_templates['task_read_tags_template']   
    sql = sql.replace('_TASK_UUID', '\''+ task_exec_id +'\'')
#    print(sql)

    # Execute the SQL command in the database
    resp = execSql(sql)

    if resp and len(resp)>0:
        tag_dict = {tag['key']: tag['value'] for tag in resp}
        return tag_dict
    else:
        return None


############################## TASK OPERATIONS ################################

@app.route('/api/v1/task/execution/create', methods=['POST'])
@app.input(schema.Task_Input, location='json', example={"workflow_exec_id": "24a976c4-fd84-47ef-92cc-5d5582bcaf41",
                                                        "docker_image": "alzeakis/pytokenjoin:v3",
                                                       "input": [  "0059004a-67b8-4445-b9d6-5b0475784c49",
                                                                   "2350a24b-87af-4505-aafb-72a15e0c118c"],
                                                       "parameters": {
                                                           "col_id_left": 1,
                                                           "col_text_left": 2,
                                                           "separator_left": " ",
                                                           "col_id_right": 0,
                                                           "col_text_right": 1,
                                                           "separator_right": " ",
                                                           "k": 1,
                                                           "delta_alg": "1",
                                                           "output_file": "out.csv",
                                                           "method": "knn",
                                                           "similarity": "jaccard",
                                                           "foreign": "foreign"
                                                       },
                                                       "tags": {}})
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_task_execution_create(json_data):
    """Create a Task Execution that will run a docker image with the provided
    parameters.

    Args:
        data: A JSON with the ID of the Workflow Execution, the docker image to run
        and the corresponding input to the tool.

    Returns:
        A JSON with the Minio response to the uploading request.
    """
    
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/task/execution/create -d '{"workflow_exec_id": "24a976c4-fd84-47ef-92cc-5d5582bcaf41", "docker_image": "alzeakis/pytokenjoin:v3", "input": [  "0059004a-67b8-4445-b9d6-5b0475784c49", "2350a24b-87af-4505-aafb-72a15e0c118c"],"parameters": {"col_id_left": 1, "col_text_left": 2, "separator_left": " ", "col_id_right": 0, "col_text_right": 1, "separator_right": " ", "k": 1, "delta_alg": "1", "output_file": "out.csv", "method": "knn", "similarity": "jaccard", "foreign": "foreign" }, "tags": {}}'

    config = current_app.config['settings']
    workflow_exec_id = json_data['workflow_exec_id']
    docker_image = json_data['docker_image']
    # input_json = json_data['input_json']
    input = json_data['input']
    parameters = json_data['parameters']
    tags = json_data['tags']

    try :
        #### CHECK WORKFLOW EXECUTION STATE
        # status = check_workflow_status(workflow_exec_id)
        state = workflow_execution_read(workflow_exec_id)['state']
        if state != 'running':
            return jsonify({'success': False, 'message': 'This workflow no longer accepts tasks'}), 500 
        
        #### GET FILE PATHS
        #TODO: REMOVE FUNCTION
        input_paths = []
        
        # url = request.base_url + 'api/v1/artifact'
        url = request.base_url.replace('task/execution/create', 'artifact')
        # res_ids = input_json.get('input', [])
        res_ids = input
        for res_id in res_ids:
            response = requests.get(url, params= {'id': res_id}, headers=request.headers)
            if response.status_code == 200:
                j = response.json()
                print(j)
                if j['success']: 
                    input_paths.append(j['result']['path'])
                else:
                    return jsonify({'success': False, 'message': f'This resource {res_id} cannot be fetched by CKAN'}), 500 
            else:
                return jsonify({'success': False, 'message': f'This resource {res_id} cannot be fetched by CKAN'}), 500 
        
        #### TOOL INVOKATION
        task_exec_id = str(uuid.uuid4())
        logdir = os.getcwd()+"/logs/"
        in_file, out_file = task_exec_id+"_input.json", task_exec_id+"_output.json"
        with open(logdir+in_file, "w") as o:
            input_json = {'input': input_paths,
                          'parameters': parameters,
                          "minio": {
                              "endpoint_url": config['MINIO_ENDPOINT'],
                              "id": config['MINIO_ACCESS_KEY'],
                              "key": config['MINIO_SECRET_KEY'],
                              "bucket": config['MINIO_BUCKET']
                              }   
                }
            o.write(json.dumps(input_json, indent=4))
            
        client = docker.from_env()
        container = client.containers.run(
            docker_image,  # Image name
            [in_file, out_file],        # Command and arguments
            volumes={logdir: {'bind': '/app/logs/', 'mode': 'rw'}},
            detach=True
        )
        # Store the container ID into a variable
        # task_exec_id = container.id
        tags['container_id'] = container.id
        print(tags)
        
        #### UPDATE KG
        start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state = 'running'
        
        response = task_execution_create(task_exec_id, workflow_exec_id, start_date, state, tags)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500
        # response = task_execution_insert_input(task_exec_id, input_json.get('input', []))
        response = task_execution_insert_input(task_exec_id, input)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500        
        # response = task_execution_insert_parameters(task_exec_id, input_json.get('parameters', {}))
        parameters = {k: str(v) for k, v in parameters.items()}
        response = task_execution_insert_parameters(task_exec_id, parameters)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500

        
        return jsonify({'success': True, 'task_exec_id': task_exec_id}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500



@app.route('/api/v1/task/execution/track', methods=['POST'])
@app.input(schema.Task_Track, location='json', example={"task_exec_id": "4a142419-2342-4495-bfa3-9b4b3c2cad2a",
                                                        'package_id': '0f55380a-78ff-413e-9a99-3d214766f563'})
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_task_execution_track(json_data):
    """Track the execution of a specific task and if it is done, it returns
    the metrics and output files in the Data Catalog.

    Args:
        id: The unique identifier of the Task Exection.
        package_id: The unique identifier of the Package ID in the Data Catalog,
        under which it will store the output files.

    Returns:
        A JSON with the task execution metadata, the metrics and the ids of the 
        outputfiles in the Data Catalog.
    """
    
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/task/execution/track -d '{"task_exec_id": "4a142419-2342-4495-bfa3-9b4b3c2cad2a", 'package_id': '0f55380a-78ff-413e-9a99-3d214766f563'}'

    task_exec_id = json_data['task_exec_id']
    package_id = json_data['package_id']
    
    try :
        #### GET METADATA FROM KG
        metadata = task_execution_read(task_exec_id)
        container_id = metadata['tags']['container_id']
        
        #### GET STATUS FROM DOCKER
        client = docker.from_env()
        try:
            container = client.containers.get(container_id)
            state = container.status
        except docker.errors.NotFound:
            return jsonify({'success': False, 'message': "Container not found"}), 500

        if state == 'exited':
            exit_code = container.attrs['State']['ExitCode']
            if exit_code == 0:
                state = 'succeeded'
            else:
                state = 'failed'
        
        metadata['state'] = state

        output_json = {}
        if state == 'failed' or state == 'succeeded':
            logdir = os.getcwd()+"/logs/"
            out_file = logdir+task_exec_id+"_output.json"
            with open(out_file) as o:
                output_json = json.load(o)
    
            #### UPDATE TASK EXECUTION
            end_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            response = task_execution_update(task_exec_id, state, end_date)
            if not response:
                return jsonify({'success': False, 'message': 'Task 1 Execution could not be commited.'}), 500
            
            #### INSERT METRICS
            metrics = output_json.get('metrics', {})
            metrics = {k: str(v) for k, v in metrics.items()}
            response = task_execution_insert_metrics(task_exec_id, metrics)
            if not response:
                return jsonify({'success': False, 'message': 'Task 2 Execution could not be created.'}), 500
            
            #### INSERT LOG
            response = task_execution_insert_log(task_exec_id, output_json.get('message', ""))
            if not response:
                return jsonify({'success': False, 'message': 'Task 4 Execution could not be created.'}), 500
            
            #### INSERT FILES TO CATALOG
            if package_id is not None and package_id != '':
                #TODO: REplace this function
                output_resource_ids = []
                url = request.base_url
                url = url.replace('task/execution/track', 'artifact/publish')
                for file in output_json['output']:
                    ftype = file['path'].split('/')[-1].split(".")[-1].upper()
                    d = { "artifact_metadata":{
                                "url":file['path'],
                                'name': file['name'],
                                "description": file['name'] + f'({ datetime.now().strftime("%Y-%m-%d %H:%M:%S")})',
                                "format": ftype,
                                "resource_tags":["Artifact"]
                                },
                            "package_metadata":  {
                                "package_id": package_id
                                }
                        }
            
                    response = requests.post(url, json=d, headers=request.headers)
                    if response.status_code == 200:
                        j = response.json()
                        if j['success']:
                            output_resource_ids.append(j['result']['resource_id'])
                        else:
                            return jsonify({'success': False, 'message': 'Error in publishing in CKAN'}), 500 
                    else:
                        return jsonify({'success': False, 'message': 'Error in publishing in CKAN'}), 500 
                    
                #### INSERT OUTPUT FILES
                response = task_execution_insert_output(task_exec_id, output_resource_ids)
                if not response:
                    return jsonify({'success': False, 'message': 'Task 3 Execution could not be created.'}), 500
                
                return jsonify({'success': True, 'metadata': metadata,
                        'resource_ids': output_resource_ids,
                        'metrics': output_json.get('metrics', {})}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500  
    
    return jsonify({'success': True, 'metadata': metadata}), 200


@app.route('/api/v1/task/execution/delete', methods=['GET'])
@app.input(schema.Identifier, location='query', example="4a142419-2342-4495-bfa3-9b4b3c2cad2a")
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_task_execution_delete(query_data):
    """Delete the given Task Execution id.

    Args:
        id: The unique identifier of the Task Exection.

    Returns:
        A JSON with the corresponding message.
    """
    
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/delete?id=4a142419-2342-4495-bfa3-9b4b3c2cad2a

    # task_exec_id = request.args.id
    task_exec_id = query_data['id']
    try :
        response = task_execution_delete(task_exec_id)
        if not response:
            return jsonify({'success': True, 'message': f'The Task {task_exec_id} could not be deleted.'}), 500
        return jsonify({'success': True, 'message': f'The Task {task_exec_id} was deleted successfully'}), 200
    except Exception as e:
        return jsonify({'success': True, 'message': str(e)}), 500


################################ WORKFLOW OPERATIONS ##########################

@app.route('/api/v1/workflow/execution/create', methods=['POST'])
@app.input(schema.Workflow_Input, location='json', example={
                                                        #"workflow_id": "workflow_id", 
                                                        "tags": {}})
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_workflow_execution_create(json_data):
    """Create a Workflow Execution under a specific defined workflow.

    Args:
        data: A JSON with the ID of the Workflow and the tags to add.

    Returns:
        A JSON with the Workflow Execution ID.
    """
    
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/workflow/execution/create -d '{"tags": {}}'

    # workflow_id = json_data['workflow_id']
    tags = json_data['tags']

    try :
        #### UPDATE KG
        workflow_exec_id = str(uuid.uuid4())
        start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state = 'running'
        
        #TODO: Add workflow_id
        # response = workflow_execution_create(workflow_id, workflow_exec_id, start_date, state, tags)
        response = workflow_execution_create(workflow_exec_id, start_date, state, tags)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500
        
        return jsonify({'success': True, 'workflow_exec_id': workflow_exec_id}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/v1/workflow/execution/read', methods=['GET'])
@app.input(schema.Identifier, location='query', example="24a976c4-fd84-47ef-92cc-5d5582bcaf41")
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_workflow_execution_read(query_data):
    """Return the metadata of the given Workflow Execution id.

    Args:
        id: The unique identifier of the Workflow Exection.

    Returns:
        A JSON with the required metadata.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/execution/read?id=24a976c4-fd84-47ef-92cc-5d5582bcaf41

    # workflow_exec_id = request.args.id
    workflow_exec_id = query_data['id']

    try :
        #### GET METADATA FROM KG
        metadata = workflow_execution_read(workflow_exec_id)
        
        return jsonify({'success': True, 'metadata': metadata}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
    
    
@app.route('/api/v1/workflow/execution/commit', methods=['POST'])
@app.input(schema.Workflow_Commit, location='json', example={"workflow_exec_id": "24a976c4-fd84-47ef-92cc-5d5582bcaf41",
                                                             "state": "succeeded"})
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_workflow_execution_commit(json_data):
    """Store the results of the Workflow Execution.

    Args:
        data: A JSON with the id of the Worfklow Execution and the state of the task.

    Returns:
        A JSON with the result of the update.
    """
    
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/workflow/execution/commit -d '{"workflow_exec_id": "24a976c4-fd84-47ef-92cc-5d5582bcaf41", "state": "succeeded"}'

    workflow_exec_id = json_data['workflow_exec_id']
    state = json_data['state']

    try :
        #### UPDATE TASK EXECUTION
        end_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        response = workflow_execution_update(workflow_exec_id, state, end_date)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be commited.'}), 500
        
        return jsonify({'success': True }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500    


@app.route('/api/v1/workflow/execution/delete', methods=['GET'])
@app.input(schema.Identifier, location='query', example="24a976c4-fd84-47ef-92cc-5d5582bcaf41")
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_workflow_execution_delete(query_data):
    """Delete the given Workflow Execution id.

    Args:
        id: The unique identifier of the Worfklow Exection.

    Returns:
        A JSON with the corresponding message.
    """
    
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/execution/delete?id=24a976c4-fd84-47ef-92cc-5d5582bcaf41

    # workflow_exec_id = request.args.id
    workflow_exec_id = query_data['id']
    try :
        response = workflow_execution_delete(workflow_exec_id)
        if not response:
            return jsonify({'success': True, 'message': f'The Task {workflow_exec_id} could not be deleted.'}), 500
        return jsonify({'success': True, 'message': f'The Task {workflow_exec_id} was deleted successfully'}), 200            
    except Exception as e:
        return jsonify({'success': True, 'message': str(e)}), 500


###########################################################


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
        print("Usage: python data_api.py <config_file>")
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


