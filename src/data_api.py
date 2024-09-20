import flask
import requests
import json
import re
import sys
import psycopg2
import yaml
import pandas as pd
import uuid
import datetime
import os
import subprocess
import traceback
import urllib

from requests.models import Response

from psycopg2.extras import RealDictCursor
from flask import request, jsonify, current_app, redirect, url_for
from apiflask import APIFlask, HTTPTokenAuth
from apiflask.fields import Dict, Nested

from flask.json import JSONEncoder
from datetime import date, datetime

# Auxiliary custom functions & SQL query templates for ranking
import utils
import sql_utils

#from container_utils import create_container
import execution


# Input schemata for validating several API requests
import schema




#################### BLUEPRINT IMPORTS #####################
# Import the blueprints for the logical parts of the API

#### USERS BP ####
from routes.users import users_bp

#### CKAN BP ####



############################################################


# Create an instance of this API; by default, its OpenAPI-compliant specification will be generated under folder /specs
app = APIFlask(__name__, spec_path='/specs', docs_path ='/docs')
app.config.from_prefixed_env()



################## BLUEPRINT REGISTRATION ##################

# Blueprints are used to split the API into logical parts, 
# such as User Management, Catalog Management,
# Workflow/Execution management etc.

app.register_blueprint(users_bp, url_prefix='/api/v1/catalog')



############################################################



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
    
    response = {
        'help': request.base_url,
        'success': True,
        'result': {
            'message':'Prototype Data API for managing resources in STELAR Knowledge Lake Management System.',
            'OpenAPI specifications':request.base_url+'specs',
            'Swagger UI':request.base_url+'docs'
        }
    }

    return jsonify(response)

#    return '''<h1>STELAR Knowledge Lake Management System</h1><p>Prototype Data API for managing KLMS resources.</p><p>API specification is available <a href='/specs'>here</a>.<p>Interactive API documentation (Swagger UI) is available <a href='/docs'>here</a>.</p>'''



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

    # Pass an empty data frame to report the original SOLR scores; no facet specs need be added; no profiling attributes involved
    return utils.assign_scores(response, pd.DataFrame(), {}, {}, [])  



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

    if request.headers:
        if request.headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(request.headers['Api-Token'])
        else:
            response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}
        return jsonify(response)

    # Check if an ID (name) for a dataset was provided as argument
    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the requested resource.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_show?id='+id, headers=resource_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

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
    response = requests.post(config['CKAN_API']+'resource_search?query='+q, headers=config.package_headers)  # auth=HTTPBasicAuth(config.username, config.password))

    return response.json()


@app.route('/api/v1/resource/profile', methods=['GET'])
@app.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Search Operations'])
def api_resource_profile(query_data):
    """Get the JSON profile available for a resource that is accessible by the user.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON object with all profiling information as maintained in CKAN for the specified resource.
    """

    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/resource/download?id=6dc36257-abb6-45b5-b3bb-5f94160fc2ee

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

    # Check if an ID (name) for a resource was provided as argument
    if 'id' in query_data:
        id = query_data['id']
    else:
        response = {'success':False, 'help': request.url+'?id=', 'error':{'__type':'No specifications','name':['No identifier provided. Please specify the id of the requested resource.']}}
        return jsonify(response)

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_show?id='+id, headers=resource_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    if response.status_code == 200:
        json_response = response.json()
        if json_response['success']:
#        # IMPORTANT: If a firewall existing on the API server, the file cannot be downloaded from CKAN
#            url_profile = json_response['result']['url']
#            print(url_profile)
#            with urllib.request.urlopen(url_profile) as url:
#                print(url)
#                data = json.load(url)
#                return data
        # ALTERNATIVE: Get the original path to the file when uploaded to CKAN 
            path_profile = json_response['result']['file']
            print(path_profile)
            with open(path_profile) as json_file:
                data = json.load(json_file)
                return jsonify(data)

    return None


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



# NO LONGER USED: Mlflow schema deprecated
#@app.route('/api/v1/workflow/tasks', methods=['GET'])
#@app.input(schema.Identifier, location='query', example="id=UC_A3")
#@app.output(schema.ResponseOK, status_code=200)
#@app.doc(tags=['Search Operations'])
#def api_workflow_tasks(query_data):
#    """Submit a request to the Knowledge Graph to retrieve the tasks executed in a workflow.
#
#    Args:
#        id: The tag value under key "name" assigned to workflow executions.
#
#    Returns:
#        A JSON with the list of task executions included in the given workflow name.
#    """
#
#    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/workflow/tasks?id=UC_A3
#
#    config = current_app.config['settings']
#
#    if 'id' in query_data:
#        id = query_data['id']
#    else:
#        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No identifier provided for the workflow in the Knowledge Graph. Please specify a valid identifier for the workflow.']}}
#        return jsonify(response)
#
#    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
#    # Formulate the SPARQL query with the given identifier
#    sparql = utils.format_sparql_filter('workflow_tasks_template', id)
#    print(sparql)
#    # Make a POST request to the Ontop API with the given query
#    # IMPORTANT! NO authentication required by public SPARQL endpoints
#    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)
#
#    return jsonify(json.loads(response.text))


# NO LONGER USED: Mlflow schema deprecated
#@app.route('/api/v1/task/executions', methods=['GET'])
#@app.input(schema.Identifier, location='query', example="id=entity_extraction")
#@app.output(schema.ResponseOK, status_code=200)
#@app.doc(tags=['Search Operations'])
#def api_task_executions(query_data):
#    """Submit a request to the Knowledge Graph to retrieve all executions tagged with the name of the given task.
#
#    Args:
#        id: The tag value under key "name" assigned to task executions.
#
#    Returns:
#        A JSON with the details of the task executions.
#    """
#
#    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/executions?id=entity_extraction
#
#    config = current_app.config['settings']
#
#    if 'id' in query_data:
#        id = query_data['id']
#    else:
#        response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No identifier provided for the task execution in the Knowledge Graph. Please specify a valid identifier for the task execution.']}}
#        return jsonify(response)
#
#    sparql_headers = {'Content-Type':'application/sparql-query', 'Accept':'application/json'}
#    # Formulate the SPARQL query with the given identifier
#    sparql = utils.format_sparql_filter('task_executions_template', id)
#    print(sparql)
#    # Make a POST request to the Ontop API with the given query
#    # IMPORTANT! NO authentication required by public SPARQL endpoints
#    response = requests.post(config['SPARQL_ENDPOINT'], headers=sparql_headers, data=sparql)
#
#    return jsonify(json.loads(response.text))


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
        actual_profile_attributes = set(specs['filter_preferences'].keys()).union(set(specs['rank_preferences'].keys()))
#        print("INITIAL PROFILE ATTRIBUTES", actual_profile_attributes)

        # STAGE #1: text-based keyword search targets SOLR (search engine for CKAN)
        if 'keywords' in specs:   # CASE #1(a): new keyword search
            q = '?q=' + ",".join("'{0}'".format(kw) for kw in specs['keywords'])   
#            print(q)
            # Submit a preliminary search request to CKAN to find packages qualifying to the specified keywords
            # Also include private datasets of the user's organization in the results
            resp_basic = requests.get(config['CKAN_API']+'package_search'+q+'&include_private=True&fl=*,score&rows='+str(config['RANK_MAX_TOPK'])+'&start=0', headers=package_headers)
            if resp_basic.status_code == 200:
                json_resp_basic = resp_basic.json()
                #FIXME: Handle large number of returned id's -> not efficient when filtering with SQL
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
                results = utils.execSql(sql)
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
                results = utils.execSql(sql)
#                print("FIELDS", key, len(results), len(ids))
                # Fill any missing scores in the partial list for this facet
                for id in ids:
                    if not id in [d['id'] for d in results if 'id' in d]:
                        results.append({'id':id, 'score':0.0})
                dict_df_facet_scores[key] = utils.read_list_json(results)
#                # In case a 'value' column (concerning PROFILING) is returned in results, remember to include its values in the final results
#                if 'value' in dict_df_facet_scores[key].columns:
#                    profile_attributes.append(key)
#                    print(key)


            # Fetch values for all profiling metadata elements by submitting a SELECT query to the PostgreSQL database for the collected ids
            # IMPORTANT! PostgreSQL credentials are required to complete this request
            actual_profile_attributes = actual_profile_attributes.intersection(utils.profile_attributes)
#            print("ACTUAL PROFILE ATTRIBUTES", actual_profile_attributes)
            for key in list(actual_profile_attributes):  #list(set(utils.profile_attributes) - set(rank_sql_commands.keys())):
                sql = utils.identifiers_sql_filter_template.replace('_VIEW',utils.sql_views[key]).replace('_IDS',sql_id_filter) 
#                print(key, '->', sql)
                results = utils.execSql(sql)
                print("PROFILING", key, len(results), len(ids))
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
    return utils.assign_scores(response, agg_scores, dict_df_facet_scores, specs['rank_preferences'], list(actual_profile_attributes))


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
                    utils.execSql(sql)
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

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/profile/publish -d '{"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": ["Profile","Computed with STELAR Profiler"]}}'

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
                utils.execSql(sql)
            return response.json()
    elif resource_metadata.get('url') != None:
        # Make a POST request to the CKAN API to link the file from the specified URL
        response = requests.post(config['CKAN_API']+'resource_create', data=resource_metadata, headers=resource_headers)
        return response.json()
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No profile metadata were associated with this dataset in the Catalog. Please provide a path or a publicly accessible URL where this file is available.']}}
        return response.json()


########### TESTING ONLY #################################
@app.route('/api/v1/profile/store', methods=['POST'])
@app.input(schema.Profile, location='json', example={"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_type": "Raster", "resource_tags": ["Profile","Computed with STELAR Profiler"]}})
@app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Publishing Operations'])
@app.auth_required(auth)
def api_profile_store(json_data):
    """Store profile information directly in the PostgreSQL database. The respective resource must correspond to an existing dataset in CKAN. The user will become the publisher of this profile.

    Args:
        data: A JSON with all metadata information provided by the publisher about the profile. Must include the profile information in a nested JSON.

    Returns:
        A JSON with the response to the storage request.
    """

    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/profile/publish -d '{"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": ["Profile","Computed with STELAR Profiler"]}}'

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
            # Extract the profile data and the CKAN resource identifier (will be part of primary keys in the database)
            profile = metadata['profile_metadata']['profile_data']
            resource_id = metadata['profile_metadata']['resource_id']
            # Distinguish handling according to Profile type
            sql_commands = utils.extractProfileProperties(resource_id, profile)
            for sql in sql_commands:
#                print(sql)
                utils.execSql(sql)
            response = {'success':True, 'help': request.url, 'result':''}
            return jsonify(response)
        else:
            response = {'success':False, 'help': request.url+'?q=', 'error':{'__type':'No specifications','name':['No metadata provided for publishing this profile in the Catalog. Please specify metadata for the profile you wish to upload.']}}
            return jsonify(response)
    else:
        response = {'success':False, 'help': request.url, 'error':{'__type':'No specifications','name':['No metadata provided for publishing this profile in the Catalog. Please specify metadata for the profile you wish to upload.']}}
        return jsonify(response)


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
            utils.execSql(sql)

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
            package_metadata['tags'] += ['Workflow']
            package_metadata['tags'] = utils.handle_keywords(package_metadata['tags'])
            # package_metadata['type'] = 'workflow'   # Must specify that this is not a dataset, but a workflow
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


def api_artifact_publish(json_data, headers):
    """Publish an artifact created by a workflow execution.

    If a package id is provided, associate the artifact (with its URL) to this package in CKAN. Otherwise, create a new package in CKAN to make this association. The user will become the publisher of this resource.

    Args:
        data: A JSON with all metadata information provided by the publisher about the new artifact.

    Returns:
        A JSON with the CKAN response to the publishing request.
    """

    config = current_app.config['settings']

    if headers:
        if headers.get('Api-Token') != None:
            package_headers, resource_headers = utils.create_CKAN_headers(headers['Api-Token'])
        else:
            return {'success':False, 'error':{'__type':'Authorization Error','name':['No API_TOKEN specified. Please specify a valid API_TOKEN in the headers of your request.']}}
    else:
        return {'success':False,  'error':{'__type':'Authorization Error','name':['No headers specified. Please specify headers for your request, including a valid API TOKEN.']}}

    specs = json_data

    if specs.get('artifact_metadata') != None:
        artifact_metadata = specs['artifact_metadata']
    else:
        return {'success':False, 'error':{'__type':'No specifications','name':['No metadata provided for publishing this artifact in the Catalog. Please specify metadata for the artifact you wish to publish.']}}

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
            response = {'success':True,  'result':result} 
            return response
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

            response = {'success':success, 'result':result}     
            return response



def api_artifact_id(resource_id, headers):
    """Get the file path of an artifact. 

    Provides the path to the file (URL, S3 bucket or local file) where an artifact (stored as a resource) is available. User may need credentials to access this file.

    Args:
        id: The unique identifier of the resource as listed in CKAN.

    Returns:
        A JSON with the file path for the specified resource as maintained in CKAN.
    """

    config = current_app.config['settings']

    if headers and headers.get('Api-Token') != None:
        package_headers, resource_headers = utils.create_CKAN_headers(headers['Api-Token'])
    else:
        return None

    # Make a GET request to the CKAN API with the parameters
    # IMPORTANT! CKAN requires NO authentication for GET requests
    response = requests.get(config['CKAN_API']+'resource_show?id='+resource_id, headers=package_headers)  #auth=HTTPBasicAuth(config.username, config.password))  

    # Get the path of this artifact 
    if response.status_code == 200:
        return response.json()['result']['url']
    else:
        return None


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
                                                       'package_id': '0f55380a-78ff-413e-9a99-3d214766f563',
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
    
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/task/execution/create -d '{"workflow_exec_id": "24a976c4-fd84-47ef-92cc-5d5582bcaf41", "docker_image": "alzeakis/pytokenjoin:v3", "input": [  "0059004a-67b8-4445-b9d6-5b0475784c49", "2350a24b-87af-4505-aafb-72a15e0c118c"],"parameters": {"col_id_left": 1, "col_text_left": 2, "separator_left": " ", "col_id_right": 0, "col_text_right": 1, "separator_right": " ", "k": 1, "delta_alg": "1", "output_file": "out.csv", "method": "knn", "similarity": "jaccard", "foreign": "foreign" }, 'package_id': '0f55380a-78ff-413e-9a99-3d214766f563', "tags": {}}'

    config = current_app.config['settings']
    workflow_exec_id = json_data['workflow_exec_id']
    docker_image = json_data['docker_image']
    # input_json = json_data['input_json']
    input = json_data['input']
    parameters = json_data['parameters']
    package_id = json_data['package_id']
    tags = json_data['tags']

    try :
        #### CHECK WORKFLOW EXECUTION STATE
        # status = check_workflow_status(workflow_exec_id)
        state = sql_utils.workflow_execution_read(workflow_exec_id)['state']
        if state != 'running':
            return jsonify({'success': False, 'message': 'This workflow no longer accepts tasks'}), 500 
        
        
        
        
        # #### GET FILE PATHS
        # input_paths = []
        # res_ids = input
        # for res_id in res_ids:
        #     path = api_artifact_id (res_id, headers=request.headers)
        #     if path is None:
        #         return jsonify({'success': False, 'message': f'This resource {res_id} cannot be fetched by CKAN'}), 500 
        #     input_paths.append(path)
            
            
            
            
        
        #### UPDATE KG
        start_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state = 'running'
        task_exec_id = str(uuid.uuid4())
        
        response = sql_utils.task_execution_create(task_exec_id, workflow_exec_id, start_date, state, tags)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500
        # response = task_execution_insert_input(task_exec_id, input_json.get('input', []))
        response = sql_utils.task_execution_insert_input(task_exec_id, input)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500        
        # response = task_execution_insert_parameters(task_exec_id, input_json.get('parameters', {}))
        parameters = {k: str(v) for k, v in parameters.items()}
        response = sql_utils.task_execution_insert_parameters(task_exec_id, parameters)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500
        
        
        #### TOOL INVOKATION
        # logdir = os.getcwd()+"/logs/"
        # in_file, out_file = task_exec_id+"_input.json", task_exec_id+"_output.json"
        # with open(logdir+in_file, "w") as o:
        #     input_json = {'input': input_paths,
        #                   'parameters': parameters,
        #                   "minio": {
        #                       "endpoint_url": config['MINIO_ENDPOINT'],
        #                       "id": config['MINIO_ACCESS_KEY'],
        #                       "key": config['MINIO_SECRET_KEY'],
        #                       "bucket": config['MINIO_BUCKET']
        #                       }   
        #         }
        #     o.write(json.dumps(input_json, indent=4))
            

        
        #### UPDATE KG
        
        # Store the container ID into a variable
        #tags['container_id'] = create_container(docker_image,
        #                                        request.headers.get('Api-Token'),
        #                                        config['API_URL'], 
        #                                        task_exec_id)

        engine = execution.exec_engine()
        tags['container_id'] = engine.create_task(docker_image, request.headers.get('Api-Token'), task_exec_id)

        tags['package_id'] = package_id
        response = sql_utils.task_execution_update(task_exec_id, state, tags=tags)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Execution could not be created.'}), 500


        
        return jsonify({'success': True, 'task_exec_id': task_exec_id}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500



@app.route('/api/v1/task/execution/input_json', methods=['GET'])
@app.input(schema.Identifier, location='query', example="24a976c4-fd84-47ef-92cc-5d5582bcaf41")
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_task_execution_input_json(query_data):
    """Return the input json of the specific Task Execution.

    Args:
        id: The unique identifier of the Task Exection.

    Returns:
        A JSON with the input fields.
    """
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/input_json?id=24a976c4-fd84-47ef-92cc-5d5582bcaf41

    task_exec_id = query_data['id']
    
    config = current_app.config['settings']
    # input = json_data['input']
    input = sql_utils.task_execution_input_read(task_exec_id)
    print(input)
    # parameters = json_data['parameters']
    parameters = sql_utils.task_execution_parameters_read(task_exec_id)

    try :
        #### GET FILE PATHS
        input_paths = []
        res_ids = input
        for res_id in res_ids:
            path = api_artifact_id (res_id, headers=request.headers)
            if path is None:
                return jsonify({'success': False, 'message': f'This resource {res_id} cannot be fetched by CKAN'}), 500 
            input_paths.append(path)
        
        input_json = {'input': input_paths,
                      'parameters': parameters,
                      "minio": {
                          "endpoint_url": config['MINIO_ENDPOINT'],
                          "id": config['MINIO_ACCESS_KEY'],
                          "key": config['MINIO_SECRET_KEY'],
                          "bucket": config['MINIO_BUCKET']
                          }   
        }
        

        
        return jsonify({'success': True, 'result': input_json}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500



@app.route('/api/v1/task/execution/output_json', methods=['POST'])
@app.input(schema.Task_Output, location='json', example={"task_exec_id": "4a142419-2342-4495-bfa3-9b4b3c2cad2a",
                                                        "output_json": {
                                                                "message": "Tool executed successfully!",
                                                                "output": [{
                                                                    "path": "s3://XXXXXXXXX-bucket/2824af95-1467-4b0b-b12a-21eba4c3ac0f.csv",
                                                                    "name": "List of joined entities"
                                                                    }
                                                                ],
                                                                "metrics": {
                                                                    "metric": 0.90,
                                                                },
                                                                "status": 200
                                                            }})
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_task_execution_output_json(json_data):
    """Receives the output json of a task execution, it marks it as done, it stores
    all the information to the KG and it returns the metrics and output files 
    in the Data Catalog.

    Args:
        id: The unique identifier of the Task Exection.
        output_json: The json that the tool has produced.

    Returns:
        A JSON with the task execution metadata, the metrics and the ids of the 
        outputfiles in the Data Catalog.
    """
    
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/task/execution/track -d '{"task_exec_id": "4a142419-2342-4495-bfa3-9b4b3c2cad2a", "output_json": {"message": "Tool executed successfully!", "output": [{ "path": "s3://XXXXXXXXX-bucket/2824af95-1467-4b0b-b12a-21eba4c3ac0f.csv","name": "List of joined entities"}], "metrics": {"metric": 0.90},"status": 200}}'

    task_exec_id = json_data['task_exec_id']
    output_json = json_data['output_json']
    print(output_json)
    
    try :
        #### GET METADATA FROM KG
        metadata = sql_utils.task_execution_read(task_exec_id)
        container_id = metadata['tags']['container_id']
        package_id = metadata['tags']['package_id']
        
        print(task_exec_id)
        print(container_id)
        print(metadata)
        
        # #### GET STATUS FROM DOCKER
        # client = docker.from_env()
        # try:
        #     container = client.containers.get(container_id)
        #     state = container.status
        # except docker.errors.NotFound:
        #     return jsonify({'success': False, 'message': "Container not found"}), 500

        # print(state)
        # if state == 'exited':
        #     exit_code = container.attrs['State']['ExitCode']
        #     if exit_code == 0:
        #         state = 'succeeded'
        #     else:
        #         state = 'failed'
        
        if output_json['status'] == 200:
            state = 'succeeded'
        else:
            state = 'failed'
        
        metadata['state'] = state

        # output_json = {}
        # if state == 'failed' or state == 'succeeded':
            # logdir = os.getcwd()+"/logs/"
            # out_file = logdir+task_exec_id+"_output.json"
            # with open(out_file) as o:
            #     output_json = json.load(o)
    
        #### UPDATE TASK EXECUTION
        end_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        response = sql_utils.task_execution_update(task_exec_id, state, end_date)
        if not response:
            return jsonify({'success': False, 'message': 'Task Execution could not be commited.'}), 500
        
        #### INSERT METRICS
        metrics = output_json.get('metrics', {})
        metrics = {k: str(v) for k, v in metrics.items()}
        response = sql_utils.task_execution_insert_metrics(task_exec_id, metrics)
        if not response:
            return jsonify({'success': False, 'message': 'Task Execution could not be commited.'}), 500
        
        #### INSERT LOG
        response = sql_utils.task_execution_insert_log(task_exec_id, output_json.get('message', ""))
        if not response:
            return jsonify({'success': False, 'message': 'Task Execution could not be commited.'}), 500
        
        #### INSERT FILES TO CATALOG
        output_resource_ids = []
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
    
            response = api_artifact_publish(d, headers=request.headers)
            print(response)
            if response['success']:
                output_resource_ids.append(response['result']['resource_id'])
            else:
                return jsonify({'success': False, 'message': 'Error in publishing in CKAN'}), 500 
            
        #### INSERT OUTPUT FILES
        response = sql_utils.task_execution_insert_output(task_exec_id, output_resource_ids)
        if not response:
            return jsonify({'success': False, 'message': 'Task Execution could not be commited.'}), 500
        
        return jsonify({'success': True, 'resource_ids': output_resource_ids,
                        'metrics': metrics}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': traceback.format_exc()}), 500  
    
    # return jsonify({'success': True, 'metadata': metadata}), 200
    return jsonify({'success': True, 'resource_ids': [], 'metrics': {}}), 200




@app.route('/api/v1/task/execution/read', methods=['GET'])
@app.input(schema.Identifier, location='query', example="24a976c4-fd84-47ef-92cc-5d5582bcaf41")
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_task_execution_read(query_data):
    """Return the metadata of the task execution.

    Args:
        id: The unique identifier of the Task Exection.

    Returns:
        A JSON with the task execution metadata.
    """
    
    #EXAMPLE: curl -X GET http://127.0.0.1:9055/api/v1/task/execution/read?id=24a976c4-fd84-47ef-92cc-5d5582bcaf41

    task_exec_id = query_data['id']
    
    try :
        #### GET METADATA FROM KG
        d = {}
        d['metadata'] = sql_utils.task_execution_read(task_exec_id)
        state = d['metadata']['state']
        if state != 'failed' and state != 'succeeded':
            return jsonify({'success': True, 'result': d}), 200    
        d['output'] = sql_utils.task_execution_output_read(task_exec_id)
        d['metrics'] = sql_utils.task_execution_metrics_read(task_exec_id)
            
        return jsonify({'success': True, 'result': d}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': traceback.format_exc()}), 500  
    


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
        response = sql_utils.task_execution_delete(task_exec_id)
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
        response = sql_utils.workflow_execution_create(workflow_exec_id, start_date, state, tags)
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
        metadata = sql_utils.workflow_execution_read(workflow_exec_id)
        
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
        response = sql_utils.workflow_execution_update(workflow_exec_id, state, end_date)
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
        response = sql_utils.workflow_execution_delete(workflow_exec_id)
        if not response:
            return jsonify({'success': True, 'message': f'The Task {workflow_exec_id} could not be deleted.'}), 500
        return jsonify({'success': True, 'message': f'The Task {workflow_exec_id} was deleted successfully'}), 200            
    except Exception as e:
        return jsonify({'success': True, 'message': str(e)}), 500
    
    
@app.route('/api/v1/workflow/statistics', methods=['POST'])
@app.input(schema.Workflow_Statistics, location='json', example={"workflow_tags": ["A3-4"],
                                                                 "metrics": ['food_tags', 'total_tags', 'f1_micro', 'f1_macro', 'f1_weighted'],
                                                                 "parameters": ['k', 'model']})
# @app.output(schema.ResponseOK, status_code=200)
@app.doc(tags=['Tracking Operations'])
@app.auth_required(auth)
def api_workflow_statistics(json_data):
    """Fetch statistics for each Worfklow Execution for a specific group of 
    workflow executions.

    Args:
        data: A JSON with the id of the Worfklow Execution and the state of the task.

    Returns:
        A JSON with the result of the update.
    """
    
    #EXAMPLE: curl -X POST -H 'Content-Type: application/json' -H 'Api-Token: XXXXXXXXX' http://127.0.0.1:9055/api/v1/workflow/statistics -d '{"workflow_tags": ["A3-4"], "metrics": ['food_tags', 'total_tags', 'f1_micro', 'f1_macro', 'f1_weighted'], "parameters": ['k', 'model']}'

    workflow_tags = json_data['workflow_tags']
    parameters = json_data['parameters']
    metrics = json_data['metrics']
    
    try :
        response = sql_utils.workflow_statistics(workflow_tags, parameters, metrics)
        if not response:
            return jsonify({'success': False, 'message': 'Workflow Statistics cannot not be returned.'}), 500
        return jsonify({'success': True, 'result': response }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500        


###########################################################


def json_config(config_file):
    """Load configuration settings for interacting with CKAN, Ontop, and the PostgreSQL database.

    Args:
        config_file: Path to a JSON file with the configuration settings.

    Returns:
        A dictionary with all configuration settings.
    """

    with open(config_file, 'r') as f:
        config_data = json.load(f)
    return config_data


def yaml_config(config_file):
    """Load configuration settings for interacting with CKAN, Ontop, and the PostgreSQL database.

    Args:
        config_file: Path to a YAML file with the configuration settings.

    Returns:
        A dictionary with all configuration settings.
    """

    with open(config_file, 'r') as f:
        config_data = yaml.safe_load(f)
    return config_data




# Deploy service at the specific host and port
def main(app, config_path):
    # Get configuration settings specified in YAML or JSON
    # config_path = 'config.yaml'  #sys.argv[1]
    app.config['settings'] = yaml_config(config_path)
    # app.config['settings'] = json_config(config_path)

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

    if 'execution' not in app.config['settings'] and 'EXECUTION_ENGINE' in os.environ:
        # Use environment var 'EXECUTION_ENGINE' to add entry to config
        app.config['settings']['execution'] = {
            'engine': os.environ['EXECUTION_ENGINE']
        }

    # The log level can be changed here
    # app.logger.setLevel('DEBUG')

    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_for=1, x_host=1, x_port=1, x_prefix=1)

    # Configure execution
    execution.configure(app.config["settings"])



# This entry point is used with 'flask run ...'
def create_app():
    main(app, 'config.yaml')
    return app
    
# This entry point is for the 'python src/data_api.py' startup
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python data_api.py <config_file>")
        sys.exit(1)

    # Do initialize the app
    main(app, sys.argv[1])
    
    # Deploy the API
    app.run(host=app.config['settings']['FLASK_RUN_HOST'],
            port=app.config['settings']['FLASK_RUN_PORT'],
            debug=app.config['settings']['FLASK_DEBUG'])

