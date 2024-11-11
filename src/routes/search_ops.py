from flask import request, jsonify, current_app
from apiflask import APIBlueprint, HTTPTokenAuth
import requests
import json
import sql_utils
import re
import uuid
import traceback
from routes.users import api_user_editor
from src.auth import auth, security_doc, policy_enforcer
from datetime import datetime
import xml.etree.ElementTree as ET
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor

from demo_t import get_demo_ckan_token


#from container_utils import create_container
import execution

# Auxiliary custom functions & SQL query templates for ranking
import utils

# Input schema for validating and structuring several API requests
import schema


search_ops_bp = APIBlueprint('search_ops_blueprint', __name__,tag='Searching Operations')


################################## SEARCH OPERATIONS ########################################

@search_ops_bp.route('/catalog/tags', methods=['GET'])
#@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/catalog/vocabularies', methods=['GET'])
#@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/catalog/all', methods=['GET'])
#@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/catalog', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="cf0c3c59-fc41-48c9-a529-6b9feff42991")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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

@search_ops_bp.route('/catalog/metadata/all', methods=['GET'])
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
@policy_enforcer(resource='catalog_items', scope='get_items', function_name='api_metadata_all_packages_function')
def api_metadata_all_packages():

    config = current_app.config['settings']

    package_list_url = f"{config['API_URL']}api/v1/catalog/all"
    package_metadata_url = f"{config['API_URL']}api/v1/catalog?id="


    # Fetch the list of IDs from the first endpoint
    response = requests.get(package_list_url)
    if response.status_code != 200:
        return jsonify({"error": "Failed to fetch package list"}), 500

    data = response.json()

    # Check if the response is successful and contains the result
    if not data.get("success", False) or "result" not in data:
        return jsonify({"error": "Invalid response from package list API"}), 500

    ids_list = data["result"]

    # Aggregate metadata for all the IDs
    all_metadata = []
    for package_id in ids_list:
        # Fetch metadata for each package using the second endpoint
        metadata_url = package_metadata_url + package_id
        metadata_response = requests.get(metadata_url)
        if metadata_response.status_code == 200:
            metadata_data = metadata_response.json()
            if metadata_data.get("success", False):
                # Append the result of each successful call
                all_metadata.append(metadata_data["result"])
            else:
                all_metadata.append({"error": f"Failed to fetch metadata for ID {package_id}"})
        else:
            all_metadata.append({"error": f"Failed to fetch metadata for ID {package_id}"})

    # Return all metadata in a single response
    return jsonify({"result": all_metadata, "success": True})

@search_ops_bp.route('/dataset/export_zenodo', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="cf0c3c59-fc41-48c9-a529-6b9feff42991")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/catalog/search', methods=['POST'])
@search_ops_bp.input(schema.Query, location='json', example={"q":{"Topic":"POI", "INSPIRE theme":"Location", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}})
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'], security=security_doc)
@auth.login_required
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


@search_ops_bp.route('/dataset/search', methods=['GET'])
@search_ops_bp.input(schema.ComplexFilter, location='query', example="q=Lakes&ext_bbox=20,35,30,42")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/resource', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/resource/search', methods=['GET'])
@search_ops_bp.input(schema.Filter, location='query', example="q=format:JSON")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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


@search_ops_bp.route('/resource/profile', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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

############### the search operations against the catalog ends in this section ####################


@search_ops_bp.route('/workflow/input/dataset', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="id=82aaa2df-be92-46ee-a36b-cc59122a5d5b")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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


@search_ops_bp.route('/workflow/output/dataset', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="id=9232eef6-5acf-4280-b3e9-38d6c8935d7d")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/workflow/input/resource', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="id=6b077882-bd24-480b-896b-d7e8431338e5")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/workflow/output/resource', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="id=50156c05-6150-494d-b372-77d859f768d2")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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
#@search_ops_bp.route('/workflow/tasks', methods=['GET'])
#@search_ops_bp.input(schema.Identifier, location='query', example="id=UC_A3")
#@search_ops_bp.output(schema.ResponseOK, status_code=200)
#@search_ops_bp.doc(tags=['Search Operations'])
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
#@search_ops_bp.route('/task/executions', methods=['GET'])
#@search_ops_bp.input(schema.Identifier, location='query', example="id=entity_extraction")
#@search_ops_bp.output(schema.ResponseOK, status_code=200)
#@search_ops_bp.doc(tags=['Search Operations'])
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


@search_ops_bp.route('/task/execution/input', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/task/execution/output', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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




@search_ops_bp.route('/task/execution/metrics', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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


@search_ops_bp.route('/task/execution/parameters', methods=['GET'])
@search_ops_bp.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'])
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



@search_ops_bp.route('/graph/search', methods=['POST']) #/kg/search
@search_ops_bp.input(schema.Filter, location='json', example={"q": "PREFIX dct: <http://purl.org/dc/terms/> SELECT ?uri ?title ?publisher WHERE { ?uri dct:title ?title . ?uri dct:publisher ?publisher . } LIMIT 5"})
#@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'], security=security_doc)
@auth.login_required
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

########################### these search operations are against the sql database ########################


@search_ops_bp.route('/catalog/sql', methods=['POST'])
@search_ops_bp.input(schema.Filter, location='json', example={"q": "SELECT * FROM public.package LIMIT 5"})
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'], security=security_doc)
@auth.login_required
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


@search_ops_bp.route('/catalog/facet/values', methods=['POST'])
@search_ops_bp.input(schema.Filter, location='json', example={"q": "format"})
@search_ops_bp.output(schema.ResponseOK, status_code=200)
@search_ops_bp.doc(tags=['Search Operations'], security=security_doc)
@auth.login_required
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