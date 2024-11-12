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

catalog_bp = APIBlueprint('catalog_blueprint', __name__,tag='Catalog Management')


##############################################################################
########################## MANAGE CATALOG RESOURCES ##########################
##############################################################################


@catalog_bp.route('/dataset/delete', methods=['POST'])
@catalog_bp.input(schema.Identifier, location='json', example={"id":"test_data_api_1"})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Catalog Management'], security=security_doc)
@auth.login_required
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


@catalog_bp.route('/dataset/unpublish', methods=['POST'])
@catalog_bp.input(schema.Identifier, location='json', example={"id":"test_data_api_1"})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Catalog Management'], security=security_doc)
@auth.login_required
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



@catalog_bp.route('/resource/delete', methods=['POST'])
@catalog_bp.input(schema.Identifier, location='json', example={"id":"aa2992aa-b589-463d-ae1e-8430d91206cb"})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Catalog Management'], security=security_doc)
@auth.login_required
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


############################### PUBLISHING OPERATIONS ############################

@catalog_bp.route('/dataset/publish', methods=['POST']) #/catalog/dataset/publish
@catalog_bp.input(schema.Dataset, location='json', example={"basic_metadata":{"title": "Test Data API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": ["STELAR","OpenStreetMap","Geospatial","Bavaria"]},"extra_metadata":{"INSPIRE theme":"Imagery", "theme": ["Earth Sciences", "Landuse", "http://eurovoc.europa.eu/4630"], "language": ["ca", "en", "es"], "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]},"temporal_start":"2023-01-31T11:33:54.132Z", "temporal_end":"2023-01-31T11:35:48.593Z"},"profile_metadata":{"url":"https://raw.githubusercontent.com/stelar-eu/data-profiler/main/examples/output/timeseries_profile.json", "name": "Time series profile in JSON", "description": "This is the profile of a time series in JSON format", "resource_type": "Tabular", "format": "JSON", "resource_tags": ["Profile", "Computed with STELAR Profiler"]}})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Publishing Operations'], security=security_doc)
@auth.login_required
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



@catalog_bp.route('/dataset/register', methods=['POST'])
@catalog_bp.input(schema.Package, location='json', example={"package_metadata": {"title": "Test Data API 1", "notes": "This dataset contains Points of Interest extracted from OpenStreetMap", "tags": [{"name": "STELAR"}, {"name": "OpenStreetMap"},{"name": "Geospatial"},{"name": "Berlin"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}],"name": "test_data_api_1","private": "false","version": "0.3","owner_org": "athenarc"}})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Publishing Operations'], security=security_doc)
@auth.login_required
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


@catalog_bp.route('/dataset/patch', methods=['POST'])
@catalog_bp.input(schema.Package, location='json', example={"package_metadata": {"id": "test_data_api_1", "tags": [{"name": "Patch"}],"extras": [{"key": "custom_tags","value": "http://www.w3.org/ns/dcat#Dataset"},{"key": "INSPIRE theme", "value": "Location"},{"key": "Topic", "value": "POI"}] }})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Publishing Operations'], security=security_doc)
@auth.login_required
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



@catalog_bp.route('/profile/publish', methods=['POST'])
@catalog_bp.input(schema.Profile, location='json', example={"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_type": "Raster", "resource_tags": ["Profile","Computed with STELAR Profiler"]}})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Publishing Operations'], security=security_doc)
@auth.login_required
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
@catalog_bp.route('/profile/store', methods=['POST'])
@catalog_bp.input(schema.Profile, location='json', example={"profile_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_type": "Raster", "resource_tags": ["Profile","Computed with STELAR Profiler"]}})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Publishing Operations'], security=security_doc)
@auth.login_required
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


@catalog_bp.route('/resource/upload', methods=['POST'])
@catalog_bp.input(schema.Resource, location='json', example={"resource_metadata": {"package_id": "test_data_api_1", "file":"/data/examples/single_field_LAI-2.json", "name": "LAI profile in JSON", "description": "This is the profile of the Leaf Area Index in JSON format", "format": "JSON", "resource_tags": ["Profile","Computed with STELAR Profiler"]}})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Publishing Operations'], security=security_doc)
@auth.login_required
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



@catalog_bp.route('/resource/link', methods=['POST'])
@catalog_bp.input(schema.Resource, location='json', example={"resource_metadata": {"package_id": "test_data_api_1", "url":"https://data.smartdublin.ie/dataset/09870e46-26a3-4dc2-b632-4d1fba5092f9/resource/40a718a8-cb99-468d-962b-af4fed4b0def/download/bleeperbike_map.geojson", "name": "Test GeoJSON resource", "description": "This is the test resource in GeoJSON format", "format": "GeoJSON", "resource_type": "Tabular", "resource_tags": ["Link to external resource", "Found in the Web"]}})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Publishing Operations'], security=security_doc)
@auth.login_required
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




@catalog_bp.route('/workflow/publish', methods=['POST'])
@catalog_bp.input(schema.Package, location='json', example={"package_metadata": {"title": "Test workflow", "notes": "This workflow performs entity matching", "tags": ["STELAR", "Entity matching", "Entity resolution"]}})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Publishing Operations'], security=security_doc)
@auth.login_required
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
        if request.headers:
            package_headers, resource_headers = utils.create_CKAN_headers(get_demo_ckan_token())
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
    

##############################################################################
########################## SEARCH CATALOG RESOURCES ##########################
##############################################################################


@catalog_bp.route('/tags', methods=['GET'])
#@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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



@catalog_bp.route('/vocabularies', methods=['GET'])
#@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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



@catalog_bp.route('/all', methods=['GET'])
#@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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



@catalog_bp.route('/', methods=['GET'])
@catalog_bp.input(schema.Identifier, location='query', example="cf0c3c59-fc41-48c9-a529-6b9feff42991")
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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

@catalog_bp.route('/metadata/all', methods=['GET'])
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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

@catalog_bp.route('/dataset/export_zenodo', methods=['GET'])
@catalog_bp.input(schema.Identifier, location='query', example="cf0c3c59-fc41-48c9-a529-6b9feff42991")
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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



@catalog_bp.route('/search', methods=['POST'])
@catalog_bp.input(schema.Query, location='json', example={"q":{"Topic":"POI", "INSPIRE theme":"Location", "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'], security=security_doc)
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


@catalog_bp.route('/dataset/search', methods=['GET'])
@catalog_bp.input(schema.ComplexFilter, location='query', example="q=Lakes&ext_bbox=20,35,30,42")
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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



@catalog_bp.route('/resource', methods=['GET'])
@catalog_bp.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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



@catalog_bp.route('/resource/search', methods=['GET'])
@catalog_bp.input(schema.Filter, location='query', example="q=format:JSON")
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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


@catalog_bp.route('/resource/profile', methods=['GET'])
@catalog_bp.input(schema.Identifier, location='query', example="6dc36257-abb6-45b5-b3bb-5f94160fc2ee")
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Search Operations'])
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

################################## RANKING OPERATIONS ########################################

@catalog_bp.route('/api/v1/catalog/rank', methods=['POST'])
@catalog_bp.input(schema.Ranking, location='json', example={"rank_preferences":{"tags": ["Geospatial","POI"], "theme":["Land Use","Land Cover","Imagery"], "language":["en","el","fr"], "spatial":{"type": "Polygon", "coordinates": [[[ 12.362, 45.39], [12.485, 45.39], [12.485, 45.576], [12.362, 45.576], [12.362, 45.39]]]}}, "settings":{"k": 10, "algorithm": "threshold", "weights": [0.3,0.5,0.4] }})
@catalog_bp.output(schema.ResponseOK, status_code=200)
@catalog_bp.doc(tags=['Ranking Operations'], security=security_doc)
@auth.login_required
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


