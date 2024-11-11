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


knowledge_graph_bp = APIBlueprint('knowledge_graph_blueprint', __name__,tag='Knowledge Graph')




############### the search operations against the catalog ends in this section ####################


@knowledge_graph_bp.route('/workflow/input/dataset', methods=['GET'])
@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=82aaa2df-be92-46ee-a36b-cc59122a5d5b")
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'])
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


@knowledge_graph_bp.route('/workflow/output/dataset', methods=['GET'])
@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=9232eef6-5acf-4280-b3e9-38d6c8935d7d")
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'])
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



@knowledge_graph_bp.route('/workflow/input/resource', methods=['GET'])
@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=6b077882-bd24-480b-896b-d7e8431338e5")
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'])
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



@knowledge_graph_bp.route('/workflow/output/resource', methods=['GET'])
@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=50156c05-6150-494d-b372-77d859f768d2")
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'])
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
#@knowledge_graph_bp.route('/workflow/tasks', methods=['GET'])
#@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=UC_A3")
#@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
#@knowledge_graph_bp.doc(tags=['Search Operations'])
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
#@knowledge_graph_bp.route('/task/executions', methods=['GET'])
#@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=entity_extraction")
#@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
#@knowledge_graph_bp.doc(tags=['Search Operations'])
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


@knowledge_graph_bp.route('/task/execution/input', methods=['GET'])
@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'])
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



@knowledge_graph_bp.route('/task/execution/output', methods=['GET'])
@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'])
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




@knowledge_graph_bp.route('/task/execution/metrics', methods=['GET'])
@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'])
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


@knowledge_graph_bp.route('/task/execution/parameters', methods=['GET'])
@knowledge_graph_bp.input(schema.Identifier, location='query', example="id=0075f24c7b654246a65c12739e96b867")
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'])
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



@knowledge_graph_bp.route('/graph/search', methods=['POST']) #/kg/search
@knowledge_graph_bp.input(schema.Filter, location='json', example={"q": "PREFIX dct: <http://purl.org/dc/terms/> SELECT ?uri ?title ?publisher WHERE { ?uri dct:title ?title . ?uri dct:publisher ?publisher . } LIMIT 5"})
#@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'], security=security_doc)
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


@knowledge_graph_bp.route('/catalog/sql', methods=['POST'])
@knowledge_graph_bp.input(schema.Filter, location='json', example={"q": "SELECT * FROM public.package LIMIT 5"})
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'], security=security_doc)
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


@knowledge_graph_bp.route('/catalog/facet/values', methods=['POST'])
@knowledge_graph_bp.input(schema.Filter, location='json', example={"q": "format"})
@knowledge_graph_bp.output(schema.ResponseOK, status_code=200)
@knowledge_graph_bp.doc(tags=['Search Operations'], security=security_doc)
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