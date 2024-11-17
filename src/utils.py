import pandas as pd
import flask
import requests
import json
import re
import psycopg2
import uuid
import copy
import random
from datetime import datetime
import logging

from flask import request, jsonify, current_app
from requests.auth import HTTPBasicAuth
import urllib.parse
from shapely.geometry import shape, GeometryCollection
from shapely.geometry.polygon import Polygon
from shapely.geometry.point import Point
import shapely.wkt

#for keycloak integration with the api
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

################################## DATABASE CONNECTOR ########################################

def execSql(sql, vars=None):
    """Opens a connection to a PostgreSQL database and executes the given SQL command.

    Args:
        sql (String): The SQL command with variables to be executed in the database.
        vars (List): The values to use per variable in the SQL command.

    Returns:
        A JSON with the retrieved query results for SELECT commands; a JSON with the final execution status (True/False) for INSERT/UPDATE/DELETE commands.
    """

    config = current_app.config['settings']

    data = None
    try:
        with psycopg2.connect(dbname=config['dbname'], user=config['dbuser'], password=config['dbpass'], host=config['dbhost'], port=config['dbport']) as conn:
            with conn.cursor() as cur:
                # Execute the SQL statement
                cur.execute(sql, vars)

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

#########################################################

# Properties regarding the various types of attributes to be extracted from profiles 

attribute_tags = ['type','count','num_missing','theme','uniqueness','nesting_level']

series_tags = ['num_peaks','abs_energy','abs_sum_changes','len_above_mean','len_below_mean']

temporal_tags = ['start','end']

geometry_tags = ['mbr','centroid','crs']

textual_tags = ['ratio_uppercase','ratio_digits','ratio_special_characters']


# Properties regarding entire profiles

tabular_tags = ['num_rows','num_attributes']

raster_tags = ['name','format','height','width','crs','spatial_coverage','spatial_resolution','start_date','end_date','temporal_resolution','no_data_value']

rdfgraph_tags = ['num_nodes','num_edges','num_namespaces','num_classes','num_object_properties','num_datatype_properties','density','num_connected_components']

hierarchical_tags = ['num_records', 'num_attributes']

text_tags = ['name','language','num_sentences','num_words','num_distinct_words','num_characters','ratio_uppercase','ratio_digits','ratio_special_characters']


# Properties regarding the various types of distributions

numerical_distribution_tags = ['count','average','stddev','min','max','median','percentile10','percentile25','percentile75','percentile90','kurtosis','skewness','variance']

categorical_distribution_tags = ['type','class_name','value','count','percentage']

language_distribution_tags = ['language','percentage']


#########################################################

# Templates of SQL SELECT queries for various types of metadata attributes (facets)
# FIXME: Distinguish facets used for filtering only (e.g., license, dataset_type) ?

# List profile metadata elements that may be involved in search requests 
profile_attributes = ['cloud_coverage', 'missing', 'lai']

# Template for fetching values in metadata for the given dataset identifiers
identifiers_sql_filter_template = 'SELECT id, value, 0.0 AS score FROM _VIEW WHERE value IS NOT NULL _IDS'


# NUMERICAL: 
# CAUTION! Included value in the returned ranked results to cater for profiling information not available in CKAN
numerical_facets = ['num_rows', 'days_active', 'velocity', 'cloud_coverage', 'missing', 'lai']
# For RANKING, SQL argument accepts a numerical (integer or real) value, e.g., 24700 expressing the dataset size in bytes or 0.67 for cloud coverage
numerical_sql_rank_template = 'SELECT id, value::numeric, exp(-0.001 * abs(value::numeric - _ARGS))::float AS score FROM _VIEW WHERE value IS NOT NULL _IDS ORDER BY score DESC LIMIT _TOPK'
# For RANGE FILTERING, SQL argument accepts an array of two numerical (integer or real) values representing the range of values, e.g., [1000, 2000] for size
numerical_sql_range_template = 'WITH vars AS (SELECT q_numeric[1]::numeric AS q_start, q_numeric[2]::numeric AS q_end FROM (SELECT _ARGS AS q_numeric) n ) SELECT id, value::numeric FROM _VIEW, vars WHERE value::numeric BETWEEN q_start AND q_end _IDS'

# CATEGORICAL: SQL argument accepts arrays of strings, e.g., ['Imagery','POI'] or ['en','fr','de']
categorical_facets = ['tags', 'theme', 'language', 'license', 'dataset_type', 'format', 'provider_name', 'organization']
categorical_sql_rank_template = 'SELECT id, jaccard_similarity(arr_values, _ARGS) AS score FROM _VIEW WHERE jaccard_similarity(arr_values, _ARGS) > 0 _IDS ORDER BY score DESC LIMIT _TOPK'

# TEMPORAL: SQL argument accepts date/time intervals, e.g., ['2018-08-15 14:25:36','2018-10-31 08:42:25'] ; 
# FIXME: either the start of the end bound could be NULL
temporal_facets = ['temporal_extent']
temporal_sql_rank_template = 'WITH vars AS (SELECT q_temporal[1]::timestamp AS q_start, q_temporal[2]::timestamp AS q_end FROM (SELECT _ARGS AS q_temporal) t ), filled_temporal_bounds AS (SELECT id, COALESCE(temporal_start,LEAST(temporal_end,vars.q_start)) AS temporal_start, COALESCE(temporal_end,now()) AS temporal_end, vars.q_start, vars.q_end FROM _VIEW, vars), epoch_bounds AS (SELECT id, EXTRACT(epoch FROM temporal_start) AS temporal_start, EXTRACT(epoch FROM temporal_end) AS temporal_end, EXTRACT(epoch FROM q_start) AS q_start, EXTRACT(epoch FROM q_end) AS q_end, EXTRACT(epoch FROM GREATEST(temporal_start,q_start)) AS overlap_start, EXTRACT(epoch FROM LEAST(temporal_end,q_end)) AS overlap_end FROM filled_temporal_bounds WHERE (temporal_start, temporal_end) OVERLAPS (q_start, q_end) _IDS) SELECT id, 1- ((overlap_end-overlap_start)/LEAST((q_end-temporal_start), (temporal_end-q_start))) AS score FROM epoch_bounds ORDER BY score DESC LIMIT _TOPK'

# RECENCY: Include facet for single date search
recency_facets = ['metadata_modified']
# For RANKING, SQL argument accepts a single date/time value, e.g., '2018-08-15 14:25:36'
recency_sql_rank_template = 'SELECT id, value, exp(-0.00001 * abs(extract (epoch FROM age(value)) - extract (epoch FROM age(_ARGS::timestamp))))::float AS score FROM _VIEW WHERE value IS NOT NULL _IDS ORDER BY score DESC LIMIT _TOPK'
# For RANGE FILTERING, SQL argument accepts date/time intervals, e.g., ['2018-08-15 14:25:36','2018-10-31 08:42:25']
recency_sql_range_template = 'WITH vars AS (SELECT q_interval[1]::timestamp AS q_start, q_interval[2]::timestamp AS q_end FROM (SELECT _ARGS AS q_interval) t ) SELECT id, value FROM _VIEW, vars WHERE value BETWEEN q_start AND q_end _IDS'

# SPATIAL: concerns either spatial extent or location
spatial_facets = ['spatial']
# SPATIAL EXTENT: SQL argument accepts WKT polygons in WGS84 (EPSG:4326), e.g., 'POLYGON((25.705543 35.034625, 25.861189 41.402938, 20.644119 41.369031, 20.924371 35.007623, 25.705543 35.034625 ))'
spatial_sql_rank_template = 'WITH vars AS (SELECT _ARGS AS qbox) SELECT p.id, ST_area(ST_Intersection(the_geom, vars.qbox))/ST_area(ST_Union(the_geom, vars.qbox)) AS score FROM public.package p, _VIEW e, vars WHERE e.package_id = p.id AND ST_Intersects(the_geom, vars.qbox) AND p.state = \'active\' _IDS ORDER BY score DESC LIMIT _TOPK'

# LOCATION: SQL argument accepts WKT poin locations in WGS84 (EPSG:4326), e.g., 'POINT(5.861189 41.402938)'
# FIXME: Expose lambda as a config parameter, instead of a fixed value like '0.001'
location_sql_rank_template = 'SELECT p.id, exp(-0.001 * ST_Distance(ST_centroid(the_geom), _ARGS)) AS score FROM public.package p, _VIEW e WHERE e.package_id = p.id AND NOT ST_IsEmpty(the_geom) AND p.state = \'active\' _IDS ORDER BY score DESC LIMIT _TOPK'


# SQL views existing in PostgreSQL database and corresponding to facets: 
sql_views = {'tags':'package_tag_array', 'language':'package_language_array', 'theme':'package_theme_array', 'license':'package_license_array', 'dataset_type':'package_dataset_type_array', 'format':'package_format_array', 'provider_name':'package_provider_array', 'organization':'package_organization_array', 'spatial':'package_extent', 'temporal_extent':'package_temporal_extent', 'metadata_modified':'package_metadata_modified', 'num_rows':'package_num_rows', 'days_active':'package_days_active', 'velocity':'package_velocity', 'cloud_coverage':'profile_vista_min_cloud_coverage', 'missing':'profile_vista_min_missing', 'lai':'profile_vista_max_lai'}

#########################################################

# Templates of SQL queries for workflow management
# FIXME: Remove fixed parameters from SQL query for 'workflow_read_statistics'
sql_workflow_execution_templates = {
    'workflow_create_template': 'INSERT INTO klms.workflow_execution(workflow_uuid, state, start_date) VALUES (%s, %s, %s)',
    'workflow_update_template': 'UPDATE klms.workflow_execution SET state = %s WHERE workflow_uuid = %s',  
    'workflow_commit_template': 'UPDATE klms.workflow_execution SET state = %s, end_date = %s WHERE workflow_uuid = %s',  
    'workflow_insert_tags_template': 'INSERT INTO klms.workflow_tag VALUES (%s, %s, %s)',
    'workflow_state_template': 'SELECT workflow_uuid AS workflow_exec_id, state FROM klms.workflow_execution WHERE workflow_uuid = %s',
    'workflow_delete_template': 'DELETE FROM klms.workflow_execution WHERE workflow_uuid = %s',
    'workflow_read_template': 'SELECT workflow_uuid AS workflow_exec_id, state, start_date, end_date FROM klms.workflow_execution WHERE workflow_uuid = %s',
    'workflow_get_tasks': """SELECT tsk.task_uuid, tsk.state, tsk.start_date, tsk.end_date, tsk_tg.value as tool_image 
                             FROM klms.workflow_execution as wf 
                             JOIN klms.task_execution as tsk ON wf.workflow_uuid=tsk.workflow_uuid 
                             JOIN klms.task_tag as tsk_tg ON tsk.task_uuid=tsk_tg.task_uuid 
                             WHERE wf.workflow_uuid= %s
                             AND tsk_tg.key='tool_image';""",
    'workflow_read_tags_template': 'SELECT key, value FROM klms.workflow_tag WHERE workflow_uuid = %s',
    'task_create_template': 'INSERT INTO klms.task_execution(task_uuid, workflow_uuid, state, start_date) VALUES (%s, %s, %s, %s)',
    'task_update_template': 'UPDATE klms.task_execution SET state = %s WHERE task_uuid = %s',
    'task_commit_template': 'UPDATE klms.task_execution SET state = %s, end_date = %s WHERE task_uuid = %s',
    'task_create_connection_template': 'UPDATE klms.task_execution SET next_task_uuid = %s WHERE task_uuid = %s',
    'task_delete_template': 'DELETE FROM klms.task_execution WHERE task_uuid = %s',
    'task_read_template': 'SELECT task_uuid AS task_exec_id, workflow_uuid AS workflow_exec_id, state, start_date, end_date FROM klms.task_execution WHERE task_uuid = %s',
    'task_read_tags_template': 'SELECT key, value FROM klms.task_tag WHERE task_uuid = %s',
    'task_read_input_dataset_template': 'SELECT * FROM klms.task_input WHERE task_uuid = %s',
    'task_read_output_dataset_template': 'SELECT * FROM klms.task_output WHERE task_uuid = %s',
    'task_insert_input_dataset_template': 'INSERT INTO klms.task_input(task_uuid, order_num, dataset_id) VALUES (%s, %s, %s)',
    'task_insert_output_dataset_template': 'INSERT INTO klms.task_output(task_uuid, order_num, dataset_id) VALUES (%s, %s, %s)',
    'task_insert_tags_template': 'INSERT INTO klms.task_tag VALUES (%s, %s, %s)',
    'task_insert_parameters_template': 'INSERT INTO klms.parameters VALUES (%s, %s, %s)',
    'task_insert_metrics_template': 'INSERT INTO klms.metrics VALUES (%s, %s, %s, now())',
    'workflow_read_statistics': """SELECT te.workflow_uuid, te.task_uuid, p.key, p.value
FROM klms.task_execution te, klms.workflow_tag wt, klms.parameters p
WHERE te.workflow_uuid = wt.workflow_uuid AND te.task_uuid = p.task_uuid AND wt.value IN ('A3-4') AND p.key in ('k', 'model')
UNION
SELECT te.workflow_uuid, te.task_uuid, m.key, m.value
FROM klms.task_execution te, klms.workflow_tag wt, klms.metrics m
WHERE te.workflow_uuid = wt.workflow_uuid AND te.task_uuid = m.task_uuid AND wt.value IN ('A3-4') AND m.key in ('food_tags', 'total_tags', 'f1_micro', 'f1_macro', 'f1_weighted')
"""
}

#########################################################

# Templates of SPARQL SELECT queries against the Knowledge Graph

sparql_templates = {
    'workflow_input_dataset_template':'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?dataset ?resource ?order ?workflowExec ?start_date ?end_date WHERE { ?dataset dct:identifier _ID . ?dataset dcat:distribution ?resource . ?taskExec klms:hasInput ?input_uri . ?input_uri klms:orderNum ?order . ?input_uri klms:input ?resource . ?taskExec dct:isPartOf ?workflowExec . ?workflowExec dcat:startDate ?start_date . ?workflowExec dcat:endDate ?end_date . }',
    'workflow_output_dataset_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?dataset ?resource ?order ?workflowExec ?start_date ?end_date WHERE { ?dataset dct:identifier _ID . ?dataset dcat:distribution ?resource . ?taskExec klms:hasOutput ?output_uri . ?output_uri klms:orderNum ?order . ?output_uri klms:output ?resource . ?taskExec dct:isPartOf ?workflowExec . ?workflowExec dcat:startDate ?start_date . ?workflowExec dcat:endDate ?end_date . }',
    'workflow_input_resource_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?resource ?order ?workflowExec ?start_date ?end_date WHERE { ?taskExec klms:hasInput ?input_uri . ?input_uri klms:orderNum ?order . ?input_uri klms:input ?resource . ?resource dct:identifier _ID . ?taskExec dct:isPartOf ?workflowExec . ?workflowExec dcat:startDate ?start_date . ?workflowExec dcat:endDate ?end_date . }',
    'workflow_input_resource_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?resource ?order ?workflowExec ?start_date ?end_date WHERE { ?taskExec klms:hasOutput ?output_uri . ?output_uri klms:orderNum ?order . ?output_uri klms:output ?resource . ?resource dct:identifier _ID . ?taskExec dct:isPartOf ?workflowExec . ?workflowExec dcat:startDate ?start_date . ?workflowExec dcat:endDate ?end_date . }',
#    'workflow_input_dataset_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?dataset ?resource ?workflow ?workflow_name ?workflow_desc ?workflowExec ?start_date ?end_date WHERE { ?dataset dct:identifier _ID . ?dataset dcat:distribution ?resource . ?taskExec klms:hasInput ?resource . ?taskExec klms:instantiates ?task . ?taskExec dct:isPartOf ?workflowExec . ?workflowExec klms:instantiates ?workflow . ?workflowExec dcat:startDate ?start_date . ?workflowExec dcat:endDate ?end_date . ?workflow dct:title ?workflow_name . ?workflow dct:description ?workflow_desc }',
#    'workflow_output_dataset_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?dataset ?resource ?workflow ?workflow_name ?workflow_desc ?workflowExec ?start_date ?end_date WHERE { ?dataset dct:identifier _ID . ?dataset dcat:distribution ?resource . ?taskExec klms:hasOutput ?resource . ?taskExec klms:instantiates ?task . ?taskExec dct:isPartOf ?workflowExec . ?workflowExec klms:instantiates ?workflow . ?workflowExec dcat:startDate ?start_date . ?workflowExec dcat:endDate ?end_date . ?workflow dct:title ?workflow_name . ?workflow dct:description ?workflow_desc }',
#    'workflow_input_resource_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?resource ?workflow ?workflow_name ?workflow_desc ?start_date ?end_date WHERE { ?taskExec klms:hasInput ?resource . ?resource dct:identifier _ID . ?taskExec dct:isPartOf ?workflowExec . ?workflow dct:title ?workflow_name . ?workflow dct:description ?workflow_desc . ?workflowExec klms:instantiates ?workflow . ?workflowExec dcat:startDate ?start_date . ?workflowExec dcat:endDate ?end_date }',
#    'workflow_output_resource_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?resource ?workflow ?workflow_name ?workflow_desc ?start_date ?end_date WHERE { ?taskExec klms:hasOutput ?resource . ?resource dct:identifier _ID . ?taskExec dct:isPartOf ?workflowExec . ?workflowExec klms:instantiates ?workflow . ?workflowExec dcat:startDate ?start_date . ?workflowExec dcat:endDate ?end_date . ?workflow dct:title ?workflow_name . ?workflow dct:description ?workflow_desc }',
    'task_execution_metrics_template': 'PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?metric ?value ?timestamp WHERE { ?taskExec dct:identifier _ID . ?taskExec klms:hasMetrics ?kvpair . ?kvpair  klms:key ?metric. ?kvpair klms:value ?value . ?kvpair dct:issued ?timestamp }',
    'task_execution_parameters_template': 'PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?parameter ?value WHERE { ?taskExec dct:identifier _ID . ?taskExec klms:hasParameters ?kvpair . ?kvpair  klms:key ?parameter . ?kvpair klms:value ?value }',
    'task_execution_input_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT  ?input_uri ?order ?resource_id WHERE {?taskExec dct:identifier _ID . ?taskExec klms:hasInput ?input_uri . ?input_uri klms:orderNum ?order . ?input_uri klms:input ?resource . ?resource dct:identifier ?resource_id } ORDER BY ?order',
    'task_execution_output_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?output_uri ?order ?resource_id WHERE {?taskExec dct:identifier _ID . ?taskExec klms:hasOutput ?output_uri . ?output_uri klms:orderNum ?order . ?output_uri klms:output ?resource . ?resource dct:identifier ?resource_id } ORDER BY ?order',
#    'task_execution_input_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT  ?input_uri ?resource_id WHERE { ?taskExec dct:identifier _ID . ?taskExec klms:hasInput ?input_uri . ?input_uri a dcat:Distribution . ?input_uri dct:identifier ?resource_id } ORDER BY ?order',
#    'task_execution_output_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT  ?output_uri ?resource_id WHERE { ?taskExec dct:identifier _ID . ?taskExec klms:hasOutput ?output_uri . ?output_uri a dcat:Distribution . ?output_uri dct:identifier ?resource_id } ORDER BY ?order',
#    'workflow_tasks_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?task_id ?state ?start_date ?end_date WHERE { ?workflowExec a klms:WorkflowExecution . ?workflowExec dct:identifier _ID . ?taskExec dct:isPartOf ?workflowExec . ?taskExec klms:state ?state . ?taskExec dct:identifier ?task_id . ?taskExec dcat:startDate ?start_date . OPTIONAL { ?taskExec dcat:endDate ?end_date .}}',
#    'task_executions_template': 'PREFIX dcat: <http://www.w3.org/ns/dcat#> PREFIX dct: <http://purl.org/dc/terms/> PREFIX klms: <http://stelar-project.eu/klms#> SELECT ?task_id ?state ?start_date ?end_date ?tag ?tag_value WHERE { ?taskExec klms:state ?state . ?taskExec dct:identifier _ID . ?taskExec dcat:startDate ?start_date . OPTIONAL { ?taskExec dcat:endDate ?end_date .} OPTIONAL { ?taskExec klms:hasTags ?kvpair . ?kvpair klms:key ?tag . ?kvpair klms:value ?tag_value . }} ORDER BY ?start_date'
}

#########################################################

#fuction that is called from the api_verify_token function in data-api.py
def construct_rsa_public_key(n, e):
    """Construct an RSA public key from 'n' and 'e' values from JWKS."""
    # Decode 'n' and 'e' from Base64URL to bytes, then convert to integers
    n_int = int.from_bytes(base64.urlsafe_b64decode(n + '=='), byteorder='big')
    e_int = int.from_bytes(base64.urlsafe_b64decode(e + '=='), byteorder='big')

    # Create the RSA public key using the cryptography library
    public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key(default_backend())

    return public_key


def create_CKAN_headers(API_TOKEN):
    """Create the headers required for publishing a package or a resource in CKAN.

    Args:
        API_TOKEN (string): The API_TOKEN issued by CKAN that is required to establish connection and submit the request.

    Returns:
        Two JSON obejcts: (i) headers for package and (ii) headers for resource.
    """

    package_headers = {'Authorization': API_TOKEN, 'Content-Type': 'application/json'}
    resource_headers = { 'X-CKAN-API-Key': API_TOKEN }
    return package_headers, resource_headers



def validate_spatial(geometry):
    """Prepares the value for spatial extent in GeoJSON as expected by CKAN.

    Args:
        geometry: A WKT string or GeoJSON object representing a 2-dimensional geometry.

    Returns:
        A GeoJSON as expected by CKAN for spatial indexing in SOLR.
    """
    try:  # First, consider it as a GeoJSON
        if isinstance(geometry, dict):
            return json.dumps(geometry)   # dictionary
        else:
            g = json.loads(geometry)      # string containing a JSON
    except:   
        try:  # Then, assuming this is WKT
            wkt = shapely.wkt.loads(geometry)
            g = shapely.geometry.mapping(wkt)
        except: 
            g = {"type":"Polygon","coordinates":[]}  # Empty polygon
    
    return json.dumps(g)



def calc_bbox(geometry):
    """Calculate the bounding box of a geometry.

    Args:
        geometry: A GeoJSON object representing a 2-dimensional geometry.

    Returns:
        A list of four coordinates representing a bounding box (left, bottom, right, top).
    """

#    print("GeoJSON:", geometry)
    # NOTE: buffer(0) is a trick for fixing scenarios where polygons have overlapping coordinates 
    g = GeometryCollection([shape(geometry).buffer(0)])
    bbox = g.bounds

    return str(bbox[0])+","+str(bbox[1])+","+str(bbox[2])+","+str(bbox[3])



def handle_extras(json_metadata):
    """Convert key value pairs from the input JSON into the format required for extra metadata in CKAN.

    Args:
        A JSON object with key value pairs.

    Returns:
        A JSON array as required for extra metadata in CKAN.
    """

    extras = []
    for key,value in json_metadata.items():
        item = {}
        item["key"] = key 
        if key=="spatial": # Special handling of GeoJSON or WKT for spatial extent
            item["value"] = validate_spatial(json_metadata['spatial'])   #json.dumps(json_metadata['spatial'])
        elif isinstance(value, dict):  # Convert a dictionary as required for extras in CKAN.
            item["value"] = json.dumps(value)
        elif isinstance(value, list):  # Convert a list as required for extras in CKAN.
            item["value"] = json.dumps(value)
        else:
            item["value"] = value
        extras.append(item)
#    arr_json = json.dumps(extras)
    return extras


def handle_keywords(list_tags):
    """Convert a list of keywords from the input JSON into the format required for keywords (tags) in CKAN.

    Args:
        A JSON array with string values.

    Returns:
        A JSON array as required for keywords (tags) in CKAN.
    """

    tags = []
    for value in list_tags:
        item = {}
        item["name"] = value
        tags.append(item)

    return tags


def format_CKAN_filter(json_metadata):
    """Convert key value pairs from the input JSON into the format required for queries in CKAN by SOLR. SOLR syntax: https://gist.github.com/mankyKitty/5906859

    Args:
        json_metadata (dict): A JSON object with key value pairs.

    Returns:
        A string with the query specifications for submission to CKAN.
    """

    q = '?q='
    bbox = None
    for key,value in json_metadata.items():
        if key=="spatial": # Special handling of GeoJSON 
            bbox = calc_bbox(value) # Replace given GeoJSON with its BBOX
#            print("bbox: " , bbox)            
    if bbox:
#        json_metadata['ext_bbox'] = bbox
        ext_bbox = 'ext_bbox='+urllib.parse.quote(bbox)
        del json_metadata['spatial']  # Remove GeoJSON from the parameters
    else:
        ext_bbox = None

    # Encode parameters for the URL request, as required by SOLR
    filters = urllib.parse.urlencode(json_metadata, doseq=False)

    if filters:
        q += urllib.parse.quote(filters)

    if ext_bbox:
        q = '?' + ext_bbox

#        if q:
#            q += '&' + ext_bbox
#        else:
#            q = '?' + ext_bbox

    return q   #urllib.parse.quote(q) #.encode('iso-8859-1'))


def read_list_json(json_arr, col_id='id', col_score='score'):
    """Reads ranked items (with an id and a numerical score) from a JSON array.

    Args:
        json_arr (array): An array with key(id), value(score) pairs.
        col_id (string): Key containing the unique identifier of each item in the dictionary (default: `id`).      
        col_score (string): Key containing the score of each item (default: `score`).      
                
    Returns:
        A DataFrame with the given items ordered by descending score.
    """
    
    df = pd.DataFrame(json_arr)
    # Use the unique identifiers as index in each data frame for fast access
    df = df.set_index(col_id)
    # Represent scores as numerical values
    df = df[pd.to_numeric(df[col_score], errors='coerce').notnull()]
    # Sort by descending score
    df = df.sort_values(by=[col_score], ascending=False)
    
    return df


def assign_scores(response, df_scores, dict_df_facet_scores, facet_specs, profile_attributes):
    """Assign scores to the search results; also include any key-value pairs regarding facet specifications for ranking.

    Args:
        response (Response): The CKAN response to the search query.
        df_scores (DataFrame): A data frame containing the aggregated scores per dataset.
        dict_df_facet_scores (dict) : A dictionary of data frames: each DataFrame holds the partial scores per facet (key).
        facet_specs (dict): A dictionary of keys (metadata items) and values (user-specified preferences) with the facet specifications for ranking.
        profile_attributes (List): An array with attribute names in Profiling metadata to include their corresponding values in the results.

    Returns:
        A JSON with the search results also reporting their ranking scores.
    """

    json_response = response.json()
    if response.status_code == 200:
        if json_response['success']:
            results = json_response['result']['results']
            for r in results:
                # Append profile values in metadata attributes involved in the search
                id = r['id']
                r['profile'] = []
                for attr in profile_attributes:
                    if 'value' in dict_df_facet_scores[attr].keys() and id in dict_df_facet_scores[attr].index:
                        kv_pair = {}
                        kv_pair['key'] = attr
                        kv_pair['value'] = dict_df_facet_scores[attr]['value'].loc[id]
                        r['profile'].append(kv_pair)
                # Append partial scores
                partial_scores = {}
                if not df_scores.empty:
                    r['score'] = df_scores.loc[r['id']]['score']  # overall score
                    r['rank'] = df_scores.index.get_loc(df_scores.loc[r['id']].name) + 1 # final rank
                elif 'score' in r: # Keep the score as obtained from SOLR
                    continue
                else:  # FIXME: Artificially add a score to each result, since CKAN does NOT return the score from SOLR
                    r['score'] = random.randint(1, 100) / 100
                # Also report the partial scores per facet for this result
                for key in dict_df_facet_scores.keys():
                    if r['id'] in dict_df_facet_scores[key].index:
                        partial_scores[key] = dict_df_facet_scores[key].loc[r['id']]['score']
                    else:
                        partial_scores[key] = 0.0
                r['partial_scores'] = partial_scores
        # Include the names of facets specified for ranking in the response
        if facet_specs:
            json_response['result']['search_facets'] = facet_specs

    return json_response


def format_sql_filter(ids):
    """Formulate a complementary condition in SQL query based on dataset identifiers.

    Args:
        ids (list): A JSON array with dataset identifiers.

    Returns:
        sql_id_filter (string): SQL condition concerning dataset identifiers in a specified list.
        k (int): Number of identifiers in the list.

    """

    sql_id_filter = ' AND id IN (' + ",".join("'{0}'".format(id) for id in ids) + ')'
    k = len(ids)   

    return sql_id_filter, k


def format_sparql_filter(sparql_tmpl, id):
    """Formulate the SPARQL query using the dataset/resource/workflow/task identifier.

    Args:
        sparql_tmpl (string): The SPARQL template query to be modified with the given id.
        id (string): The identifier of a dataset/resource/workflow/task in the Knowledge Graph.

    Returns:
        sparql (string): The updated SPARQL query to be submitted against the Knowledge Graph.
    """
    sparql = ""
    if sparql_tmpl in sparql_templates:
        sparql = sparql_templates[sparql_tmpl].replace('_ID', '"'+id +'"')

    return sparql


def format_facet_preferences(json_metadata, sql_id_filter, k):
    """Convert key-value pairs regarding facet specifications from the input JSON into the format required for ranking using query templates against a PostgreSQL database.

    Args:
        json_metadata (dict): A JSON object with key-value pairs regarding facet preferences.
        sql_id_filter (string): SQL condition concerning dataset identifiers in a specified list.
        k (int): Number of values to retrieve having the greatest scores per facet.

    Returns:
        A dictionary of strings: an SQL query statement per specified facet for submission to PostgreSQL.
    """

    sql = {}

    for key in json_metadata.keys():
        if key in numerical_facets:    # NUMERICAL metadata elements
            if isinstance(json_metadata[key], list):  # RANGE of numerical values acts as FILTER
                sql[key] = numerical_sql_range_template.replace('_VIEW',sql_views[key]).replace('_ARGS', 'array'+str(json_metadata[key])).replace('_IDS',sql_id_filter) 
#                print('range', sql[key])
            else: # SINGLE numerical value used for RANKING
                sql[key] = numerical_sql_rank_template.replace('_VIEW',sql_views[key]).replace('_TOPK',str(k)).replace('_ARGS', str(json_metadata[key])).replace('_IDS',sql_id_filter) 
#                print('rank', sql[key])
        elif key in categorical_facets:    # CATEGORICAL metadata elements
            sql[key] = categorical_sql_rank_template.replace('_VIEW',sql_views[key]).replace('_TOPK',str(k)).replace('_ARGS', 'array'+str(json_metadata[key])).replace('_IDS',sql_id_filter) 
        elif key in spatial_facets:      # SPATIAL metadata elements
            try:  # Examine several specs for geometries 
                if isinstance(json_metadata[key], dict):  # GeoJSON as dictionary
                    g = 'ST_GeomFromGeoJSON('+ "'{0}'".format(json.dumps(json_metadata[key])) +')' 
                    geom = shape(json_metadata[key])
                else:    # string containing a GeoJSON
                    g = 'ST_GeomFromGeoJSON('+ "'{0}'".format(json.loads(str(json_metadata[key]))) +')' 
                    geom = shape(json.loads(str(json_metadata[key])))
            except:   
                try:  # Then, assuming this is WKT in WGS84
                    g = 'ST_GeomFromText(' + "'{0}'".format(shapely.wkt.loads(str(json_metadata[key]))) +', 4326)'
                    geom = shapely.wkt.loads(str(json_metadata[key]))
                except:  # Empty polygon
                    g = 'ST_GeomFromGeoJSON(' + "'{0}'".format('{"type":"Polygon","coordinates":[]}')
                    geom = GeometryCollection()            
            if isinstance(geom, Polygon):  # spatial extent
                sql[key] = spatial_sql_rank_template.replace('_VIEW',sql_views[key]).replace('_TOPK',str(k)).replace('_ARGS', g).replace('_IDS',sql_id_filter) 
            elif isinstance(geom, Point): # point location
                sql[key] = location_sql_rank_template.replace('_VIEW',sql_views[key]).replace('_TOPK',str(k)).replace('_ARGS', g).replace('_IDS',sql_id_filter) 
        elif key == 'temporal_extent':     # TEMPORAL EXTENT metadata elements
            sql[key] = temporal_sql_rank_template.replace('_VIEW',sql_views[key]).replace('_TOPK',str(k)).replace('_ARGS', 'array'+str(json_metadata[key])).replace('_IDS',sql_id_filter) 
        elif key == 'metadata_modified':     # RECENCY (last_updated) metadata element
            if isinstance(json_metadata[key], list):  # RANGE of date/time values acts as FILTER
                sql[key] = recency_sql_range_template.replace('_VIEW',sql_views[key]).replace('_ARGS', 'array'+str(json_metadata[key])).replace('_IDS',sql_id_filter) 
#                print('range', sql[key])
            else: # SINGLE date/time value used for RANKING
                sql[key] = recency_sql_rank_template.replace('_VIEW',sql_views[key]).replace('_TOPK',str(k)).replace('_ARGS', '\''+str(json_metadata[key])+'\'').replace('_IDS',sql_id_filter) 
#                print('rank', sql[key])          
    return sql



def cleanupDict(mydict, keys):
    """Removes any elements in the given dictionary that are not tagged under the given keys.

    Args:
        mydict (dict): A dictionary with key value pairs.
        keys (list): List of keys to retain in the given dictionary.

    Returns:
        A copy of the input dictionary, holding only the specified keys (if present).
    """

    for k in mydict.copy().keys():
        if not k in keys:
            mydict.pop(k) # Does nothing if the key is not present
            
    return mydict


def cleanupListDict(mylist, keys):
    """Removes any elements in each dictionary in the given list that are not tagged under the given keys.

    Args:
        mylist (dict): A list of dictionaries, each with the same key value pairs.
        keys (list): List of keys to retain in each dictionary.

    Returns:
        A copy of the input list, holding only the specified keys (if present) in each dictionary.
    """

    newlist = []
    for d in mylist:
        newlist.append(cleanupDict(d, keys))
            
    return newlist



def processTabularResource(resource_id, metadata, sql):
    """Process metadata about a tabular resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the the metadata of this tabular resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    tabular_metadata = cleanupDict(copy.deepcopy(metadata), tabular_tags)         
    tabular_metadata['resource_id'] = resource_id
    # Rename property as required by the schema
    if 'num_columns' in tabular_metadata:
        tabular_metadata['num_columns'] = tabular_metadata.pop('num_attributes')
    sql.append(prepareInsertSql(tabular_metadata, 'klms.tabular'))



def processTabularProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of a tabular/vector dataset.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this profile
    tabular_metadata = cleanupDict(copy.deepcopy(prof), tabular_tags)         
    tabular_metadata['resource_id'] = resource_id
    # Rename property as required by the schema
    tabular_metadata['num_columns'] = tabular_metadata.pop('num_attributes')
    sql.append(prepareInsertSql(tabular_metadata, 'klms.tabular'))


def processRasterResource(resource_id, metadata, sql):
    """Process metadata regarding a raster resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the metadata of this raster resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    raster_metadata = cleanupDict(copy.deepcopy(metadata), raster_tags)     
    raster_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(raster_metadata, 'klms.raster'))


def processRasterProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of a raster collection.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information of the raster collection.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    for var in prof: #['variables']:
        # Collect general info about this profile
        ext_raster_tags = raster_tags.copy()
        ext_raster_tags.append('date')  # Include original 'date' temporarily in order to convert it to an interval
        raster_metadata = cleanupDict(copy.deepcopy(var), ext_raster_tags)  
        # CAUTION! Currently, a raster profile indicates spatial resolution per axis; KLMS schema assumes a common resolution
        raster_metadata['spatial_resolution'] = raster_metadata['spatial_resolution']['pixel_size_x'] 
        # If a single date is reported, replace it with a time interval
        if 'date' in raster_metadata and not 'start_date' in raster_metadata and not 'end_date' in raster_metadata:      
            raster_metadata['start_date'] = datetime.strptime(raster_metadata['date'], "%d.%m.%Y").strftime("%Y-%m-%d")  
            raster_metadata['end_date'] = raster_metadata['start_date']
        raster_metadata.pop('date')
        raster_metadata['resource_id'] = resource_id 
        sql.append(prepareInsertSql(raster_metadata, 'klms.raster'))

        # Also ingest information about each of the bands
        for band in var['bands']:
            # Numerical distribution of pixel values 
            band_distribution = cleanupDict(copy.deepcopy(band), numerical_distribution_tags)   
            band_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
            sql.append(prepareInsertSql(band_distribution, 'klms.numerical_distribution'))
            # FIXME: This band will be associated with the resource (i.e., the raster collection, NOT the specific raster)
            attr_metadata = {}         
            attr_metadata['attr_name'] = band['name']
            attr_metadata['type'] = 'Band'
            attr_metadata['attr_id'] = band['uuid']  # Reuse the UUID already included in the original profile
            attr_metadata['resource_id'] = resource_id
            sql.append(prepareInsertSql(attr_metadata, 'klms.attribute'))
            # CAUTION! Also handle this band as a SPECIAL CASE (NOT as numerical attribute); but associated with the specific raster
            band_metadata = {}
            band_metadata['raster_name'] = raster_metadata['name']  # Name of the raster as included in the original profile
            band_metadata['attr_id'] = band['uuid']  # Reuse the UUID already included in the original profile
            band_metadata['value_distribution'] = band_distribution['distr_id']
            # CAUTION! If applicable, also include categorical distribution for NO DATA values in this band  
            if 'no_data_distribution' in band:
                class_uuid =  str(uuid.uuid1())  # Generate a UUID for this distribution
                class_distribution = cleanupListDict(copy.deepcopy(band['no_data_distribution']), categorical_distribution_tags)
                for item in class_distribution:
                    item['distr_id'] = class_uuid
                    # Rename property as required by the schema
                    item['type'] = item.pop('value')
                    sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
                band_metadata['no_data_distribution'] = class_uuid
            # Create the band as a numerical attribute
            sql.append(prepareInsertSql(band_metadata, 'klms.band_attribute'))


def processHierarchicalResource(resource_id, metadata, sql):
    """Process metadata about a hierarchical resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the the metadata of this hierarchical resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    hierarchical_metadata = cleanupDict(copy.deepcopy(prof), hierarchical_tags)         
    hierarchical_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(hierarchical_metadata, 'klms.hierarchical'))


def processHierarchicalProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of a hierarchical dataset.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Get all values concerning depth distribution
    depth_distribution = cleanupDict(copy.deepcopy(prof['depth_distribution']), numerical_distribution_tags)   
    depth_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
    sql.append(prepareInsertSql(depth_distribution, 'klms.numerical_distribution'))
    # Collect general info about this profile
    hierarchical_metadata = cleanupDict(copy.deepcopy(prof), hierarchical_tags)         
    hierarchical_metadata['resource_id'] = resource_id
#    hierarchical_metadata['num_attributes'] = len(profile['variables'])   # CAUTION! property NOT currently available in the profile
    hierarchical_metadata['depth_distribution'] = depth_distribution['distr_id']
    sql.append(prepareInsertSql(hierarchical_metadata, 'klms.hierarchical'))


def processRdfGraphResource(resource_id, metadata, sql):
    """Process metadata about a RDF graph resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the the metadata of this RDF graph resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    rdfgraph_metadata = cleanupDict(copy.deepcopy(prof), rdfgraph_tags)         
    rdfgraph_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(rdfgraph_metadata, 'klms.rdfgraph'))



def processRdfGraphProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of an RDF graph.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this profile
    rdfgraph_metadata = cleanupDict(copy.deepcopy(prof), rdfgraph_tags)         
    rdfgraph_metadata['resource_id'] = resource_id

    # Also get all statistics concerning its various distributions
    degree_centrality_distribution = cleanupDict(copy.deepcopy(prof['degree_centrality_distribution']), numerical_distribution_tags)   
    degree_centrality_distribution['distr_id'] = str(uuid.uuid1())  # Generate a UUID for this distribution
    rdfgraph_metadata['degree_centrality_distribution'] = degree_centrality_distribution['distr_id']
    sql.append(prepareInsertSql(degree_centrality_distribution, 'klms.numerical_distribution'))
    degree_distribution = cleanupDict(copy.deepcopy(prof['degree_distribution']), numerical_distribution_tags)   
    degree_distribution['distr_id'] = str(uuid.uuid1())  # Generate a UUID for this distribution
    rdfgraph_metadata['degree_distribution'] = degree_distribution['distr_id']
    sql.append(prepareInsertSql(degree_distribution, 'klms.numerical_distribution'))
    in_degree_distribution = cleanupDict(copy.deepcopy(prof['in_degree_distribution']), numerical_distribution_tags)   
    in_degree_distribution['distr_id'] = str(uuid.uuid1())  # Generate a UUID for this distribution
    rdfgraph_metadata['in_degree_distribution'] = in_degree_distribution['distr_id']
    sql.append(prepareInsertSql(in_degree_distribution, 'klms.numerical_distribution'))
    out_degree_distribution = cleanupDict(copy.deepcopy(prof['out_degree_distribution']), numerical_distribution_tags)   
    out_degree_distribution['distr_id'] = str(uuid.uuid1())  # Generate a UUID for this distribution
    rdfgraph_metadata['out_degree_distribution'] = out_degree_distribution['distr_id']
    sql.append(prepareInsertSql(out_degree_distribution, 'klms.numerical_distribution'))
    if 'class_distribution' in prof:
        class_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
        class_distribution = cleanupListDict(copy.deepcopy(prof['class_distribution']), categorical_distribution_tags)
        for item in class_distribution:
            item['distr_id'] = class_uuid
            # Rename property as required by the schema
            item['type'] = item.pop('class_name')
            sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
        rdfgraph_metadata['class_distribution'] = class_uuid
    # Must have included foreign keys to the various distributions
    sql.append(prepareInsertSql(rdfgraph_metadata, 'klms.rdfgraph'))



def processTextualResource(resource_id, metadata, sql):
    """Process metadata about a textual resource in CKAN.

    Args:
        resource_id (String) : A unique identifier for this resource (assigned by CKAN).
        metadata (array): JSON array containing the the metadata of this textual resource (according to KLMS ontology).
        sql (array): JSON array collecting the SQL commands from this resource.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting the metadata into PostgreSQL according to KLMS schema.
    """

    # Collect general info about this resource
    text_metadata = cleanupDict(copy.deepcopy(prof), text_tags)         
    text_metadata['resource_id'] = resource_id
    sql.append(prepareInsertSql(text_metadata, 'klms.text'))



def processTextualProfile(resource_id, prof, sql):
    """Provides metadata extracted from the profile of a text collection.

    Args:
        resource_id (String) : A unique identifier for this profile.
        prof (array): JSON array containing the profile information about all text documents in the collection.
        sql (array): JSON array collecting the SQL commands from this profile.

    Returns:
        An updated collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    # Collect info about the profile of each text document
    for var in prof: #['variables']:
        text_metadata = cleanupDict(copy.deepcopy(var), text_tags)         
        text_metadata['resource_id'] = resource_id
        # Get all values concerning its various distributions
        if 'sentence_length_distribution' in var:
            sentence_length_distribution = cleanupDict(copy.deepcopy(var['sentence_length_distribution']), numerical_distribution_tags)   
            sentence_length_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
            sql.append(prepareInsertSql(sentence_length_distribution, 'klms.numerical_distribution'))
            text_metadata['sentence_length_distribution'] = sentence_length_distribution['distr_id']
        if 'word_length_distribution' in var:
            word_length_distribution = cleanupDict(copy.deepcopy(var['word_length_distribution']), numerical_distribution_tags)   
            word_length_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
            sql.append(prepareInsertSql(word_length_distribution, 'klms.numerical_distribution'))
            text_metadata['word_length_distribution'] = word_length_distribution['distr_id']
        if 'language_distribution' in var:
            lang_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
            lang_distribution = cleanupListDict(copy.deepcopy(var['language_distribution']), language_distribution_tags)
            for item in lang_distribution:
                item['distr_id'] = lang_uuid
                # Rename property as required by the schema
                item['type'] = item.pop('language')
                sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
            text_metadata['language_distribution'] = lang_uuid
        if 'special_characters_distribution' in var:
            chars_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
            chars_distribution = cleanupListDict(copy.deepcopy(var['special_characters_distribution']), categorical_distribution_tags)
            for item in chars_distribution:
                item['distr_id'] = chars_uuid
                sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
            text_metadata['special_characters_distribution'] = chars_uuid
        # Must have included foreign keys to the various distributions
        sql.append(prepareInsertSql(text_metadata, 'klms.text'))


def extractProfileProperties(resource_id, profile):
    """Provides metadata extracted from a data profile.

    Args:
        resource_id (String) : A unique identifier for this profile.
        profile (array): JSON array containing the profile information.

    Returns:
        A collection of INSERT SQL statements to be executed for ingesting profile metadata into PostgreSQL according to KLMS schema.
    """

    sql = []   		# Collects SQL commands to be executed

    # PHASE #1: Dataset-related information
    prof = profile['table']  # No need to generate a UUID for this dataset; it has already obtained one as a CKAN resource
    # Handle each profile according to its type
    # Common handling of profiles for Tabular and TimeSeries data
    if prof['profiler_type'] == 'Tabular' or prof['profiler_type'] == 'TimeSeries':
        processTabularProfile(resource_id, prof, sql)
    elif prof['profiler_type'] == 'Raster' or prof['profiler_type'] == 'Vista_Raster':
        # IMPORTANT! Extract information about all raster images in the collection (all under a single resource in CKAN)
        if len(profile['variables']) > 0:
            processRasterProfile(resource_id, profile['variables'], sql)
            # IMPORTANT! Return the list of collected SQL commands for execution
            return sql
    elif prof['profiler_type'] == 'Hierarchical':
        processHierarchicalProfile(resource_id, prof, sql)
    elif prof['profiler_type'] == 'RDFGraph':
        processRdfGraphProfile(resource_id, prof, sql)
        # IMPORTANT! Return the list of collected SQL commands for execution
        return sql
    elif prof['profiler_type'] == 'Textual':
        # IMPORTANT! Extract information about all text documents in the collection (all under a single resource in CKAN)
        if len(profile['variables']) > 0:
            processTextualProfile(resource_id, profile['variables'], sql)
            # IMPORTANT! Return the list of collected SQL commands for execution
            return sql
        # OPTION #2: Extract information about the collection (corpus) only
        #processTextualProfile(resource_id, prof, sql)

    # PHASE #2: Attribute-related information, value distributions
    for var in profile['variables']:
        # Generate a UUID for this attribute
        attr_uuid = str(uuid.uuid1())
        
        # Collect general info about this attribute
        attribute_metadata = cleanupDict(copy.deepcopy(var), attribute_tags)         
        attribute_metadata['attr_name'] = var['name']
        attribute_metadata['attr_id'] = attr_uuid
        attribute_metadata['resource_id'] = resource_id
        sql.append(prepareInsertSql(attribute_metadata, 'klms.attribute'))

        # Handle each attribute according to its type
        if var['type'] == 'Numeric':
            # Get all values concerning numerical distribution
            numerical_distribution = cleanupDict(copy.deepcopy(var), numerical_distribution_tags)   
#            numerical_distribution['attr_id'] = attr_uuid
            numerical_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
            sql.append(prepareInsertSql(numerical_distribution, 'klms.numerical_distribution'))
            # Compose values concerning the numerical attribute
            numerical_attribute = {} 
            numerical_attribute['attr_id'] = attr_uuid
            numerical_attribute['value_distribution'] = numerical_distribution['distr_id']
            sql.append(prepareInsertSql(numerical_attribute, 'klms.numerical_attribute'))
        elif var['type'] == 'TimeSeries':
            # Get all values concerning numerical distribution
            numerical_distribution = cleanupDict(copy.deepcopy(var), numerical_distribution_tags)   
#            numerical_distribution['attr_id'] = attr_uuid
            numerical_distribution['distr_id'] =  str(uuid.uuid1())  # Generate a UUID for this distribution
            sql.append(prepareInsertSql(numerical_distribution, 'klms.numerical_distribution'))
            # Get all values concerning time series statistics
            series_attribute = cleanupDict(copy.deepcopy(var), series_tags) 
            series_attribute['attr_id'] = attr_uuid
            series_attribute['value_distribution'] = numerical_distribution['distr_id']
            sql.append(prepareInsertSql(series_attribute, 'klms.series_attribute'))
        elif var['type'] == 'DateTime':
            # Get all values concerning a temporal attribute
            temporal_attribute = cleanupDict(copy.deepcopy(var), temporal_tags)
            temporal_attribute['attr_id'] = attr_uuid
            # Rename properties with PostgreSQL-reserved words
            temporal_attribute['start_time'] = temporal_attribute.pop('start')
            temporal_attribute['end_time'] = temporal_attribute.pop('end')
            sql.append(prepareInsertSql(temporal_attribute, 'klms.temporal_attribute'))
        elif var['type'] == 'Categorical':
            # Get all values concerning frequency distribution
            freq_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
            frequency_distribution = cleanupListDict(copy.deepcopy(var['frequency_distribution']), categorical_distribution_tags)   
            for item in frequency_distribution:
                item['distr_id'] = freq_uuid
#                item['attr_id'] = attr_uuid
                sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
            # Get all values concerning a categorical attribute
            categorical_attribute = {}
            categorical_attribute['attr_id'] = attr_uuid
            categorical_attribute['frequency_distribution'] = freq_uuid
            sql.append(prepareInsertSql(categorical_attribute, 'klms.categorical_attribute'))
        elif var['type'] == 'Textual':
            # Get all values concerning a textual attribute
            textual_attribute = cleanupDict(copy.deepcopy(var), textual_tags)
            textual_attribute['attr_id'] = attr_uuid
            # Collect any statistics about distributions
            if 'num_chars_distribution' in var:
                chars_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                chars_distribution = cleanupDict(copy.deepcopy(var['num_chars_distribution']), numerical_distribution_tags)
                chars_distribution['distr_id'] = chars_uuid
#                chars_distribution['attr_id'] = attr_uuid
                textual_attribute['num_chars_distribution'] = chars_uuid
                sql.append(prepareInsertSql(chars_distribution, 'klms.numerical_distribution'))
            if 'num_words_distribution' in var:
                words_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                words_distribution = cleanupDict(copy.deepcopy(var['num_words_distribution']), numerical_distribution_tags)
                words_distribution['distr_id'] = words_uuid
#                words_distribution['attr_id'] = attr_uuid
                textual_attribute['num_words_distribution'] = words_uuid
                sql.append(prepareInsertSql(words_distribution, 'klms.numerical_distribution'))
            # Must have included foreign keys to the various distributions
            sql.append(prepareInsertSql(textual_attribute, 'klms.textual_attribute'))
        elif var['type'] == 'Geometry':
            # Get all values concerning a geometry attribute
            geometry_attribute = cleanupDict(copy.deepcopy(var), geometry_tags)
            geometry_attribute['attr_id'] = attr_uuid
            # Collect any statistics about distributions
            if 'length_distribution' in var:
                length_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                length_distribution = cleanupDict(copy.deepcopy(var['length_distribution']), numerical_distribution_tags)
                length_distribution['distr_id'] = length_uuid
#                length_distribution['attr_id'] = attr_uuid
                geometry_attribute['length_distribution'] = length_uuid
                sql.append(prepareInsertSql(length_distribution, 'klms.numerical_distribution'))
            if 'area_distribution' in var:
                area_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                area_distribution = cleanupDict(copy.deepcopy(var['length_distribution']), numerical_distribution_tags)
                area_distribution['distr_id'] = area_uuid
#                area_distribution['attr_id'] = attr_uuid
                geometry_attribute['area_distribution'] = area_uuid
                sql.append(prepareInsertSql(area_distribution, 'klms.numerical_distribution'))
            if 'geom_type_distribution' in var:
                geomtype_uuid = str(uuid.uuid1())  # Generate a UUID for this distribution
                geom_type_distribution = cleanupListDict(copy.deepcopy(var['geom_type_distribution']), categorical_distribution_tags)
                for item in geom_type_distribution:
                    item['distr_id'] = geomtype_uuid
#                    item['attr_id'] = attr_uuid
                    sql.append(prepareInsertSql(item, 'klms.categorical_distribution'))
                geometry_attribute['geom_type_distribution'] = geomtype_uuid
            # Must have included foreign keys to the various distributions
            sql.append(prepareInsertSql(geometry_attribute, 'klms.geometry_attribute'))

    # Return the list of collected SQL commands for execution
    return sql



def extractResourceProperties(resource_id, metadata):
    """Provides metadata extracted from a resource that conform to the KLMS schema.

    Args:
        resource_id (String) : A unique identifier for this resource.
        metadata (dict): JSON containing the resource metadata.

    Returns:
        A collection of INSERT SQL statements to be executed for ingesting resource metadata into PostgreSQL according to KLMS schema.
    """

    sql = []   		# Collects SQL commands to be executed

    # PHASE #1: Dataset-related information
    # Handle each resource according to its type
    # Common handling of profiles for Tabular and TimeSeries data
    if metadata['resource_type'] == 'Tabular' or metadata['resource_type'] == 'TimeSeries':
        processTabularResource(resource_id, metadata, sql)
        return sql
    elif metadata['resource_type'] == 'Raster':
        processRasterResource(resource_id, metadata, sql)
        return sql
    elif metadata['resource_type'] == 'Hierarchical':
        processHierarchicalResource(resource_id, metadata, sql)
        return sql
    elif metadata['resource_type'] == 'RDFGraph':
        processRdfGraphResource(resource_id, metadata, sql)
        return sql
    elif metadata['resource_type'] == 'Textual':
        processTextualResource(resource_id, metadata, sql)
        return sql

    # PHASE #2: Attribute-related information NOT applicable

    # Return the list of collected SQL commands for execution
    return sql



def prepareInsertSql(metadata, table):
    """Prepares an INSERT statement in SQL for ingesting the metadata into the specified table.

    Args:
#        resource_id (String): The name of the table where this data will be inserted.
        table (String): The name of the table where this data will be inserted.
        metadata (dict): JSON dictionary containing key, value pairs.

    Returns:
        A string with the INSERT statement to be executed in PostgreSQL.
    """

    columns = ", ".join(list(metadata.keys()))
    # Special handling of strings containing single quotes for PostgreSQL
    values = ", ".join("'{0}'".format(str(item).replace("'", r"''")) for item in metadata.values())
    sql = "INSERT INTO " + table + "(" + columns + ")" + " VALUES (" + values + ");"

    return sql


def prepareZenodoMetadata(dataset, creator, creator_org, doi:None):
    """Prepares the metadata in JSON about a dataset as expected by Zenodo.

    Args:
        dataset (JSON): A JSON object representing metadata for a dataset (CKAN packege).
        creator (String): The name of the creator of the dataset as listed in CKAN.
        creator_org (String): The name of the owner organization of the dataset as listed in CKAN.
        doi (String): The Digital Object Identifier of the dataset, if already assigned by the publisher If not, leave the field empty and Zenodo will register a new DOI when the dataset gets published.

    Returns:
        A JSON as expected by Zenodo for describing a dataset.
    """

    # Extract specific metadata as required by Zenodo schema 
    # (schema largely conforms with https://schema.datacite.org/meta/kernel-4.4/metadata.xsd)
    res_id = dataset['id']
    
    # Basic metadata
    title = dataset['title']
    description = dataset['notes']
    tags = [t['name'] for t in dataset['tags']]
    
    # List of creators/authors of the Zenodo deposition (dataset)
    author = dataset['author'] if dataset['author'] else None
    maintainer = dataset['maintainer'] if dataset['maintainer'] else None
    organization = dataset['organization']['description']
    creators = []
    if creator:
        creators.append({'name': creator, 'affiliation': creator_org})
    if author:
        creators.append({'name': author, 'affiliation': organization})
    if maintainer:
        creators.append({'name': maintainer, 'affiliation': organization})

    url = dataset['url'] if dataset['url'] else None
    version = dataset['version'] if dataset['version'] else None
    isopen = dataset['isopen']
    private = dataset['private']
    license_title = dataset['license_title'] if dataset['license_title'] else None

    # Handle some of the available extra metadata
    spatial = next((item['value'] for item in dataset['extras'] if item['key'] == 'spatial'), None)
    spatial_resolution_in_meters = next((item['value'] for item in dataset['extras'] if item['key'] == 'spatial_resolution_in_meters'), None)
    temporal_start = next((item['value'] for item in dataset['extras'] if item['key'] == 'temporal_start'), None)
    temporal_end = next((item['value'] for item in dataset['extras'] if item['key'] == 'temporal_end'), None)
    frequency = next((item['value'] for item in dataset['extras'] if item['key'] == 'frequency'), None)
    documentation = next((item['value'] for item in dataset['extras'] if item['key'] == 'documentation'), None)
    language = next((item['value'] for item in dataset['extras'] if item['key'] == 'language'), None)
    theme = next((item['value'] for item in dataset['extras'] if item['key'] == 'theme'), None)
    alternate_identifier = next((item['value'] for item in dataset['extras'] if item['key'] == 'alternate_identifier'), None)

    # locations : list of locations -> NOT always the BBOX specified in CKAN
    # * lat (double): latitude
    # * lon (double): longitude
    # * place (string): place�s name (required)
    # * description (string): place�s description (optional)
    # Example: [{"lat": 34.02577, "lon": -118.7804, "place": "Los Angeles"}, {"place": "Mt.Fuji, Japan", "description": "Sample found 100ft from the foot of the mountain."}]
    locations = None
    if spatial:
        locations = []
        loc = {}
        # Extract the centroid from the spatial extent in CKAN
        geom = json.loads(spatial) 
        bbox = shape(geom)
        loc['lon'] = bbox.centroid.x
        loc['lat'] = bbox.centroid.y
        loc['place'] = 'N/A'
        locations.append(loc)

    # access_right -> Controlled vocabulary in Zenodo:
    # * open: Open Access
    # * embargoed: Embargoed Access
    # * restricted: Restricted Access
    # * closed: Closed Access
    if isopen:
        access_right = "open"
        license = license_title if license_title else None
    elif private:
        access_right = "closed"
    else:
        access_right = "restricted"

    # dates -> List of date intervals
    # * start (ISO date string): start date (*)
    # * end (ISO date string): end date (*)
    # * type (Collected, Valid, Withdrawn): The interval�s type (required)
    # * description (string): The interval�s description (optional)
    # (*) Note that you have to specify at least a start or end date. For an exact date, use the same value for both start and end.
    # Example: [{"start": "2018-03-21", "end": "2018-03-25", "type": "Collected", "description": "Specimen A5 collection period."}]
    dates = None
    if temporal_start or temporal_end:
        dates = []
        timespan = {'type' : 'Valid'}   # Assuming that timespan specified the time period when dataset is valid
        if temporal_start:
            timespan['start'] = temporal_start
        if temporal_end:
            timespan['end'] = emporal_end
        dates.append(timespan)

    # language: the main language of the record as ISO 639-2 or 639-3 code
    lang = None
    if language:
        list_lang = language.replace('{','').replace('}','').split(',')  
        lang = list_lang[0]  # the first language specified in CKAN

    # https://developers.zenodo.org/#representation
    # IMPORTANT: By default, using EU project grant for STELAR. List of OpenAIRE-supported grants. Example: [{'id':'283595'}] (European Commission grants only) or funder DOI-prefixed: [{'id': '10.13039/501100000780::283595'}] (All grants, recommended)
    zenodo_metadata = { "upload_type":"dataset", "creators": creators, "title": title, "description": description, "keywords": tags, "access_right": access_right, "language":lang, "locations": locations, "dates" : dates,"license": license,"doi": doi, "grants": [{"id": "10.13039/501100000780::101070122"}] }

    return zenodo_metadata


